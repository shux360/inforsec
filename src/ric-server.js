import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { isAbsolute, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import tls from 'node:tls';
import { rootDir, runtimeConfig } from './config.js';
import { AuditLog } from './lib/audit-log.js';
import {
  fingerprintFromRaw,
  loadPins,
  verifyCertificateIssuedByCa
} from './lib/certs.js';
import { createJsonLineParser, writeJsonLine } from './lib/framing.js';
import { openEnvelope } from './lib/envelope.js';
import { ReplayCache } from './lib/replay-cache.js';
import { RateLimiter } from './lib/rate-limiter.js';
import { RevocationList } from './lib/revocation.js';

const PAYLOAD_KEY_LABEL = 'oran-cti-payload-key-v1';
const HEADER_MAC_KEY_LABEL = 'oran-cti-header-mac-key-v1';

export async function startRicServer(overrides = {}) {
  const config = runtimeConfig(overrides);
  const audit = new AuditLog(config.paths.auditLog);
  const caPem = readFileSync(config.paths.caCert);
  const pins = loadPins(config.paths.pins);
  const pinnedFingerprints = new Set(Object.values(pins.xapps).map((pin) => pin.tlsFingerprint));
  const signingPublicKeys = loadSigningPublicKeys(pins);
  const revocationList = new RevocationList(config.paths.revoked, { pollMs: 5000 });
  const replayCache = new ReplayCache({ ttlMs: config.maxSkewSeconds * 1000 });
  const rateLimiter = new RateLimiter({ limit: config.rateLimitPerMinute });

  const server = tls.createServer(
    {
      key: readFileSync(config.paths.ricKey),
      cert: readFileSync(config.paths.ricCert),
      ca: caPem,
      requestCert: true,
      rejectUnauthorized: false,
      minVersion: 'TLSv1.3',
      maxVersion: 'TLSv1.3'
    },
    (socket) => {
      void handleConnection({
        socket,
        audit,
        caPem,
        pins,
        pinnedFingerprints,
        signingPublicKeys,
        revocationList,
        replayCache,
        rateLimiter,
        config
      });
    }
  );

  server.on('tlsClientError', (error, socket) => {
    const remote = `${socket.remoteAddress ?? 'unknown'}:${socket.remotePort ?? 'unknown'}`;
    console.log(`[RIC] TLS client rejected from ${remote}: ${error.message}`);
    void audit.write({
      event: 'rejected',
      stage: 'tls-handshake',
      remote,
      reason: error.message
    });
  });

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    const onListening = () => {
      server.off('error', reject);
      resolve();
    };

    if (config.pipePath) {
      server.listen(config.pipePath, onListening);
    } else {
      server.listen(config.port, config.host, onListening);
    }
  });

  const target = config.pipePath ?? `${config.host}:${server.address().port}`;
  console.log(`[RIC] listening on ${target} with TLS 1.3 mTLS`);

  return {
    server,
    close: () =>
      new Promise((resolve, reject) => {
        let settled = false;
        const finish = (error) => {
          if (settled) return;
          settled = true;
          if (error) reject(error);
          else resolve();
        };

        // stop revocation watcher before closing server
        try {
          revocationList?.close();
        } catch (err) {
          // ignore
        }
        server.close((error) => finish(error));
        server.closeAllConnections?.();
        setTimeout(() => finish(), 250);
      })
  };
}

async function handleConnection({
  socket,
  audit,
  caPem,
  pins,
  pinnedFingerprints,
  signingPublicKeys,
  revocationList,
  replayCache,
  rateLimiter,
  config
}) {
  const peer = socket.getPeerCertificate(true);
  const fingerprint = peer.raw ? fingerprintFromRaw(peer.raw) : 'UNKNOWN';
  const subject = peer.subject?.CN ?? 'unknown-client';
  const remote = socket.remoteAddress ? `${socket.remoteAddress}:${socket.remotePort}` : 'local-pipe';
  const cipher = socket.getCipher();

  if (!peer.raw) {
    await rejectConnection(socket, audit, {
      stage: 'mtls-certificate',
      remote,
      subject,
      fingerprint,
      reason: 'client did not present a certificate'
    });
    return;
  }

  try {
    verifyCertificateIssuedByCa(peer.raw, caPem);
  } catch (error) {
    await rejectConnection(socket, audit, {
      stage: 'mtls-certificate',
      remote,
      subject,
      fingerprint,
      reason: error.message
    });
    return;
  }

  if (revocationList.has(fingerprint)) {
    await rejectConnection(socket, audit, {
      stage: 'certificate-revocation',
      remote,
      subject,
      fingerprint,
      reason: 'client certificate fingerprint is revoked'
    });
    return;
  }

  if (!pinnedFingerprints.has(fingerprint)) {
    await rejectConnection(socket, audit, {
      stage: 'certificate-pinning',
      remote,
      subject,
      fingerprint,
      reason: 'certificate not in pinned xApp set'
    });
    return;
  }

  console.log(`[RIC] accepted pinned client ${subject} from ${remote} using ${cipher.name}`);
  await audit.write({
    event: 'connected',
    stage: 'mtls',
    remote,
    subject,
    fingerprint,
    cipher: cipher.name,
    protocol: socket.getProtocol()
  });

  const payloadKey = socket.exportKeyingMaterial(32, PAYLOAD_KEY_LABEL, Buffer.alloc(0));
  const headerMacKey = socket.exportKeyingMaterial(32, HEADER_MAC_KEY_LABEL, Buffer.alloc(0));

  const onMessage = async (message) => {
    const rate = rateLimiter.consume(fingerprint);
    if (!rate.allowed) {
      await audit.write({
        event: 'rejected',
        stage: 'availability',
        senderId: message.senderId ?? 'unknown',
        fingerprint,
        reason: 'rate limit exceeded',
        retryAfter: rate.retryAfter
      });
      writeJsonLine(socket, { status: 'rejected', reason: 'rate limit exceeded', retryAfter: rate.retryAfter });
      return;
    }

    try {
      const pinnedForSender = pins.xapps[message.senderId];
      if (!pinnedForSender || pinnedForSender.tlsFingerprint !== fingerprint) {
        throw new Error('senderId does not match pinned certificate identity');
      }

      const result = openEnvelope({
        envelope: message,
        publicKeyPem: signingPublicKeys[message.senderId],
        payloadKey,
        headerMacKey,
        replayCache,
        maxSkewSeconds: config.maxSkewSeconds
      });

      const signatureHash = createHash('sha256')
        .update(message.signature)
        .digest('hex')
        .slice(0, 16);
      const objectCount = Array.isArray(result.payload.objects) ? result.payload.objects.length : 0;
      const bundleId = result.payload.id ?? 'unknown';

      console.log(`[RIC] accepted CTI payload ${bundleId} from ${message.senderId}; objects=${objectCount}`);
      await audit.write({
        event: 'accepted',
        stage: 'payload-verification',
        senderId: message.senderId,
        fingerprint,
        bundleId,
        objectCount,
        signatureHash
      });
      writeJsonLine(socket, {
        status: 'accepted',
        bundleId,
        objectCount,
        signatureHash
      });
    } catch (error) {
      console.log(`[RIC] rejected message from ${message.senderId ?? subject}: ${error.message}`);
      await audit.write({
        event: 'rejected',
        stage: 'payload-verification',
        senderId: message.senderId ?? 'unknown',
        fingerprint,
        reason: error.message
      });
      writeJsonLine(socket, { status: 'rejected', reason: error.message });
    }
  };

  socket.on(
    'data',
    createJsonLineParser(
      (message) => {
        void onMessage(message);
      },
      (error) => {
        console.log(`[RIC] rejected malformed JSON from ${subject}: ${error.message}`);
        void audit.write({
          event: 'rejected',
          stage: 'framing',
          subject,
          fingerprint,
          reason: error.message
        });
        writeJsonLine(socket, { status: 'rejected', reason: 'malformed JSON frame' });
      }
    )
  );

  socket.on('error', (error) => {
    console.log(`[RIC] socket error for ${subject}: ${error.message}`);
  });
}

function loadSigningPublicKeys(pins) {
  return Object.fromEntries(
    Object.entries(pins.xapps).map(([senderId, pin]) => {
      if (!pin.signingPublicKey) {
        throw new Error(`missing signing public key for ${senderId}`);
      }

      const keyPath = isAbsolute(pin.signingPublicKey)
        ? pin.signingPublicKey
        : resolve(rootDir, pin.signingPublicKey);
      return [senderId, readFileSync(keyPath, 'utf8')];
    })
  );
}

async function rejectConnection(socket, audit, event) {
  console.log(`[RIC] rejected ${event.subject ?? 'client'}: ${event.reason}`);
  await audit.write({ event: 'rejected', ...event });
  writeJsonLine(socket, { status: 'rejected', reason: event.reason });
  socket.end();
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  startRicServer().catch((error) => {
    console.error(`[RIC] fatal: ${error.message}`);
    process.exitCode = 1;
  });
}
