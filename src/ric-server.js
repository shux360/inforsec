import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import http from 'node:http';
import { isAbsolute, resolve } from 'node:path';
import tls from 'node:tls';
import { pathToFileURL } from 'node:url';
import { authenticator as totpAuthenticator } from 'otplib';
import { rootDir, runtimeConfig } from './config.js';
import { AuditLog } from './lib/audit-log.js';
import {
  fingerprintFromRaw,
  loadPins,
  verifyCertificateIssuedByCa
} from './lib/certs.js';
import { toBase64Url } from './lib/encoding.js';
import { buildEnvelope, openEnvelope } from './lib/envelope.js';
import { createJsonLineParser, writeJsonLine } from './lib/framing.js';
import { RateLimiter } from './lib/rate-limiter.js';
import { ReplayCache } from './lib/replay-cache.js';
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

  // optional demo HTTP endpoint for integration with the UI (non-TLS, demo-only)
  let demoServer;
  if (config.demoPort) {
    demoServer = http.createServer(async (req, res) => {
      // Set CORS headers to allow browser requests from localhost:5173
      res.setHeader('Access-Control-Allow-Origin', '*');
      res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'content-type, x-demo-api-key');

      // Handle CORS preflight requests
      if (req.method === 'OPTIONS') {
        res.statusCode = 200;
        res.end();
        return;
      }

      // Restrict demo endpoints to localhost only and require API key header for safety
      const remoteAddr = req.socket.remoteAddress ?? '';
      const allowedLoopbacks = ['127.0.0.1', '::1', '::ffff:127.0.0.1'];
      if (!allowedLoopbacks.includes(remoteAddr)) {
        res.statusCode = 403;
        res.end('forbidden');
        return;
      }

      const providedKey = req.headers['x-demo-api-key'];
      if (!providedKey || String(providedKey) !== String(config.demoApiKey)) {
        res.statusCode = 401;
        res.end('unauthorized');
        return;
      }

      if (req.method !== 'POST' || (req.url !== '/demo/envelope' && req.url !== '/demo/send')) {
        res.statusCode = 404;
        res.end('not found');
        return;
      }

      try {
        const body = await new Promise((resolve, reject) => {
          let data = '';
          req.setEncoding('utf8');
          req.on('data', (chunk) => (data += chunk));
          req.on('end', () => resolve(data));
          req.on('error', reject);
        });
        const message = JSON.parse(body);
        const remote = req.socket.remoteAddress ?? 'demo-client';
        const subject = message.senderId ?? 'demo-client';
        const identity = message.senderId ?? remote;

        if (req.url === '/demo/envelope') {
          const demoPayloadKey = createHash('sha256').update(config.demoSecret ?? 'demo-payload').digest().slice(0, 32);
          const demoHeaderMacKey = createHash('sha256').update(config.demoSecret ?? 'demo-header').digest().slice(0, 32);

          const result = await processDemoEnvelope({
            message,
            audit,
            pins,
            signingPublicKeys,
            revocationList,
            replayCache,
            rateLimiter,
            demoPayloadKey,
            demoHeaderMacKey,
            identity,
            remote,
            subject,
            config
          });

          res.setHeader('content-type', 'application/json');
          res.end(JSON.stringify(result));
          return;
        }

        // /demo/send: perform real signing and open an mTLS client to the RIC server
        if (req.url === '/demo/send') {
          const senderId = message.senderId ?? 'xapp-legitimate';
          const payload = message.payload ?? message;
          const profile = String(message.profile ?? 'xapp');

          // choose certificate/key/signing key paths based on requested profile (demo convenience)
          const certPathName = `${profile}Cert`;
          const keyPathName = `${profile}Key`;
          const signingKeyPathName = `${profile}SigningKey`;

          const clientCert = readFileSync(config.paths[certPathName] ?? config.paths.xappCert, 'utf8');
          const clientKey = readFileSync(config.paths[keyPathName] ?? config.paths.xappKey, 'utf8');
          // some demo profiles (e.g. foreign) reuse the xapp signing key; fall back when not present
          const signingKey = readFileSync(config.paths[signingKeyPathName] ?? config.paths.xappSigningKey, 'utf8');

          // create TLS client to RIC server using mTLS
          const tlsOptions = {
            host: config.host,
            port: config.port,
            key: clientKey,
            cert: clientCert,
            ca: caPem,
            rejectUnauthorized: false,
            minVersion: 'TLSv1.3',
            maxVersion: 'TLSv1.3'
          };

          const client = tls.connect(tlsOptions, () => {
            // derive keying material
            const payloadKey = client.exportKeyingMaterial(32, PAYLOAD_KEY_LABEL, Buffer.alloc(0));
            const headerMacKey = client.exportKeyingMaterial(32, HEADER_MAC_KEY_LABEL, Buffer.alloc(0));

            // If caller supplied a nonce string, derive a 96-bit IV deterministically from it for replay testing
            let envelopeNonce;
            if (message.nonce) {
              const hash = createHash('sha256').update(String(message.nonce)).digest();
              const iv = hash.slice(0, 12); // 96-bit
              envelopeNonce = toBase64Url(iv);
            }

            // build envelope using the signing key
            const envelope = buildEnvelope({
              payload,
              senderId,
              privateKeyPem: signingKey,
              payloadKey,
              headerMacKey,
              now: Date.now(),
              nonce: envelopeNonce
            });

            // send envelope as a JSON line
            writeJsonLine(client, envelope);
          });

          // collect single JSON-line response from the RIC server
          const parser = createJsonLineParser(
            (messageObj) => {
              res.setHeader('content-type', 'application/json');
              res.end(JSON.stringify({ sent: true, serverResponse: messageObj }));
              client.end();
            },
            (err) => {
              res.statusCode = 500;
              res.end(JSON.stringify({ error: 'failed to parse server response', detail: err.message }));
              client.end();
            }
          );

          client.on('data', (chunk) => {
            // `parser` is a function returned by createJsonLineParser
            try {
              parser(chunk);
            } catch (err) {
              // defensive: ensure client errors don't crash the demo server
            }
          });

          client.on('error', (err) => {
            if (!res.writableEnded) {
              res.statusCode = 500;
              res.end(JSON.stringify({ error: err.message }));
            }
          });

          return;
        }
      } catch (err) {
        res.statusCode = 500;
        res.end(JSON.stringify({ error: err.message }));
      }
    });

    demoServer.listen(config.demoPort, () => {
      console.log(`[RIC] demo HTTP endpoint listening on ${config.demoPort}`);
    });
  }

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
    demoServer,
    serverPort: server.address && server.address().port,
    demoPort: demoServer && demoServer.address && demoServer.address().port,
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
        try {
          demoServer?.close();
        } catch (err) {
          // ignore
        }
        server.close((error) => finish(error));
        server.closeAllConnections?.();
        setTimeout(() => finish(), 250);
      })
  };
}

async function processDemoEnvelope({
  message,
  audit,
  pins,
  signingPublicKeys,
  revocationList,
  replayCache,
  rateLimiter,
  demoPayloadKey,
  demoHeaderMacKey,
  identity,
  remote,
  subject,
  config
}) {
  const id = identity ?? subject ?? remote;
  const rate = rateLimiter.consume(id);
  if (!rate.allowed) {
    await audit.write({
      event: 'rejected',
      stage: 'availability',
      senderId: message.senderId ?? id,
      fingerprint: id,
      reason: 'rate limit exceeded',
      retryAfter: rate.retryAfter
    });
    return { status: 'rejected', reason: 'rate limit exceeded', retryAfter: rate.retryAfter };
  }

  // optional revocation check by identity
  if (revocationList.has(id)) {
    await audit.write({ event: 'rejected', stage: 'certificate-revocation', senderId: message.senderId, fingerprint: id, reason: 'revoked' });
    return { status: 'rejected', reason: 'revoked' };
  }

  // check pinned sender mapping (best-effort in demo)
  const pinnedForSender = pins.xapps[message.senderId];
  if (pinnedForSender && pinnedForSender.tlsFingerprint && pinnedForSender.tlsFingerprint !== id) {
    // mismatch
    await audit.write({ event: 'rejected', stage: 'certificate-pinning', senderId: message.senderId, fingerprint: id, reason: 'sender id pin mismatch' });
    return { status: 'rejected', reason: 'senderId does not match pinned identity' };
  }

  // replay protection (use nonce from message)
  if (replayCache?.has(message.nonce)) {
    await audit.write({ event: 'rejected', stage: 'replay', senderId: message.senderId, fingerprint: id, reason: 'nonce replay' });
    return { status: 'rejected', reason: 'nonce replay' };
  }

  // TOTP verification if configured
  const totpSecret = pinnedForSender?.totpSecret;
  if (totpSecret) {
    const token = message.payload?.twoFactor?.token ?? message.payload?.twoFactorToken;
    if (!token) {
      await audit.write({ event: 'rejected', stage: 'payload-verification', senderId: message.senderId, fingerprint: id, reason: 'missing two-factor token' });
      return { status: 'rejected', reason: 'missing two-factor token' };
    }
    const verified = totpAuthenticator.check(String(token), String(totpSecret));
    if (!verified) {
      await audit.write({ event: 'rejected', stage: 'payload-verification', senderId: message.senderId, fingerprint: id, reason: 'invalid two-factor token' });
      return { status: 'rejected', reason: 'invalid two-factor token' };
    }
  }

  // accept payload (demo mode bypasses crypto verification)
  replayCache?.add(message.nonce);
  await audit.write({ event: 'accepted', stage: 'demo-payload', senderId: message.senderId, fingerprint: id, bundleId: message.payload?.id ?? 'unknown', objectCount: Array.isArray(message.payload?.objects) ? message.payload.objects.length : 0 });

  return { status: 'accepted', bundleId: message.payload?.id ?? 'unknown' };
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

      // If the sender has a configured TOTP secret, enforce 2FA
      const senderPin = pins.xapps[message.senderId];
      const totpSecret = senderPin?.totpSecret;
      if (totpSecret) {
        const token = result.payload?.twoFactor?.token ?? result.payload?.twoFactorToken;
        if (!token) {
          throw new Error('missing two-factor token');
        }

        const verified = totpAuthenticator.check(String(token), String(totpSecret));
        if (!verified) {
          throw new Error('invalid two-factor token');
        }
      }

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
