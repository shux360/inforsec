import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import tls from 'node:tls';
import { runtimeConfig } from './config.js';
import { buildEnvelope } from './lib/envelope.js';
import { createJsonLineParser, writeJsonLine } from './lib/framing.js';
import { fromBase64Url, toBase64Url } from './lib/encoding.js';
import { verifyCertificateIssuedByCa } from './lib/certs.js';

const PAYLOAD_KEY_LABEL = 'oran-cti-payload-key-v1';
const HEADER_MAC_KEY_LABEL = 'oran-cti-header-mac-key-v1';

const profiles = {
  xapp: {
    senderId: 'xapp-legitimate',
    certPath: 'xappCert',
    keyPath: 'xappKey',
    signingKeyPath: 'xappSigningKey'
  },
  rogue: {
    senderId: 'xapp-rogue',
    certPath: 'rogueCert',
    keyPath: 'rogueKey',
    signingKeyPath: 'rogueSigningKey'
  },
  foreign: {
    senderId: 'xapp-foreign-self-signed',
    certPath: 'foreignCert',
    keyPath: 'foreignKey',
    signingKeyPath: 'xappSigningKey'
  }
};

export async function runXapp(options = {}) {
  const config = runtimeConfig(options);
  const profileName = options.profile ?? process.env.XAPP_PROFILE ?? 'xapp';
  const mode = options.mode ?? process.env.XAPP_MODE ?? 'normal';
  const profile = profiles[profileName];

  if (!profile) {
    throw new Error(`unknown xApp profile: ${profileName}`);
  }

  const payloadPath = options.payloadPath ?? process.env.STIX_FILE ?? config.paths.samplePayload;
  const payload = JSON.parse(readFileSync(payloadPath, 'utf8'));
  const cert = readFileSync(config.paths[profile.certPath]);
  const key = readFileSync(config.paths[profile.keyPath]);
  const signingKey = readFileSync(config.paths[profile.signingKeyPath]);
  const ca = readFileSync(config.paths.caCert);
  const responses = [];

  const target = config.pipePath ?? `${config.host}:${config.port}`;
  console.log(`[xApp:${profile.senderId}] connecting to ${target} mode=${mode}`);

  return await new Promise((resolve, reject) => {
    const connectTarget = config.pipePath
      ? { path: config.pipePath }
      : { host: config.host, port: config.port };

    const socket = tls.connect({
      ...connectTarget,
      servername: 'localhost',
      cert,
      key,
      ca,
      rejectUnauthorized: false,
      minVersion: 'TLSv1.3',
      maxVersion: 'TLSv1.3'
    });

    const done = (error) => {
      socket.removeAllListeners();
      if (!socket.destroyed) {
        socket.end();
      }
      if (error) {
        reject(error);
      } else {
        resolve(responses);
      }
    };

    socket.on('secureConnect', () => {
      try {
        const peer = socket.getPeerCertificate(true);
        verifyCertificateIssuedByCa(peer.raw, ca);
        const identityHost =
          config.serverIdentity ?? (config.pipePath || config.host === '127.0.0.1' ? 'localhost' : config.host);
        const hostnameError = tls.checkServerIdentity(identityHost, socket.getPeerCertificate());
        if (hostnameError) {
          throw hostnameError;
        }
      } catch (error) {
        done(new Error(`server certificate verification failed: ${error.message}`));
        return;
      }

      const cipher = socket.getCipher();
      console.log(`[xApp:${profile.senderId}] mTLS established with ${cipher.name}`);
      const payloadKey = socket.exportKeyingMaterial(32, PAYLOAD_KEY_LABEL, Buffer.alloc(0));
      const headerMacKey = socket.exportKeyingMaterial(32, HEADER_MAC_KEY_LABEL, Buffer.alloc(0));

      const envelope = buildEnvelope({
        payload,
        senderId: profile.senderId,
        privateKeyPem: signingKey,
        payloadKey,
        headerMacKey
      });

      if (mode === 'tamper') {
        const tampered = { ...envelope };
        const ciphertext = fromBase64Url(tampered.ciphertext);
        ciphertext[0] ^= 0xff;
        tampered.ciphertext = toBase64Url(ciphertext);
        console.log('[xApp] sending ciphertext with one flipped byte');
        writeJsonLine(socket, tampered);
        return;
      }

      if (mode === 'replay') {
        console.log('[xApp] sending same valid envelope twice to trigger nonce replay detection');
        writeJsonLine(socket, envelope);
        setTimeout(() => writeJsonLine(socket, envelope), 250);
        return;
      }

      if (mode === 'flood') {
        const count = Number(options.count ?? process.env.XAPP_FLOOD_COUNT ?? 35);
        console.log(`[xApp] sending ${count} signed telemetry messages to exercise rate limiting`);
        for (let index = 0; index < count; index += 1) {
          const floodPayload = {
            ...payload,
            id: `${payload.id}-flood-${index}`,
            objects: payload.objects
          };
          writeJsonLine(
            socket,
            buildEnvelope({
              payload: floodPayload,
              senderId: profile.senderId,
              privateKeyPem: signingKey,
              payloadKey,
              headerMacKey
            })
          );
        }
        return;
      }

      writeJsonLine(socket, envelope);
    });

    socket.on(
      'data',
      createJsonLineParser(
        (message) => {
          responses.push(message);
          console.log(`[xApp:${profile.senderId}] RIC response: ${JSON.stringify(message)}`);
          if (mode !== 'replay' && mode !== 'flood') {
            done();
          }
          if (mode === 'replay' && responses.length >= 2) {
            done();
          }
          if (mode === 'flood' && responses.length >= Number(options.count ?? process.env.XAPP_FLOOD_COUNT ?? 35)) {
            done();
          }
        },
        (error) => done(error)
      )
    );

    socket.on('error', (error) => {
      if (profileName === 'foreign') {
        console.log(`[xApp:${profile.senderId}] expected TLS failure: ${error.message}`);
        resolve([{ status: 'rejected', reason: error.message }]);
        return;
      }

      reject(error);
    });

    socket.on('end', () => {
      if (responses.length > 0) {
        done();
      }
    });

    socket.setTimeout(5_000, () => {
      if (responses.length > 0) {
        done();
      } else {
        done(new Error('timed out waiting for RIC response'));
      }
    });
  });
}

function parseArgs(argv) {
  const parsed = {};
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--profile') parsed.profile = argv[++index];
    else if (arg === '--mode') parsed.mode = argv[++index];
    else if (arg === '--host') parsed.host = argv[++index];
    else if (arg === '--port') parsed.port = Number(argv[++index]);
    else if (arg === '--count') parsed.count = Number(argv[++index]);
  }
  return parsed;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  runXapp(parseArgs(process.argv.slice(2))).catch((error) => {
    console.error(`[xApp] fatal: ${error.message}`);
    process.exitCode = 1;
  });
}
