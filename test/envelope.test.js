import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import test from 'node:test';
import { buildEnvelope, openEnvelope } from '../src/lib/envelope.js';
import { ReplayCache } from '../src/lib/replay-cache.js';
import { fromBase64Url, toBase64Url } from '../src/lib/encoding.js';

const keyPair = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const privateKeyPem = keyPair.privateKey.export({ type: 'pkcs8', format: 'pem' });
const publicKeyPem = keyPair.publicKey.export({ type: 'spki', format: 'pem' });

function fixture() {
  return {
    payload: {
      type: 'bundle',
      id: 'bundle--unit-test',
      objects: [{ type: 'indicator', id: 'indicator--unit-test' }]
    },
    senderId: 'xapp-legitimate',
    privateKeyPem,
    publicKeyPem,
    payloadKey: randomBytes(32),
    headerMacKey: randomBytes(32),
    now: Date.now()
  };
}

test('opens a valid encrypted and signed CTI envelope', () => {
  const data = fixture();
  const envelope = buildEnvelope(data);
  const opened = openEnvelope({
    envelope,
    publicKeyPem,
    payloadKey: data.payloadKey,
    headerMacKey: data.headerMacKey,
    replayCache: new ReplayCache(),
    now: data.now
  });

  assert.deepEqual(opened.payload, data.payload);
  assert.equal(opened.protectedHeader.senderId, 'xapp-legitimate');
});

test('rejects ciphertext tampering with AES-GCM authentication failure', () => {
  const data = fixture();
  const envelope = buildEnvelope(data);
  const ciphertext = fromBase64Url(envelope.ciphertext);
  ciphertext[0] ^= 0xff;
  envelope.ciphertext = toBase64Url(ciphertext);

  assert.throws(
    () =>
      openEnvelope({
        envelope,
        publicKeyPem,
        payloadKey: data.payloadKey,
        headerMacKey: data.headerMacKey,
        replayCache: new ReplayCache(),
        now: data.now
      }),
    /authenticate|Unsupported state|bad decrypt|unable to authenticate/i
  );
});

test('rejects replayed nonce', () => {
  const data = fixture();
  const replayCache = new ReplayCache();
  const envelope = buildEnvelope(data);

  openEnvelope({
    envelope,
    publicKeyPem,
    payloadKey: data.payloadKey,
    headerMacKey: data.headerMacKey,
    replayCache,
    now: data.now
  });

  assert.throws(
    () =>
      openEnvelope({
        envelope,
        publicKeyPem,
        payloadKey: data.payloadKey,
        headerMacKey: data.headerMacKey,
        replayCache,
        now: data.now
      }),
    /nonce already seen/
  );
});

test('rejects stale timestamps', () => {
  const data = fixture();
  const oldNow = data.now - 120_000;
  const envelope = buildEnvelope({ ...data, now: oldNow });

  assert.throws(
    () =>
      openEnvelope({
        envelope,
        publicKeyPem,
        payloadKey: data.payloadKey,
        headerMacKey: data.headerMacKey,
        replayCache: new ReplayCache(),
        now: data.now
      }),
    /timestamp outside acceptable replay window/
  );
});
