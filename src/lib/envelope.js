import { createCipheriv, createDecipheriv, createHmac, randomBytes, sign, verify } from 'node:crypto';
import { canonicalJson } from './canonical-json.js';
import { fromBase64Url, toBase64Url } from './encoding.js';

export const ENVELOPE_VERSION = '1.0';
export const SIGNATURE_ALGORITHM = 'ECDSA-P256-SHA256';
export const PAYLOAD_ALGORITHM = 'AES-256-GCM';
export const HEADER_MAC_ALGORITHM = 'HMAC-SHA256';

export function buildEnvelope({ payload, senderId, privateKeyPem, payloadKey, headerMacKey, now = Date.now(), nonce }) {
  const iv = nonce ? fromBase64Url(nonce) : randomBytes(12);
  if (iv.length !== 12) {
    throw new Error('AES-GCM requires a 96-bit nonce');
  }

  const timestamp = Math.floor(now / 1000);
  const nonceValue = toBase64Url(iv);
  const signatureInput = canonicalJson({
    nonce: nonceValue,
    payload,
    senderId,
    timestamp
  });
  const signature = sign('sha256', Buffer.from(signatureInput), privateKeyPem);

  const protectedHeader = {
    version: ENVELOPE_VERSION,
    senderId,
    timestamp,
    nonce: nonceValue,
    algorithms: {
      payload: PAYLOAD_ALGORITHM,
      signature: SIGNATURE_ALGORITHM,
      headerMac: HEADER_MAC_ALGORITHM
    },
    signature: toBase64Url(signature)
  };

  const aad = Buffer.from(canonicalJson(protectedHeader));
  const cipher = createCipheriv('aes-256-gcm', payloadKey, iv);
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([
    cipher.update(Buffer.from(canonicalJson(payload))),
    cipher.final()
  ]);
  const tag = cipher.getAuthTag();

  const hmac = createHmac('sha256', headerMacKey)
    .update(aad)
    .digest();

  return {
    ...protectedHeader,
    ciphertext: toBase64Url(ciphertext),
    tag: toBase64Url(tag),
    headerMac: toBase64Url(hmac)
  };
}

export function openEnvelope({
  envelope,
  publicKeyPem,
  payloadKey,
  headerMacKey,
  replayCache,
  maxSkewSeconds = 30,
  now = Date.now()
}) {
  validateEnvelopeShape(envelope);

  const protectedHeader = {
    version: envelope.version,
    senderId: envelope.senderId,
    timestamp: envelope.timestamp,
    nonce: envelope.nonce,
    algorithms: envelope.algorithms,
    signature: envelope.signature
  };
  const aad = Buffer.from(canonicalJson(protectedHeader));
  const expectedMac = createHmac('sha256', headerMacKey).update(aad).digest();
  const actualMac = fromBase64Url(envelope.headerMac);
  if (actualMac.length !== expectedMac.length || !actualMac.equals(expectedMac)) {
    throw new Error('header HMAC verification failed');
  }

  const currentSeconds = Math.floor(now / 1000);
  if (Math.abs(currentSeconds - envelope.timestamp) > maxSkewSeconds) {
    throw new Error('timestamp outside acceptable replay window');
  }

  if (replayCache?.has(envelope.nonce)) {
    throw new Error('nonce already seen');
  }

  const iv = fromBase64Url(envelope.nonce);
  const decipher = createDecipheriv('aes-256-gcm', payloadKey, iv);
  decipher.setAAD(aad);
  decipher.setAuthTag(fromBase64Url(envelope.tag));
  const plaintext = Buffer.concat([
    decipher.update(fromBase64Url(envelope.ciphertext)),
    decipher.final()
  ]);
  const payload = JSON.parse(plaintext.toString('utf8'));

  const signatureInput = canonicalJson({
    nonce: envelope.nonce,
    payload,
    senderId: envelope.senderId,
    timestamp: envelope.timestamp
  });
  const signatureValid = verify(
    'sha256',
    Buffer.from(signatureInput),
    publicKeyPem,
    fromBase64Url(envelope.signature)
  );
  if (!signatureValid) {
    throw new Error('ECDSA signature verification failed');
  }

  replayCache?.add(envelope.nonce, now);
  return { payload, protectedHeader };
}

function validateEnvelopeShape(envelope) {
  if (!envelope || typeof envelope !== 'object') {
    throw new Error('envelope must be an object');
  }

  if (envelope.version !== ENVELOPE_VERSION) {
    throw new Error(`unsupported envelope version: ${envelope.version}`);
  }

  if (envelope.algorithms?.payload !== PAYLOAD_ALGORITHM) {
    throw new Error('unsupported payload algorithm');
  }

  if (envelope.algorithms?.signature !== SIGNATURE_ALGORITHM) {
    throw new Error('unsupported signature algorithm');
  }

  if (envelope.algorithms?.headerMac !== HEADER_MAC_ALGORITHM) {
    throw new Error('unsupported header MAC algorithm');
  }

  for (const field of ['senderId', 'timestamp', 'nonce', 'signature', 'ciphertext', 'tag', 'headerMac']) {
    if (envelope[field] === undefined || envelope[field] === null) {
      throw new Error(`missing envelope field: ${field}`);
    }
  }
}
