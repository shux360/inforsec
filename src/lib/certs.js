import { createHash, X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';

export function normalizeFingerprint(value) {
  return value.replaceAll(':', '').toUpperCase();
}

export function fingerprintFromPem(pem) {
  const cert = new X509Certificate(pem);
  return normalizeFingerprint(cert.fingerprint256);
}

export function fingerprintFromRaw(rawCert) {
  return createHash('sha256').update(rawCert).digest('hex').toUpperCase();
}

export function loadPins(path) {
  const pins = JSON.parse(readFileSync(path, 'utf8'));
  return {
    xapps: Object.fromEntries(
      Object.entries(pins.xapps ?? {}).map(([name, value]) => {
        if (typeof value === 'string') {
          return [name, { tlsFingerprint: normalizeFingerprint(value) }];
        }

        return [
          name,
          {
            ...value,
            tlsFingerprint: normalizeFingerprint(value.tlsFingerprint)
          }
        ];
      })
    )
  };
}

export function loadRevokedFingerprints(path) {
  const data = JSON.parse(readFileSync(path, 'utf8'));
  return new Set((data.revokedFingerprints ?? []).map(normalizeFingerprint));
}

export function verifyCertificateIssuedByCa(rawCert, caPem, now = new Date()) {
  const cert = new X509Certificate(rawCert);
  const ca = new X509Certificate(caPem);
  const notBefore = new Date(cert.validFrom);
  const notAfter = new Date(cert.validTo);

  if (now < notBefore || now > notAfter) {
    throw new Error('certificate is outside its validity period');
  }

  if (cert.issuer !== ca.subject) {
    throw new Error('certificate issuer does not match trusted CA');
  }

  if (!cert.verify(ca.publicKey)) {
    throw new Error('certificate signature was not issued by trusted CA');
  }

  return cert;
}
