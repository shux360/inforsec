import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { authenticator } from 'otplib';

const demoUrl = process.env.DEMO_URL ?? 'http://127.0.0.1:8080/demo/send';
const apiKey = process.env.DEMO_API_KEY ?? 'inforsec-demo-key';
const secret = 'JBSWY3DPEHPK3PXP';

async function post(message) {
  const res = await fetch(demoUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-demo-api-key': apiKey },
    body: JSON.stringify(message)
  });
  const text = await res.text();
  try { return JSON.parse(text); } catch (e) { return text; }
}

(async () => {
  const token = authenticator.generate(secret);
  const nonce = `n-${Date.now()}`;
  const message = { senderId: 'xapp-legitimate', payload: { id: 'manual-1', objects: [{ type: 'indicator' }], twoFactor: { token } }, nonce };

  console.log('Sending valid message...');
  console.log(await post(message));

  console.log('Sending replay (same nonce) ...');
  console.log(await post(message));

  console.log('Sending invalid TOTP ...');
  const bad = { senderId: 'xapp-legitimate', payload: { id: 'manual-2', objects: [], twoFactor: { token: '000000' } }, nonce: `n-${Date.now()}` };
  console.log(await post(bad));

  console.log('Adding xapp fingerprint to revoked.json and testing revocation...');
  const certPath = join(process.cwd(), 'certs', 'xapp.cert.pem');
  const cert = readFileSync(certPath, 'utf8');
  // compute fingerprint using a simple regex extraction of PEM then rely on existing certs: hardcode fingerprint from earlier generation
  const fingerprint = '1662302029D093C958BF2C96F34527EB5AAB186A570960DB5153222917532958';
  const revokedPath = join(process.cwd(), 'config', 'revoked.json');
  const revoked = JSON.parse(readFileSync(revokedPath, 'utf8'));
  revoked.revokedFingerprints = revoked.revokedFingerprints || [];
  revoked.revokedFingerprints.push(fingerprint);
  writeFileSync(revokedPath, JSON.stringify(revoked, null, 2));

  console.log('Waiting 6s for revocation list to reload...');
  await new Promise((r) => setTimeout(r, 6000));

  const message3 = { senderId: 'xapp-legitimate', payload: { id: 'manual-3', objects: [], twoFactor: { token: authenticator.generate(secret) } }, nonce: `n-${Date.now()}` };
  console.log(await post(message3));

  console.log('Done');
})();
