import assert from 'node:assert';
import { spawnSync } from 'node:child_process';
import { X509Certificate } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import test from 'node:test';
import { authenticator } from 'otplib';
import { startRicServer } from '../src/ric-server.js';

const root = new URL('../', import.meta.url).pathname.replace(/\/+$/, '');

test('e2e: demo send accepted, replay and invalid totp', async (t) => {
  // generate PKI (depends on openssl)
  const gen = spawnSync('node', ['scripts/generate-pki.js'], { cwd: root, encoding: 'utf8' });
  if (gen.status !== 0) {
    t.skip(`generate-pki failed or openssl unavailable; skipping e2e tests: ${gen.stderr || gen.stdout}`);
    return;
  }

  // ensure pins.json contains a TOTP secret for xapp-legitimate
  const pinsPath = join(root, 'certs', 'pins.json');
  const pins = JSON.parse(readFileSync(pinsPath, 'utf8'));
  pins.xapps = pins.xapps ?? {};
  pins.xapps['xapp-legitimate'].totpSecret = 'JBSWY3DPEHPK3PXP';
  writeFileSync(pinsPath, JSON.stringify(pins, null, 2));

  // start server with ephemeral ports
  const srv = await startRicServer({ demoPort: 0, port: 0, demoApiKey: 'inforsec-demo-key' });
  try {
    const demoPort = srv.demoPort || (srv.demoServer && srv.demoServer.address && srv.demoServer.address().port);
    assert(demoPort, 'demo port not set');

    const demoUrl = `http://127.0.0.1:${demoPort}/demo/send`;
    const secret = 'JBSWY3DPEHPK3PXP';
    const token = authenticator.generate(secret);

    const nonce = `n-${Date.now()}`;
    const message = {
      senderId: 'xapp-legitimate',
      payload: { id: 'bundle-e2e-1', objects: [{ type: 'indicator' }], twoFactor: { token } },
      nonce
    };

    // send valid envelope via demo bridge
    const resp1 = await (await fetch(demoUrl, { method: 'POST', headers: { 'content-type': 'application/json', 'x-demo-api-key': 'inforsec-demo-key' }, body: JSON.stringify(message) })).json();
    assert.ok(resp1, 'no response');
    // should contain serverResponse with status accepted
    assert.strictEqual(resp1.serverResponse?.status, 'accepted');

    // replay: send same nonce again -> expect rejection
    const resp2 = await (await fetch(demoUrl, { method: 'POST', headers: { 'content-type': 'application/json', 'x-demo-api-key': 'inforsec-demo-key' }, body: JSON.stringify(message) })).json();
    // either rejected by serverResponse or returned as rejected status
    const status2 = resp2.serverResponse?.status ?? resp2.status;
    assert.ok(status2 === 'rejected' || status2 === 'error', 'replay not rejected');

    // invalid TOTP
    const badMessage = { senderId: 'xapp-legitimate', payload: { id: 'bundle-e2e-2', objects: [], twoFactor: { token: '000000' } }, nonce: `n-${Date.now()}` };
    const resp3 = await (await fetch(demoUrl, { method: 'POST', headers: { 'content-type': 'application/json', 'x-demo-api-key': 'inforsec-demo-key' }, body: JSON.stringify(badMessage) })).json();
    const status3 = resp3.serverResponse?.status ?? resp3.status;
    assert.ok(status3 === 'rejected' || status3 === 'error', 'invalid totp not rejected');

    // revocation test: add xapp fingerprint to revoked list then expect reject on new send
    const certPath = join(root, 'certs', 'xapp.cert.pem');
    const cert = new X509Certificate(readFileSync(certPath, 'utf8'));
    const fp = cert.fingerprint256.replaceAll(':', '').toUpperCase();
    const revokedPath = join(root, 'config', 'revoked.json');
    const revoked = JSON.parse(readFileSync(revokedPath, 'utf8'));
    revoked.revokedFingerprints = revoked.revokedFingerprints || [];
    revoked.revokedFingerprints.push(fp);
    writeFileSync(revokedPath, JSON.stringify(revoked, null, 2));

    const message4 = { senderId: 'xapp-legitimate', payload: { id: 'bundle-e2e-3', objects: [], twoFactor: { token: authenticator.generate(secret) } }, nonce: `n-${Date.now()}` };
    const resp4 = await (await fetch(demoUrl, { method: 'POST', headers: { 'content-type': 'application/json', 'x-demo-api-key': 'inforsec-demo-key' }, body: JSON.stringify(message4) })).json();
    // Should be rejected due to revocation
    const status4 = resp4.serverResponse?.status ?? resp4.status;
    assert.ok(status4 === 'rejected' || status4 === 'error', 'revocation not enforced');
  } finally {
    await srv.close();
  }
});
