import { readFileSync, existsSync } from 'node:fs';
import { normalizeFingerprint } from './certs.js';

export class RevocationList {
  constructor(path, { pollMs = 5000 } = {}) {
    this.path = path;
    this.list = new Set();
    this.pollMs = pollMs;
    this._stopped = false;
    this.load();
    this._timer = setInterval(() => this.load(), this.pollMs);
  }

  load() {
    try {
      if (!existsSync(this.path)) return;
      const data = JSON.parse(readFileSync(this.path, 'utf8'));
      const revoked = new Set((data.revokedFingerprints ?? []).map(normalizeFingerprint));
      this.list = revoked;
    } catch (err) {
      // on parse error, do not replace the current list
      // keep previous revocation set until the file is valid again
      // logging is left to the caller
      // eslint-disable-next-line no-console
      console.error('[RevocationList] failed to load revocation list:', err.message);
    }
  }

  has(fingerprint) {
    if (!fingerprint) return false;
    return this.list.has(normalizeFingerprint(fingerprint));
  }

  close() {
    if (this._stopped) return;
    clearInterval(this._timer);
    this._stopped = true;
  }
}
