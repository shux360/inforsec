export class ReplayCache {
  constructor({ ttlMs = 30_000 } = {}) {
    this.ttlMs = ttlMs;
    this.entries = new Map();
  }

  has(nonce, now = Date.now()) {
    this.prune(now);
    return this.entries.has(nonce);
  }

  add(nonce, now = Date.now()) {
    this.prune(now);
    this.entries.set(nonce, now + this.ttlMs);
  }

  prune(now = Date.now()) {
    for (const [nonce, expiresAt] of this.entries.entries()) {
      if (expiresAt <= now) {
        this.entries.delete(nonce);
      }
    }
  }
}
