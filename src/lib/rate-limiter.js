export class RateLimiter {
  constructor({ limit, windowMs = 60_000, penaltyMs = null } = {}) {
    this.limit = limit;
    this.windowMs = windowMs;
    this.penaltyMs = penaltyMs ?? windowMs;
    this.buckets = new Map();
    this.blocked = new Map();
  }

  consume(identity, now = Date.now()) {
    const blockedUntil = this.blocked.get(identity) ?? 0;
    if (blockedUntil > now) {
      return { allowed: false, remaining: 0, retryAfter: Math.ceil((blockedUntil - now) / 1000) };
    }

    const bucket = this.buckets.get(identity);
    if (!bucket || bucket.resetAt <= now) {
      this.buckets.set(identity, { count: 1, resetAt: now + this.windowMs });
      return { allowed: true, remaining: this.limit - 1 };
    }

    bucket.count += 1;
    const allowed = bucket.count <= this.limit;
    const remaining = Math.max(0, this.limit - bucket.count);
    if (!allowed) {
      // apply penalty when the limit is exceeded
      this.blocked.set(identity, now + this.penaltyMs);
      return { allowed: false, remaining: 0, retryAfter: Math.ceil(this.penaltyMs / 1000) };
    }

    return { allowed, remaining };
  }

  isBlocked(identity, now = Date.now()) {
    const blockedUntil = this.blocked.get(identity) ?? 0;
    return blockedUntil > now;
  }

  unblock(identity) {
    this.blocked.delete(identity);
  }
}
