export class RateLimiter {
  constructor({ limit, windowMs = 60_000 }) {
    this.limit = limit;
    this.windowMs = windowMs;
    this.buckets = new Map();
  }

  consume(identity, now = Date.now()) {
    const bucket = this.buckets.get(identity);
    if (!bucket || bucket.resetAt <= now) {
      this.buckets.set(identity, { count: 1, resetAt: now + this.windowMs });
      return { allowed: true, remaining: this.limit - 1 };
    }

    bucket.count += 1;
    return {
      allowed: bucket.count <= this.limit,
      remaining: Math.max(0, this.limit - bucket.count)
    };
  }
}
