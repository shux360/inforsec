import assert from 'node:assert/strict';
import test from 'node:test';
import { ReplayCache } from '../src/lib/replay-cache.js';

test('ReplayCache remembers nonces until TTL expiry', () => {
  const cache = new ReplayCache({ ttlMs: 1000 });
  cache.add('abc', 1000);

  assert.equal(cache.has('abc', 1500), true);
  cache.prune(2500);
  assert.equal(cache.has('abc'), false);
});
