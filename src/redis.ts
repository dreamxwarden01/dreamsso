import { Redis } from 'ioredis';
import { config } from './config.js';

function makeRedis() {
  const r = new Redis(config.redisUrl);
  r.on('error', (err: Error) => console.error('Redis error:', err));
  return r;
}

// ES live binding: importers use `redis` and see reconnectRedis()'s swap.
export let redis = makeRedis();

// Rebuild the client against the current config.redisUrl (the /setup wizard calls
// this after writing .env).
export async function reconnectRedis(): Promise<void> {
  const old = redis;
  redis = makeRedis();
  try {
    await old.quit();
  } catch {
    /* best effort */
  }
}
