import { redis } from '../redis.js';
import { createCodeStore } from './codeStore.js';
export type { AuthCode } from './codeStore.js';

// Read the live Redis binding, including after installer reconnects.
export const { createCode, consumeCode } = createCodeStore({
  save: (key, value, ttl) => redis.set(key, value, 'EX', ttl),
  getdel: key => redis.getdel(key),
});
