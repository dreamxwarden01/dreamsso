import crypto from 'node:crypto';
import { redis } from '../redis.js';

// Single-use authorization code, bound to the client/redirect/PKCE/user/session.
// Short TTL; consumed exactly once at /token (next slice).
export interface AuthCode {
  clientId: string;
  redirectUri: string;
  userSub: string;
  sid: string;
  codeChallenge: string;
  codeChallengeMethod: string;
  nonce?: string;
  scope: string;
  amr: string[];
  acr?: string;
  authTime: number;
}

const KEY = (code: string) => `code:${code}`;
const TTL_SECONDS = 60;

export async function createCode(data: AuthCode): Promise<string> {
  const code = crypto.randomBytes(32).toString('base64url');
  await redis.set(KEY(code), JSON.stringify(data), 'EX', TTL_SECONDS);
  return code;
}

export async function consumeCode(code: string): Promise<AuthCode | null> {
  const key = KEY(code);
  const raw = await redis.get(key);
  if (!raw) return null;
  await redis.del(key); // single-use
  return JSON.parse(raw) as AuthCode;
}
