import crypto from 'node:crypto';
import { redis } from './redis.js';
import { config } from './config.js';

// The BFF session lives server-side in Redis; the browser only ever holds an
// opaque cookie (acct_sid). OIDC tokens never reach client JS — that's the
// whole point of the backend-for-frontend.
export interface SessionData {
  sub: string;
  ssoSid?: string; // the SSO master session id (id_token `sid`) — for rotate + back-channel logout
  claims: Record<string, unknown>; // merged id_token + userinfo claims
  accessToken: string;
  idToken: string;
  accessExpiresAt: number; // epoch seconds — when the access token expires
  amr: string[];
  acr?: string;
  authTime?: number;
  permissions?: string[]; // granted RBAC keys, refreshed best-effort by /api/me
  createdAt: number;
}

const KEY = (sid: string) => `acct:sess:${sid}`;
// Index: SSO session id -> the set of BFF session ids bound to it. Powers
// rotate-by-sid (one live BFF session per SSO session) + back-channel logout.
const SID_IDX = (ssoSid: string) => `acct:ssosid:${ssoSid}`;

// ttlSeconds is capped by the caller at the SSO session's absolute expiry
// (`sess_exp` claim) — a BFF session never outlives the SSO session behind it.
export async function createSession(data: SessionData, ttlSeconds = config.sessionTtl): Promise<string> {
  const sid = crypto.randomBytes(32).toString('base64url');
  await redis.set(KEY(sid), JSON.stringify(data), 'EX', ttlSeconds);
  if (data.ssoSid) {
    await redis.sadd(SID_IDX(data.ssoSid), sid);
    await redis.expire(SID_IDX(data.ssoSid), ttlSeconds);
  }
  return sid;
}

// Revoke every BFF session bound to an SSO session — used both for rotate-on-login
// (drop the browser's prior session for this SSO session) and back-channel logout.
export async function revokeBySsoSid(ssoSid: string): Promise<number> {
  const sids = await redis.smembers(SID_IDX(ssoSid));
  if (sids.length) await redis.del(...sids.map(KEY));
  await redis.del(SID_IDX(ssoSid));
  return sids.length;
}

export async function getSession(sid: string | undefined): Promise<SessionData | null> {
  if (!sid) return null;
  const raw = await redis.get(KEY(sid));
  if (!raw) return null;
  try {
    return JSON.parse(raw) as SessionData;
  } catch {
    return null;
  }
}

export async function updateSession(sid: string, data: SessionData): Promise<void> {
  // Preserve the remaining TTL rather than resetting it on every write.
  const ttl = await redis.ttl(KEY(sid));
  await redis.set(KEY(sid), JSON.stringify(data), 'EX', ttl > 0 ? ttl : config.sessionTtl);
}

export async function destroySession(sid: string | undefined): Promise<void> {
  if (sid) await redis.del(KEY(sid));
}
