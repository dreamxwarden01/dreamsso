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
  if (!Number.isSafeInteger(ttlSeconds) || ttlSeconds <= 0) throw new Error('invalid_session_ttl');
  const sid = crypto.randomBytes(32).toString('base64url');
  if (data.ssoSid) {
    // Replacement and its index publish together. Revocation cannot observe a
    // partially-created session or lose a newly-added index member.
    await redis.eval(`
      local previous = redis.call('SMEMBERS', KEYS[2])
      for _, old in ipairs(previous) do redis.call('DEL', ARGV[4] .. old) end
      redis.call('DEL', KEYS[2])
      redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2])
      redis.call('SADD', KEYS[2], ARGV[3])
      redis.call('EXPIRE', KEYS[2], ARGV[2])
      return 1
    `, 2, KEY(sid), SID_IDX(data.ssoSid), JSON.stringify(data), ttlSeconds, sid, KEY(''));
  } else {
    await redis.set(KEY(sid), JSON.stringify(data), 'EX', ttlSeconds);
  }
  return sid;
}

// Back-channel logout removes the indexed BFF sessions and index atomically.
// Login replacement is handled by createSession in its own atomic operation.
export async function revokeBySsoSid(ssoSid: string): Promise<number> {
  return Number(await redis.eval(`
    local sids = redis.call('SMEMBERS', KEYS[1])
    for _, sid in ipairs(sids) do redis.call('DEL', ARGV[1] .. sid) end
    redis.call('DEL', KEYS[1])
    return #sids
  `, 1, SID_IDX(ssoSid), KEY('')));
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

export async function updateSession(sid: string, data: SessionData): Promise<boolean> {
  // One atomic existing-only write. Missing/expired/non-expiring records are not
  // renewed, and an update cannot move a session to another identity/SID index.
  return (await redis.eval(`
    local ttl = redis.call('PTTL', KEYS[1])
    if ttl <= 0 then return 0 end
    local ok, old = pcall(cjson.decode, redis.call('GET', KEYS[1]))
    local updated = cjson.decode(ARGV[1])
    if not ok or type(old) ~= 'table' or old.sub ~= updated.sub or old.ssoSid ~= updated.ssoSid then return 0 end
    redis.call('SET', KEYS[1], ARGV[1], 'XX', 'KEEPTTL')
    return 1
  `, 1, KEY(sid), JSON.stringify(data))) === 1;
}

export async function destroySession(sid: string | undefined): Promise<void> {
  if (!sid) return;
  await redis.eval(`
    local raw = redis.call('GET', KEYS[1])
    if raw then
      local ok, data = pcall(cjson.decode, raw)
      if ok and type(data) == 'table' and type(data.ssoSid) == 'string' then
        redis.call('SREM', ARGV[2] .. data.ssoSid, ARGV[1])
      end
    end
    return redis.call('DEL', KEYS[1])
  `, 1, KEY(sid), sid, SID_IDX(''));
}
