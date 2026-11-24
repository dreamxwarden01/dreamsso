import crypto from 'node:crypto';
import { redis } from './redis.js';
import { pool } from './db.js';

// Short-lived open-registration state and compatibility for existing email links:
//   reg:pending:<email>   the one in-flight registration per address:
//                         {token, code|null, createdAt, lastSent}. TTL = link
//                         validity (30 min) anchored at CREATION; a resend
//                         within 5 min re-sends the SAME token without
//                         extending the window (delivery-delay protection).
//   reg:rl:<email>        stateful send limiter, videosite policy: 5 sends per
//                         rolling 24h with ESCALATING backoff by sends-so-far
//                         (0/60/120/180/240s). Reserve-then-send; a failed
//                         send releases the slot. Deny returns retry_after +
//                         whether retrying can ever succeed inside the window.
// New invitations use the PostgreSQL lifecycle and durable mail queue; their
// binding and proof deadline do not depend on these short-lived Redis records.

const TOKEN_TTL_SECONDS = 30 * 60;
const TOKEN_REUSE_SECONDS = 5 * 60;
const RL_MAX_SENDS = 5;
const RL_WINDOW_SECONDS = 24 * 3600;
const RL_BACKOFFS = [0, 60, 120, 180, 240]; // seconds, indexed by sends-so-far
export const registrationLinkValidityMinutes = TOKEN_TTL_SECONDS / 60;

const sha256 = (s: string) => crypto.createHash('sha256').update(s).digest('hex');
const pendKey = (email: string) => `reg:pending:${email.toLowerCase()}`;
const rlKey = (email: string) => `reg:rl:${email.toLowerCase()}`;

export interface PendingRegistration {
  token: string; // raw — needed to re-send the same link (server-side only)
  code: string | null; // invitation code carried into the complete step
  createdAt: number; // epoch s — validity anchor
  lastSent: number; // epoch s — same-token resend window
}

export async function getPending(email: string): Promise<PendingRegistration | null> {
  const raw = await redis.get(pendKey(email));
  return raw ? (JSON.parse(raw) as PendingRegistration) : null;
}

// Issue (or re-use) the pending registration for an address. Returns the token
// to mail plus whether this was a same-token resend.
export async function issuePending(
  email: string,
  code: string | null,
): Promise<{ token: string; reused: boolean }> {
  const now = Math.floor(Date.now() / 1000);
  const token = crypto.randomBytes(48).toString('hex');
  const value = JSON.stringify({token,code,createdAt:now,lastSent:now});
  const raw = await redis.eval(`
    local raw=redis.call('GET',KEYS[1])
    if raw then
      local ok,old=pcall(cjson.decode,raw)
      if ok and old.code==cjson.decode(ARGV[1]).code and tonumber(old.createdAt) and tonumber(old.lastSent)
         and tonumber(ARGV[2])-old.createdAt<tonumber(ARGV[3]) and tonumber(ARGV[2])-old.lastSent<tonumber(ARGV[4])
         and redis.call('TTL',KEYS[1])>0 then
        old.lastSent=tonumber(ARGV[2]);redis.call('SET',KEYS[1],cjson.encode(old),'KEEPTTL');return cjson.encode(old)
      end
    end
    redis.call('SET',KEYS[1],ARGV[1],'EX',ARGV[3]);return ARGV[1]
  `,1,pendKey(email),value,String(now),String(TOKEN_TTL_SECONDS),String(TOKEN_REUSE_SECONDS)) as string;
  const rec=JSON.parse(raw) as PendingRegistration;
  return {token:rec.token,reused:rec.token!==token};
}

// Constant-ish time token check; the pending row stays until consumed/evicted.
export async function validatePending(email: string, token: string): Promise<PendingRegistration | null> {
  if (typeof token !== 'string' || token.length < 32 || token.length > 128) return null;
  const cur = await getPending(email);
  if (!cur || !Number.isFinite(cur.createdAt) || Math.floor(Date.now()/1000)-cur.createdAt >= TOKEN_TTL_SECONDS) return null;
  const a = Buffer.from(sha256(cur.token));
  const b = Buffer.from(sha256(token));
  return crypto.timingSafeEqual(a, b) ? cur : null;
}

export async function dropPending(email: string): Promise<void> {
  await redis.del(pendKey(email));
}

// --- stateful send limiter (videosite policy) ---
// Reply: {1, next_backoff}                 -> reserved; next_backoff for the UI
//        {0, retry_after, can_retry(0|1)}  -> denied
const RESERVE_LUA = `
local first = tonumber(redis.call('HGET', KEYS[1], 'first') or '0')
local count = tonumber(redis.call('HGET', KEYS[1], 'count') or '0')
local last = tonumber(redis.call('HGET', KEYS[1], 'last') or '0')
local now = tonumber(ARGV[1])
local win = tonumber(ARGV[2])
local max = tonumber(ARGV[3])
if count > 0 and (now - first) < win then
  if count >= max then return {0, (first + win) - now, 0} end
  local backoff = tonumber(ARGV[3 + math.min(count, max - 1) + 1])
  if (now - last) < backoff then return {0, backoff - (now - last), 1} end
  redis.call('HINCRBY', KEYS[1], 'count', 1)
  redis.call('HSET', KEYS[1], 'last', now)
  local nb = tonumber(ARGV[3 + math.min(count + 1, max - 1) + 1])
  return {1, nb}
end
redis.call('DEL', KEYS[1])
redis.call('HSET', KEYS[1], 'first', now, 'count', 1, 'last', now)
redis.call('EXPIRE', KEYS[1], win)
return {1, tonumber(ARGV[5])}
`;
const RELEASE_LUA = `
local c = redis.call('HINCRBY', KEYS[1], 'count', -1)
if c < 0 then redis.call('HSET', KEYS[1], 'count', 0) end
redis.call('HDEL', KEYS[1], 'last')
return c
`;

export type SendReservation =
  | { ok: true; nextBackoff: number }
  | { ok: false; retryAfter: number; canRetry: boolean };

export async function reserveRegistrationSend(email: string): Promise<SendReservation> {
  const r = (await redis.eval(
    RESERVE_LUA, 1, rlKey(email),
    String(Math.floor(Date.now() / 1000)), String(RL_WINDOW_SECONDS), String(RL_MAX_SENDS),
    ...RL_BACKOFFS.map(String),
  )) as number[];
  if (r[0] === 1) return { ok: true, nextBackoff: r[1] ?? 0 };
  return { ok: false, retryAfter: Math.max(1, r[1] ?? 60), canRetry: r[2] === 1 };
}

export async function releaseRegistrationSend(email: string): Promise<void> {
  await redis.eval(RELEASE_LUA, 1, rlKey(email));
}

// Invitation lifecycle is stored in invitations.ts. Codes remain displayable audit IDs.
export const CODE_RE = /^[A-Z0-9]{12}$/;
export function generateInviteCode(): string {
  return Array.from({length:12},()=> 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'[crypto.randomInt(36)]).join('');
}

// Pending verification records are proofs, not global address reservations.

// Invitation records and their immutable email bindings are retained permanently.
// Only expired private delivery material and short-lived completion receipts are pruned.
export async function sweepInvitations(): Promise<void> {
  await pool.query("UPDATE invitation_mail_jobs SET payload_enc=NULL WHERE expires_at<clock_timestamp() AND payload_enc IS NOT NULL");
  await pool.query("DELETE FROM registration_completions WHERE retry_until<clock_timestamp()");
}
