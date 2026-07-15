import crypto from 'node:crypto';
import { redis } from './redis.js';
import { pool } from './db.js';

// Self-serve registration state — Redis for the hot path (like passwordReset):
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
// Invitation codes are Postgres (invitation_codes) — the consumed record must
// outlive Redis.

const TOKEN_TTL_SECONDS = 30 * 60;
const TOKEN_REUSE_SECONDS = 5 * 60;
const RL_MAX_SENDS = 5;
const RL_WINDOW_SECONDS = 24 * 3600;
const RL_BACKOFFS = [0, 60, 120, 180, 240]; // seconds, indexed by sends-so-far
export const MAX_CODE_USES = 3; // email SWITCHES per code; the 4th voids it
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
  const cur = await getPending(email);
  if (cur && cur.code === code && now - cur.lastSent < TOKEN_REUSE_SECONDS) {
    await redis.set(pendKey(email), JSON.stringify({ ...cur, lastSent: now }), 'KEEPTTL');
    return { token: cur.token, reused: true };
  }
  const token = crypto.randomBytes(48).toString('hex');
  const rec: PendingRegistration = { token, code, createdAt: now, lastSent: now };
  await redis.set(pendKey(email), JSON.stringify(rec), 'EX', TOKEN_TTL_SECONDS);
  return { token, reused: false };
}

// Constant-ish time token check; the pending row stays until consumed/evicted.
export async function validatePending(email: string, token: string): Promise<PendingRegistration | null> {
  if (typeof token !== 'string' || token.length < 32 || token.length > 128) return null;
  const cur = await getPending(email);
  if (!cur) return null;
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

// --- invitation codes (Postgres; consumed rows are permanent records) ---

const CODE_CHARSET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
export const CODE_RE = /^[A-Z0-9]{12}$/;

export function generateInviteCode(): string {
  const bytes = crypto.randomBytes(12);
  let out = '';
  for (const b of bytes) out += CODE_CHARSET[b % CODE_CHARSET.length];
  return out;
}

export interface LiveInvite {
  code: string;
  invited_role_slug: string | null;
  use_count: number;
  pending_email: string | null;
}

// A code usable at /register/start: exists, unconsumed, unvoided, unexpired.
export async function getLiveInvite(code: string): Promise<LiveInvite | null> {
  if (!CODE_RE.test(code)) return null;
  const { rows: [r] } = await pool.query<LiveInvite>(
    `SELECT code, invited_role_slug, use_count, pending_email
       FROM invitation_codes
      WHERE code = $1 AND used_by IS NULL AND voided_at IS NULL AND expires_at > now()`,
    [code],
  );
  return r ?? null;
}

// Void = mark, don't delete (user design): the row stays VISIBLE for 24h
// (voided_at distinguishes it from merely expired), then the sweeper clears
// it. Kills any in-flight pending link. Shared by the org-page void and the
// overuse auto-void (possibly a compromised code).
export async function voidInvite(code: string, pendingEmail: string | null): Promise<void> {
  if (pendingEmail) await dropPending(pendingEmail);
  await pool.query(
    `UPDATE invitation_codes
        SET voided_at = now(), clear_at = now() + interval '24 hours',
            pending_email = NULL, pending_at = NULL
      WHERE code = $1 AND used_by IS NULL AND voided_at IS NULL`,
    [code],
  );
}

// Claim a use for `email`. Same-address resend is free; a switch increments
// use_count, evicts the previous address's pending registration, and past the
// cap VOIDS the code. Returns what happened.
export async function claimInviteUse(
  invite: LiveInvite,
  email: string,
): Promise<'resend' | 'claimed' | 'voided'> {
  if (invite.pending_email && invite.pending_email.toLowerCase() === email.toLowerCase()) {
    await pool.query('UPDATE invitation_codes SET pending_at = now() WHERE code = $1', [invite.code]);
    return 'resend';
  }
  if (invite.use_count >= MAX_CODE_USES) {
    await voidInvite(invite.code, invite.pending_email);
    return 'voided';
  }
  if (invite.pending_email) await dropPending(invite.pending_email);
  await pool.query(
    `UPDATE invitation_codes SET use_count = use_count + 1, pending_email = $2, pending_at = now()
      WHERE code = $1`,
    [invite.code, email],
  );
  return 'claimed';
}

// Consume at completion — the permanent record (clear_at NULL = keep forever).
// Fails when the code was voided mid-flow so the registration refuses.
export async function consumeInvite(code: string, sub: string): Promise<boolean> {
  const { rowCount } = await pool.query(
    `UPDATE invitation_codes
        SET used_by = $2, used_at = now(), clear_at = NULL,
            pending_email = NULL, pending_at = NULL
      WHERE code = $1 AND used_by IS NULL AND voided_at IS NULL`,
    [code, sub],
  );
  return (rowCount ?? 0) > 0;
}

// A live pending registration reserves its address system-wide: admin
// user-create/edit and self-service email changes treat it as taken.
export async function pendingEmailExists(email: string): Promise<boolean> {
  return (await redis.exists(`reg:pending:${email.toLowerCase()}`)) === 1;
}

// The whole reservation family: registration pendings + pending email
// CHANGES both hold their target address against every uniqueness check.
export async function emailReserved(email: string): Promise<boolean> {
  const { changePendingForAddress } = await import('./emailChange.js');
  return (await pendingEmailExists(email)) || (await changePendingForAddress(email));
}

// Hourly sweep: clear stale pending stamps (their Redis rows are long gone),
// then delete rows past their clear_at (expired-unused after expiry+24h,
// voided after void+24h). Consumed rows have clear_at NULL — kept forever.
export async function sweepInvitations(): Promise<void> {
  try {
    await pool.query(
      `UPDATE invitation_codes SET pending_email = NULL, pending_at = NULL
        WHERE pending_at IS NOT NULL AND pending_at < now() - interval '40 minutes'`,
    );
    await pool.query(
      `DELETE FROM invitation_codes WHERE clear_at IS NOT NULL AND clear_at < now()`,
    );
  } catch (e) {
    console.error('sweepInvitations failed:', (e as Error).message);
  }
}
