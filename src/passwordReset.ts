import crypto from 'node:crypto';
import { redis } from './redis.js';

// Password-reset state — all Redis, mirroring the login-txn pattern:
//   pwreset:tok:<sha256(token)>   the live reset token: {sub, attempts}.
//                                 Single-use, 30 min, burned by 5 failed
//                                 challenge attempts.
//   pwreset:user:<sub>            pointer to the live token hash — issuing a
//                                 new link invalidates the previous one
//                                 (latest-wins), and consumption clears both.
//   pwreset:rl:<email>            per-address send limiter {first, count, last}:
//                                 3 sends per rolling 24h + a 120s cooldown
//                                 since the last send. Reserve-then-send —
//                                 the slot is taken atomically BEFORE the
//                                 (slow) email call so concurrent requests
//                                 can't all pass at count=2; a failed send
//                                 releases the slot AND the cooldown (nothing
//                                 arrived, so an immediate retry is fine).
//   pwreset:pk:<sha256(token)>    in-flight WebAuthn challenge for the reset's
//                                 strong-factor ceremony (consumed per attempt).
//   pwreset:ticket:<sha256>       one-time login ticket for the post-reset
//                                 session hop onto the SSO origin (60s).

const TOKEN_TTL_SECONDS = 30 * 60;
const TICKET_TTL_SECONDS = 60;
const PK_TTL_SECONDS = 300;
const MAX_CHALLENGE_ATTEMPTS = 5;
const RL_MAX_SENDS = 3;
const RL_WINDOW_SECONDS = 24 * 3600;
const RL_COOLDOWN_SECONDS = 120;

export const resetTokenValidityMinutes = TOKEN_TTL_SECONDS / 60;

const sha256 = (s: string) => crypto.createHash('sha256').update(s).digest('hex');
const tokKey = (hash: string) => `pwreset:tok:${hash}`;
const userKey = (sub: string) => `pwreset:user:${sub}`;
const rlKey = (email: string) => `pwreset:rl:${email.toLowerCase()}`;
const pkKey = (hash: string) => `pwreset:pk:${hash}`;
const ticketKey = (hash: string) => `pwreset:ticket:${hash}`;

export interface ResetTokenRecord {
  sub: string;
  attempts: number;
}

export async function issueResetToken(sub: string): Promise<string> {
  const token = crypto.randomBytes(32).toString('base64url');
  const hash = sha256(token);
  // Latest-wins: kill the previous outstanding link (and any half-done ceremony).
  const prev = await redis.get(userKey(sub));
  if (prev) await redis.del(tokKey(prev), pkKey(prev));
  const rec: ResetTokenRecord = { sub, attempts: 0 };
  await redis.set(tokKey(hash), JSON.stringify(rec), 'EX', TOKEN_TTL_SECONDS);
  await redis.set(userKey(sub), hash, 'EX', TOKEN_TTL_SECONDS);
  return token;
}

export async function getResetToken(
  token: string,
): Promise<(ResetTokenRecord & { hash: string }) | null> {
  if (typeof token !== 'string' || token.length < 20 || token.length > 100) return null;
  const hash = sha256(token);
  const raw = await redis.get(tokKey(hash));
  if (!raw) return null;
  return { ...(JSON.parse(raw) as ResetTokenRecord), hash };
}

// A failed challenge attempt. Returns the remaining attempts; 0 = token burned.
export async function bumpResetAttempts(rec: ResetTokenRecord & { hash: string }): Promise<number> {
  const attempts = rec.attempts + 1;
  if (attempts >= MAX_CHALLENGE_ATTEMPTS) {
    await redis.del(tokKey(rec.hash), pkKey(rec.hash), userKey(rec.sub));
    return 0;
  }
  await redis.set(tokKey(rec.hash), JSON.stringify({ sub: rec.sub, attempts }), 'KEEPTTL');
  return MAX_CHALLENGE_ATTEMPTS - attempts;
}

export async function consumeResetToken(rec: ResetTokenRecord & { hash: string }): Promise<void> {
  await redis.del(tokKey(rec.hash), pkKey(rec.hash), userKey(rec.sub));
}

// --- send limiter: 3 emails per address per rolling 24h + 120s cooldown ---
// Atomic reserve (Lua): inside the window, deny past the count cap OR within
// the cooldown since the last send; window lapsed -> CLEAR the record and
// start fresh (count 1). The caller releases on send failure.
const RESERVE_LUA = `
local first = tonumber(redis.call('HGET', KEYS[1], 'first') or '0')
local count = tonumber(redis.call('HGET', KEYS[1], 'count') or '0')
local last = tonumber(redis.call('HGET', KEYS[1], 'last') or '0')
local now = tonumber(ARGV[1])
local win = tonumber(ARGV[2])
if count > 0 and (now - first) < win then
  if count >= tonumber(ARGV[3]) then return 0 end
  if (now - last) < tonumber(ARGV[4]) then return 0 end
  redis.call('HINCRBY', KEYS[1], 'count', 1)
  redis.call('HSET', KEYS[1], 'last', now)
  return 1
end
redis.call('DEL', KEYS[1])
redis.call('HSET', KEYS[1], 'first', now, 'count', 1, 'last', now)
redis.call('EXPIRE', KEYS[1], win)
return 1
`;
const RELEASE_LUA = `
local c = redis.call('HINCRBY', KEYS[1], 'count', -1)
if c < 0 then redis.call('HSET', KEYS[1], 'count', 0) end
redis.call('HDEL', KEYS[1], 'last')
return c
`;

export async function reserveResetSend(email: string): Promise<boolean> {
  const ok = (await redis.eval(
    RESERVE_LUA, 1, rlKey(email),
    String(Math.floor(Date.now() / 1000)), String(RL_WINDOW_SECONDS),
    String(RL_MAX_SENDS), String(RL_COOLDOWN_SECONDS),
  )) as number;
  return ok === 1;
}

export async function releaseResetSend(email: string): Promise<void> {
  await redis.eval(RELEASE_LUA, 1, rlKey(email));
}

// --- WebAuthn challenge for the reset's strong-factor step (consumed per attempt) ---

export async function storeResetPasskeyChallenge(tokenHash: string, challenge: string): Promise<void> {
  await redis.set(pkKey(tokenHash), challenge, 'EX', PK_TTL_SECONDS);
}

export async function takeResetPasskeyChallenge(tokenHash: string): Promise<string | null> {
  return redis.getdel(pkKey(tokenHash));
}

// --- one-time login ticket: reset complete -> session on the SSO origin ---

export interface LoginTicket {
  sub: string;
  amr: string[];
  acr: string;
  userLabel: string; // KMSI chip: display_name || username
}

export async function mintLoginTicket(t: LoginTicket): Promise<string> {
  const ticket = crypto.randomBytes(32).toString('base64url');
  await redis.set(ticketKey(sha256(ticket)), JSON.stringify(t), 'EX', TICKET_TTL_SECONDS);
  return ticket;
}

export async function redeemLoginTicket(ticket: string): Promise<LoginTicket | null> {
  if (typeof ticket !== 'string' || ticket.length < 20 || ticket.length > 100) return null;
  const raw = await redis.getdel(ticketKey(sha256(ticket)));
  return raw ? (JSON.parse(raw) as LoginTicket) : null;
}
