import crypto from 'node:crypto';
import { redis } from './redis.js';

// Email verification state (change + confirm-current) — Redis, mirroring the
// passwordReset layout:
//   emailchg:tok:<sha256(token)>  the live link: {sub, kind, newEmail,
//                                 createdAt, lastSent}. kind 'change' swaps
//                                 the address on verify; 'confirm' only sets
//                                 email_verified on the CURRENT address.
//   emailchg:user:<sub>           pointer to the live token hash — one pending
//                                 per user, latest-wins; cancel/consume clears.
//   emailchg:addr:<email>         reservation: a pending CHANGE holds its new
//                                 address against every uniqueness check
//                                 (org create/edit, registration, other
//                                 changes), same family as reg:pending:*.
// Verification-link sends ride the SHARED per-address limiter in
// registration.ts (reg:rl:*) — one inbox, one budget across flows.

const TOKEN_TTL_SECONDS = 30 * 60;
const TOKEN_REUSE_SECONDS = 5 * 60;
export const emailChangeValidityMinutes = TOKEN_TTL_SECONDS / 60;

const sha256 = (s: string) => crypto.createHash('sha256').update(s).digest('hex');
const tokKey = (hash: string) => `emailchg:tok:${hash}`;
const userKey = (sub: string) => `emailchg:user:${sub}`;
const addrKey = (email: string) => `emailchg:addr:${email.toLowerCase()}`;

export interface EmailChange {
  sub: string;
  kind: 'change' | 'confirm';
  newEmail: string; // for 'confirm' this is the CURRENT address
  token: string; // raw — needed to re-send the same link (server-side only)
  createdAt: number;
  lastSent: number;
}

export async function getEmailChange(sub: string): Promise<EmailChange | null> {
  const hash = await redis.get(userKey(sub));
  if (!hash) return null;
  const raw = await redis.get(tokKey(hash));
  return raw ? (JSON.parse(raw) as EmailChange) : null;
}

// Issue (or same-token re-send) the pending verification for a user.
// Latest-wins: a new target address kills the previous link + reservation.
export async function issueEmailChange(
  sub: string,
  kind: 'change' | 'confirm',
  newEmail: string,
): Promise<{ token: string; reused: boolean }> {
  const now = Math.floor(Date.now() / 1000);
  const cur = await getEmailChange(sub);
  if (cur && cur.kind === kind && cur.newEmail.toLowerCase() === newEmail.toLowerCase() &&
      now - cur.lastSent < TOKEN_REUSE_SECONDS) {
    const rec = { ...cur, lastSent: now };
    await redis.set(tokKey(sha256(cur.token)), JSON.stringify(rec), 'KEEPTTL');
    return { token: cur.token, reused: true };
  }
  if (cur) await dropEmailChange(cur);
  const token = crypto.randomBytes(32).toString('base64url');
  const rec: EmailChange = { sub, kind, newEmail, token, createdAt: now, lastSent: now };
  await redis.set(tokKey(sha256(token)), JSON.stringify(rec), 'EX', TOKEN_TTL_SECONDS);
  await redis.set(userKey(sub), sha256(token), 'EX', TOKEN_TTL_SECONDS);
  if (kind === 'change') await redis.set(addrKey(newEmail), sub, 'EX', TOKEN_TTL_SECONDS);
  return { token, reused: false };
}

// The public verify hop: single-use redemption by raw token.
export async function redeemEmailChange(token: string): Promise<EmailChange | null> {
  if (typeof token !== 'string' || token.length < 20 || token.length > 100) return null;
  const raw = await redis.getdel(tokKey(sha256(token)));
  if (!raw) return null;
  const rec = JSON.parse(raw) as EmailChange;
  await redis.del(userKey(rec.sub));
  if (rec.kind === 'change') await redis.del(addrKey(rec.newEmail));
  return rec;
}

export async function dropEmailChange(rec: EmailChange): Promise<void> {
  await redis.del(tokKey(sha256(rec.token)), userKey(rec.sub));
  if (rec.kind === 'change') await redis.del(addrKey(rec.newEmail));
}

export async function cancelEmailChange(sub: string): Promise<boolean> {
  const cur = await getEmailChange(sub);
  if (!cur) return false;
  await dropEmailChange(cur);
  return true;
}

// Reservation lookup for the shared uniqueness family (see emailReserved in
// registration.ts, which folds this in with registration pendings).
export async function changePendingForAddress(email: string): Promise<boolean> {
  return (await redis.exists(addrKey(email))) === 1;
}

// Who holds the reservation — a user re-submitting their OWN pending address
// must not collide with themselves.
export async function changePendingOwner(email: string): Promise<string | null> {
  return redis.get(addrKey(email));
}
