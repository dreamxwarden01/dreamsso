import crypto from 'node:crypto';
import { pool } from './db.js';
import { sealSecret, openSecret } from './secretbox.js';

// Emailed one-time codes — videosite's semantics, ported:
//   - validity 5 min measured from sent_at (refreshed on every send/resend)
//   - resend within the window returns the SAME code (generated_at governs
//     regeneration); a new code resets the attempt counter
//   - 5 failed attempts kill the code (mustResend)
//   - per-user rolling 24h send limits: 60s cooldown, 20/day
// Codes are sealed at rest with KEY_ENCRYPTION_KEY (same as TOTP secrets).
const OTP_TTL_SECONDS = 300;
const MAX_ATTEMPTS = 5;
const COOLDOWN_SECONDS = 60;
const DAILY_CAP = 20;

export const otpValidityMinutes = OTP_TTL_SECONDS / 60;

const genCode = () => crypto.randomInt(0, 1_000_000).toString().padStart(6, '0');

// "dreamxwarden01@gmail.com" -> "dr•••••@gmail.com" (videosite-style masking).
export function maskEmail(email: string): string {
  const [local, domain] = email.split('@');
  if (!domain) return '•••••';
  const keep = local.slice(0, Math.min(2, Math.max(1, local.length - 1)));
  return `${keep}•••••@${domain}`;
}

export type IssueResult =
  | { ok: true; code: string }
  | { ok: false; reason: 'cooldown'; retryAfter: number }
  | { ok: false; reason: 'daily_limit'; retryAfter: number }; // seconds until the 24h window resets

export async function issueEmailOtp(sub: string, purpose = 'login'): Promise<IssueResult> {
  // Rolling 24h limits (cooldown + daily cap), reset when the window lapses.
  const { rows: [lim] } = await pool.query<{ total_sent: number; expired: boolean; since_last: number; daily_reset_in: number }>(
    `SELECT total_sent,
            first_sent < now() - interval '24 hours' AS expired,
            GREATEST(0, EXTRACT(EPOCH FROM (now() - last_sent)))::int AS since_last,
            GREATEST(0, EXTRACT(EPOCH FROM (first_sent + interval '24 hours' - now())))::int AS daily_reset_in
       FROM email_otp_limits WHERE user_sub = $1`,
    [sub],
  );
  if (lim && !lim.expired) {
    if (lim.total_sent >= DAILY_CAP) return { ok: false, reason: 'daily_limit', retryAfter: lim.daily_reset_in };
    if (lim.since_last < COOLDOWN_SECONDS) {
      return { ok: false, reason: 'cooldown', retryAfter: COOLDOWN_SECONDS - lim.since_last };
    }
  }

  // Reuse the live code when it's still fresh and has attempts left; otherwise
  // mint a new one (resets attempts). sent_at refreshes either way — it drives
  // the verification window.
  const { rows: [existing] } = await pool.query<{ code_enc: Buffer; fresh: boolean; attempts: number }>(
    `SELECT code_enc, attempts, generated_at > now() - ($3 || ' seconds')::interval AS fresh
       FROM email_otps WHERE user_sub = $1 AND purpose = $2`,
    [sub, purpose, OTP_TTL_SECONDS],
  );
  let code: string | null = null;
  if (existing && existing.fresh && existing.attempts < MAX_ATTEMPTS) {
    try {
      code = openSecret(existing.code_enc);
    } catch {
      code = null; // KEK changed / corrupt — fall through to a fresh code
    }
  }
  if (code) {
    await pool.query(`UPDATE email_otps SET sent_at = now() WHERE user_sub = $1 AND purpose = $2`, [sub, purpose]);
  } else {
    code = genCode();
    await pool.query(
      `INSERT INTO email_otps (user_sub, purpose, code_enc) VALUES ($1, $2, $3)
         ON CONFLICT (user_sub, purpose) DO UPDATE
           SET code_enc = EXCLUDED.code_enc, generated_at = now(), sent_at = now(), attempts = 0`,
      [sub, purpose, sealSecret(code)],
    );
  }

  await pool.query(
    `INSERT INTO email_otp_limits (user_sub, first_sent, last_sent, total_sent) VALUES ($1, now(), now(), 1)
       ON CONFLICT (user_sub) DO UPDATE SET
         first_sent = CASE WHEN email_otp_limits.first_sent < now() - interval '24 hours' THEN now() ELSE email_otp_limits.first_sent END,
         last_sent  = now(),
         total_sent = CASE WHEN email_otp_limits.first_sent < now() - interval '24 hours' THEN 1 ELSE email_otp_limits.total_sent + 1 END`,
    [sub],
  );
  return { ok: true, code };
}

export type VerifyOtpResult = { valid: true } | { valid: false; mustResend: boolean };

export async function verifyEmailOtp(sub: string, purpose: string, code: string): Promise<VerifyOtpResult> {
  const { rows: [row] } = await pool.query<{ code_enc: Buffer; attempts: number; live: boolean }>(
    `SELECT code_enc, attempts, sent_at > now() - ($3 || ' seconds')::interval AS live
       FROM email_otps WHERE user_sub = $1 AND purpose = $2`,
    [sub, purpose, OTP_TTL_SECONDS],
  );
  if (!row || !row.live) return { valid: false, mustResend: true };
  if (row.attempts >= MAX_ATTEMPTS) return { valid: false, mustResend: true };

  let stored: string | null = null;
  try {
    stored = openSecret(row.code_enc);
  } catch {
    /* treat as mismatch */
  }
  const match =
    stored != null && /^\d{6}$/.test(code) &&
    crypto.timingSafeEqual(Buffer.from(stored), Buffer.from(code));

  if (match) {
    await pool.query(`DELETE FROM email_otps WHERE user_sub = $1 AND purpose = $2`, [sub, purpose]);
    return { valid: true };
  }
  const attempts = row.attempts + 1;
  await pool.query(`UPDATE email_otps SET attempts = $3 WHERE user_sub = $1 AND purpose = $2`, [sub, purpose, attempts]);
  return { valid: false, mustResend: attempts >= MAX_ATTEMPTS };
}
