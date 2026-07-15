// TOTP authenticator management (the SSO's normalized `totp_credentials` table).
// otplib v13 functional API + qrcode; secrets sealed with KEY_ENCRYPTION_KEY.
// Passkeys (webauthn_credentials) land next; this file is authenticator-only.
import { generateSecret, generateURI, verifySync } from 'otplib';
import QRCode from 'qrcode';
import { pool } from './db.js';
import { redis } from './redis.js';
import { sealSecret, openSecret } from './secretbox.js';
import { getSetting } from './settings.js';

// TOTP replay protection (otplib-native, PER AUTHENTICATOR): remember the last
// accepted time step for each credential and pass it as `afterTimeStep`, so codes
// at or before it are rejected. Tracking the STEP per credential is collision-free
// — unlike a per-code marker, where two of the up-to-15 live OTPs (±1 step × ≤5
// authenticators) could share a 6-digit value and wrongly block each other. TTL
// only needs to outlive a code's validity (epochTolerance ±1 step ≈ 90s); 300s for margin.
const TOTP_STEP_TTL = 300;
const totpStepKey = (credentialId: string) => `totp:step:${credentialId}`;

// Atomic single-use claim on a credential's TOTP time step: SET only if the new
// step is strictly newer than the stored one, so replays (same/earlier step) and
// concurrent submissions of the same code are rejected. Lua = one atomic op, no
// GET-then-SET race. Returns true iff the step was newly claimed.
const CLAIM_STEP_LUA = `
local cur = tonumber(redis.call('GET', KEYS[1])) or 0
if tonumber(ARGV[1]) > cur then
  redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2])
  return 1
end
return 0`;
async function claimTotpStep(credentialId: string, timeStep: number): Promise<boolean> {
  const r = await redis.eval(CLAIM_STEP_LUA, 1, totpStepKey(credentialId), String(timeStep), String(TOTP_STEP_TTL));
  return Number(r) === 1;
}

const MAX_AUTHENTICATORS = 5;
// Unconfirmed setup rows expire: the QR/secret is only confirmable for this long
// (abandoned setups are also cleared on the next setup attempt).
const SETUP_TTL_MINUTES = 15;

export interface AuthenticatorRow {
  id: string;
  label: string | null;
  created_at: string;
  last_used_at: string | null;
}

export async function listAuthenticators(sub: string): Promise<AuthenticatorRow[]> {
  const { rows } = await pool.query(
    `SELECT id, label, created_at, last_used_at FROM totp_credentials
       WHERE user_sub = $1 AND confirmed_at IS NOT NULL ORDER BY created_at`,
    [sub],
  );
  return rows;
}

export interface TotpSetup {
  id: string;
  secret: string;
  otpauth_uri: string;
  qr_data_url: string;
}

// Begins setup: stores an UNCONFIRMED row (confirmed_at NULL) and returns the
// secret/QR. Abandoned (unconfirmed) attempts are cleared first.
export async function startAuthenticatorSetup(
  sub: string,
  username: string,
  label: string | null,
): Promise<TotpSetup | { error: string }> {
  const { rows: [{ count }] } = await pool.query(
    `SELECT COUNT(*)::int AS count FROM totp_credentials WHERE user_sub = $1 AND confirmed_at IS NOT NULL`,
    [sub],
  );
  if (count >= MAX_AUTHENTICATORS) return { error: `maximum of ${MAX_AUTHENTICATORS} authenticators` };

  await pool.query(`DELETE FROM totp_credentials WHERE user_sub = $1 AND confirmed_at IS NULL`, [sub]);

  const secret = generateSecret();
  const issuer = (await getSetting('site_name', 'DreamSSO'))!;
  const otpauth_uri = generateURI({ label: username, issuer, secret, strategy: 'totp' });
  const qr_data_url = await QRCode.toDataURL(otpauth_uri);
  const { rows: [row] } = await pool.query(
    `INSERT INTO totp_credentials (user_sub, secret_enc, label) VALUES ($1, $2, $3) RETURNING id`,
    [sub, sealSecret(secret), label],
  );
  return { id: row.id, secret, otpauth_uri, qr_data_url };
}

// Confirms the pending row with a 6-digit code; flips confirmed_at + sets label.
export async function confirmAuthenticator(
  sub: string,
  id: string,
  code: string,
  label: string | null,
): Promise<{ ok: boolean; reason?: string }> {
  const { rows: [row] } = await pool.query(
    `SELECT secret_enc FROM totp_credentials
      WHERE id = $1 AND user_sub = $2 AND confirmed_at IS NULL
        AND created_at > now() - ($3 || ' minutes')::interval`,
    [id, sub, SETUP_TTL_MINUTES],
  );
  if (!row) return { ok: false, reason: 'not_found' };
  let secret: string;
  try {
    secret = openSecret(row.secret_enc);
  } catch {
    return { ok: false, reason: 'decrypt_failed' };
  }
  const result = verifySync({ token: String(code), secret, strategy: 'totp', epochTolerance: 30 });
  if (!result.valid) return { ok: false, reason: 'invalid_code' };
  // Record the step so the setup code can't be replayed on the login/step-up path.
  await claimTotpStep(id, (result as { timeStep: number }).timeStep);
  await pool.query(
    `UPDATE totp_credentials SET confirmed_at = now(), label = COALESCE($3, label) WHERE id = $1 AND user_sub = $2`,
    [id, sub, label],
  );
  return { ok: true };
}

export async function renameAuthenticator(sub: string, id: string, label: string): Promise<boolean> {
  const { rowCount } = await pool.query(
    `UPDATE totp_credentials SET label = $3 WHERE id = $1 AND user_sub = $2 AND confirmed_at IS NOT NULL`,
    [id, sub, label],
  );
  return (rowCount ?? 0) > 0;
}

export async function removeAuthenticator(sub: string, id: string): Promise<boolean> {
  const { rowCount } = await pool.query(`DELETE FROM totp_credentials WHERE id = $1 AND user_sub = $2`, [id, sub]);
  return (rowCount ?? 0) > 0;
}

// How many confirmed authenticators a user has — drives the login-challenge
// method computation (strong factor present -> challenge required).
export async function countAuthenticators(sub: string): Promise<number> {
  const { rows: [r] } = await pool.query(
    `SELECT COUNT(*)::int AS n FROM totp_credentials WHERE user_sub = $1 AND confirmed_at IS NOT NULL`,
    [sub],
  );
  return r.n;
}

// Verify a login-challenge code against ANY of the user's confirmed
// authenticators (a user may have several). Touches last_used_at on the match.
export async function verifyLoginTotp(sub: string, code: string): Promise<boolean> {
  if (!/^\d{6}$/.test(code)) return false;
  const { rows } = await pool.query(
    `SELECT id, secret_enc FROM totp_credentials WHERE user_sub = $1 AND confirmed_at IS NOT NULL`,
    [sub],
  );
  for (const row of rows) {
    let secret: string;
    try {
      secret = openSecret(row.secret_enc);
    } catch {
      continue;
    }
    const result = verifySync({ token: code, secret, strategy: 'totp', epochTolerance: 30 });
    if (!result.valid) continue;
    // Single-use: reject if this credential's step was already consumed (a replay
    // or a concurrent duplicate). Covers login, step-up, and everything routed here.
    if (!(await claimTotpStep(row.id, (result as { timeStep: number }).timeStep))) continue;
    await pool.query(`UPDATE totp_credentials SET last_used_at = now() WHERE id = $1`, [row.id]);
    return true;
  }
  return false;
}
