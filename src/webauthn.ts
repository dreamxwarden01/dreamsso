// Passkey (WebAuthn) management for the SSO's normalized `webauthn_credentials`.
// @simplewebauthn/server v13. The registration challenge is held in Redis keyed
// by the subject (no DB challenge table needed for self-service registration).
import crypto from 'node:crypto';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
  type RegistrationResponseJSON,
  type AuthenticationResponseJSON,
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
} from '@simplewebauthn/server';
import { pool } from './db.js';
import { redis } from './redis.js';
import { config } from './config.js';

const MAX_PASSKEYS = 10;
const CHALLENGE_TTL = 300; // 5 min
const regKey = (sub: string) => `acct:webauthn:reg:${sub}`;

export interface PasskeyRow {
  id: string;
  label: string | null;
  created_at: string;
  last_used_at: string | null;
}

export async function listPasskeys(sub: string): Promise<PasskeyRow[]> {
  const { rows } = await pool.query(
    `SELECT id, label, created_at, last_used_at FROM webauthn_credentials WHERE user_sub = $1 ORDER BY created_at`,
    [sub],
  );
  return rows;
}

// Generates creation options + stashes the challenge (keyed by sub) in Redis.
export async function startRegistration(
  sub: string,
  username: string,
  displayName: string,
): Promise<PublicKeyCredentialCreationOptionsJSON | { error: string }> {
  const { rows: [{ count }] } = await pool.query(
    `SELECT COUNT(*)::int AS count FROM webauthn_credentials WHERE user_sub = $1`,
    [sub],
  );
  if (count >= MAX_PASSKEYS) return { error: `maximum of ${MAX_PASSKEYS} passkeys` };

  const { rows: existing } = await pool.query(
    `SELECT credential_id, transports FROM webauthn_credentials WHERE user_sub = $1`,
    [sub],
  );
  const excludeCredentials = existing.map((r) => ({
    id: Buffer.from(r.credential_id).toString('base64url'),
    transports: r.transports ?? undefined,
  }));

  const options = await generateRegistrationOptions({
    rpName: config.webauthnRpName,
    rpID: config.webauthnRpId,
    userID: new TextEncoder().encode(sub),
    userName: username,
    userDisplayName: displayName,
    attestationType: 'none',
    excludeCredentials,
    // residentKey 'required' → discoverable credential (for usernameless sign-in
    // later). userVerification 'required' (NOT 'preferred'): it pairs with the
    // server's requireUserVerification:true in finishRegistration. With 'preferred'
    // an authenticator may skip UV — the response then comes back UV=false and the
    // server rejects it, so it fails on every device that chose not to prompt.
    // 'required' forces the Face ID / Touch ID / PIN prompt so UV is always
    // present and accepted. (Matches videosite prod.)
    authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
  });

  await redis.set(regKey(sub), options.challenge, 'EX', CHALLENGE_TTL);
  return options;
}

function rand6(): string {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const bytes = crypto.randomBytes(6);
  let s = '';
  for (let i = 0; i < 6; i++) s += alphabet[bytes[i] % alphabet.length];
  return s;
}

// Verifies the attestation against the stored challenge and persists the
// credential. Label defaults to `Passkey-XXXXXX` when blank.
export async function finishRegistration(
  sub: string,
  response: RegistrationResponseJSON,
  label: string | null,
): Promise<{ ok: boolean; reason?: string; id?: string; label?: string }> {
  const expectedChallenge = await redis.get(regKey(sub));
  if (!expectedChallenge) return { ok: false, reason: 'challenge_expired' };

  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response,
      expectedChallenge,
      expectedOrigin: config.webauthnOrigins,
      expectedRPID: config.webauthnRpId,
      // Pairs with userVerification:'required' in the options — accept only
      // user-verified responses (see the note in startRegistration).
      requireUserVerification: true,
    });
  } catch {
    return { ok: false, reason: 'verify_failed' };
  }
  if (!verification.verified || !verification.registrationInfo) return { ok: false, reason: 'not_verified' };
  await redis.del(regKey(sub));

  const info = verification.registrationInfo;
  const cred = info.credential;
  const aaguid = /^[0-9a-f-]{36}$/i.test(info.aaguid) ? info.aaguid : null;
  const finalLabel = label && label.trim() ? label.trim().slice(0, 100) : `Passkey-${rand6()}`;

  try {
    const { rows: [row] } = await pool.query(
      `INSERT INTO webauthn_credentials
         (user_sub, credential_id, public_key, sign_count, transports, aaguid, backup_eligible, backup_state, label)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id, label`,
      [
        sub,
        Buffer.from(cred.id, 'base64url'),
        Buffer.from(cred.publicKey),
        cred.counter ?? 0,
        cred.transports ?? null,
        aaguid,
        info.credentialDeviceType === 'multiDevice',
        info.credentialBackedUp,
        finalLabel,
      ],
    );
    return { ok: true, id: row.id, label: row.label };
  } catch (err) {
    if ((err as { code?: string }).code === '23505') return { ok: false, reason: 'already_registered' };
    throw err;
  }
}

export async function renamePasskey(sub: string, id: string, label: string): Promise<boolean> {
  const { rowCount } = await pool.query(
    `UPDATE webauthn_credentials SET label = $3 WHERE id = $1 AND user_sub = $2`,
    [id, sub, label],
  );
  return (rowCount ?? 0) > 0;
}

export async function removePasskey(sub: string, id: string): Promise<boolean> {
  const { rowCount } = await pool.query(`DELETE FROM webauthn_credentials WHERE id = $1 AND user_sub = $2`, [id, sub]);
  return (rowCount ?? 0) > 0;
}

export async function countPasskeys(sub: string): Promise<number> {
  const { rows: [r] } = await pool.query(
    `SELECT COUNT(*)::int AS n FROM webauthn_credentials WHERE user_sub = $1`,
    [sub],
  );
  return r.n;
}

// --- login-time assertions (first-factor sign-in + the MFA challenge) ---
// The challenge itself is stored by the CALLER inside the login txn (shared
// lifetime, reused across sheet-reopens, consumed per verification attempt).

// Username-less when `sub` is absent (discoverable credentials / conditional UI);
// scoped to the user's credentials in the challenge phase.
export async function loginAuthOptions(sub?: string): Promise<PublicKeyCredentialRequestOptionsJSON> {
  let allowCredentials;
  if (sub) {
    const { rows } = await pool.query(
      `SELECT credential_id, transports FROM webauthn_credentials WHERE user_sub = $1`,
      [sub],
    );
    allowCredentials = rows.map((r) => ({
      id: Buffer.from(r.credential_id).toString('base64url'),
      transports: r.transports ?? undefined,
    }));
  }
  return generateAuthenticationOptions({
    rpID: config.webauthnRpId,
    userVerification: 'required', // pairs with requireUserVerification below (see startRegistration note)
    timeout: 600_000, // one lifetime everywhere: the login txn's 10 minutes
    allowCredentials,
  });
}

// Verify an assertion: look the credential up by id, verify the signature, bump
// sign_count + last_used_at. `expectedSub` pins the challenge phase to the user
// who already passed the password (first-factor passes undefined).
export async function verifyLoginAssertion(
  response: AuthenticationResponseJSON,
  expectedChallenge: string,
  expectedSub?: string,
): Promise<{ ok: true; sub: string } | { ok: false; reason: string }> {
  let credId: Buffer;
  try {
    credId = Buffer.from(String(response.id ?? ''), 'base64url');
  } catch {
    return { ok: false, reason: 'malformed' };
  }
  if (!credId.length) return { ok: false, reason: 'malformed' };
  const { rows: [row] } = await pool.query(
    `SELECT id, user_sub, credential_id, public_key, sign_count, transports
       FROM webauthn_credentials WHERE credential_id = $1`,
    [credId],
  );
  if (!row) return { ok: false, reason: 'unknown_credential' };
  if (expectedSub && row.user_sub !== expectedSub) return { ok: false, reason: 'wrong_user' };

  try {
    const v = await verifyAuthenticationResponse({
      response,
      expectedChallenge,
      expectedOrigin: config.webauthnOrigins,
      expectedRPID: config.webauthnRpId,
      requireUserVerification: true,
      credential: {
        id: Buffer.from(row.credential_id).toString('base64url'),
        publicKey: new Uint8Array(row.public_key),
        counter: Number(row.sign_count),
        transports: row.transports ?? undefined,
      },
    });
    if (!v.verified) return { ok: false, reason: 'not_verified' };
    await pool.query(
      `UPDATE webauthn_credentials SET sign_count = $2, last_used_at = now() WHERE id = $1`,
      [row.id, v.authenticationInfo.newCounter],
    );
    return { ok: true, sub: row.user_sub };
  } catch {
    return { ok: false, reason: 'verify_failed' };
  }
}
