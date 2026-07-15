import { Router, type Response, type NextFunction } from 'express';
import argon2 from 'argon2';
import { pool } from '../db.js';
import { requireScope, type AuthedRequest } from '../resourceAuth.js';
import { requirePerm, hasPerm, permissionDenied } from '../rbac/index.js';
import * as mfa from '../mfa.js';
import * as webauthn from '../webauthn.js';
import { fanOutLogout } from '../oidc/backchannel.js';
import { isStepupFresh } from '../oidc/sessions.js';
import { acceptedStepupMethods, stepupSatisfies } from '../oidc/stepupPolicy.js';

// The Security pane's resource API (password + MFA management), access-token
// protected. Self-service for the authenticated subject.
export const securityRouter = Router();
const scoped = requireScope('profile');

// A "strong" MFA factor = a confirmed TOTP or a passkey. Email is a low-trust
// channel that doesn't count. Removing the LAST strong factor is gated by
// profile.security.mfa.disable (privileged roles can't drop to email-only).
async function strongFactorCount(sub: string): Promise<number> {
  const { rows } = await pool.query<{ n: number }>(
    `SELECT (SELECT count(*) FROM totp_credentials WHERE user_sub = $1 AND confirmed_at IS NOT NULL)
          + (SELECT count(*) FROM webauthn_credentials WHERE user_sub = $1) AS n`,
    [sub],
  );
  return Number(rows[0]?.n ?? 0);
}
// True if removing one strong factor now would leave the user with none AND they
// may not disable MFA — i.e. the removal must be blocked.
async function blocksLastFactor(sub: string): Promise<boolean> {
  return (await strongFactorCount(sub)) <= 1 && !(await hasPerm(sub, 'profile.security.mfa.disable'));
}

function trimLabel(v: unknown): string | null {
  return typeof v === 'string' && v.trim() ? v.trim().slice(0, 100) : null;
}

// Per-account factor caps (setup AND finish both check — the second is the
// TOCTOU backstop).
const MAX_AUTHENTICATORS = 5;
const MAX_PASSKEYS = 10;

async function confirmedTotpCount(sub: string): Promise<number> {
  const { rows } = await pool.query<{ n: number }>(
    'SELECT count(*)::int AS n FROM totp_credentials WHERE user_sub = $1 AND confirmed_at IS NOT NULL', [sub]);
  return rows[0]?.n ?? 0;
}
async function passkeyCount(sub: string): Promise<number> {
  const { rows } = await pool.query<{ n: number }>(
    'SELECT count(*)::int AS n FROM webauthn_credentials WHERE user_sub = $1', [sub]);
  return rows[0]?.n ?? 0;
}

// Personal-security mutations (MFA toggle, factor add/remove, password change)
// demand a fresh sudo window in the FALLBACK tier: the owned strong factors if
// any, else a single fallback — email (MFA toggle on + verified) else password.
// So there's no "zero factors rides free" carve-out any more; a no-factor user
// confirms their password (the floor) via the challenge. A fresh login already
// stamped that method, so a just-signed-in user passes with no prompt, and only
// re-challenges once the window lapses. Unconditional (NOT behind
// stepup_portal_required), same stance as the email-change tier gate. The BFF
// forwards the caller's own master-session sid in x-stepup-sid; a successful
// step-up stamps that session, so the window is reusable across the portal.
//
// Two tiers by window: the MFA toggle rides the standard window
// (stepup_validity_minutes); factor ADD/REMOVE and password change reuse the same
// stamp but only within a stricter cap (FACTOR_STEPUP_MAX_S) — the client's
// page-entry gate re-challenges when less than 3 minutes of that cap remain.
export const FACTOR_STEPUP_MAX_S = 600; // 10 min
function requireSecurityStepup(maxAgeSeconds?: number) {
  return async (req: AuthedRequest, res: Response, next: NextFunction): Promise<void> => {
    const sub = req.auth!.sub;
    const sid = typeof req.headers['x-stepup-sid'] === 'string' ? req.headers['x-stepup-sid'] : '';
    if (/^[0-9a-f-]{36}$/.test(sid)) {
      const { rows: [s] } = await pool.query<{ user_sub: string; stepup_at: string | null; stepup_method: string | null }>(
        // Full-precision epoch (matches org.ts + the ms-precision status probe).
        'SELECT user_sub, EXTRACT(EPOCH FROM stepup_at)::text AS stepup_at, stepup_method FROM sessions WHERE sid = $1',
        [sid],
      );
      const at = s?.stepup_at ? Number(s.stepup_at) : null;
      if (s && s.user_sub === sub) {
        const withinCap = !maxAgeSeconds || (at != null && Date.now() / 1000 - at < maxAgeSeconds);
        const { accepted } = await acceptedStepupMethods(sub, 'fallback');
        if (withinCap && stepupSatisfies(accepted, s.stepup_method, await isStepupFresh(at))) {
          return next();
        }
      }
    }
    res.status(403).json({ error: 'step_up_required' });
  };
}

// Password policy (matches videosite): ≥8 chars AND ≥3 of {upper, lower, digit, special}.
// Exported: the password-reset confirm endpoint enforces the same rule.
export function passwordComplexityOk(pw: string): boolean {
  if (pw.length < 8) return false;
  let cats = 0;
  if (/[A-Z]/.test(pw)) cats++;
  if (/[a-z]/.test(pw)) cats++;
  if (/[0-9]/.test(pw)) cats++;
  if (/[^A-Za-z0-9]/.test(pw)) cats++;
  return cats >= 3;
}

// GET /account/security — password + MFA summary for the Security pane.
securityRouter.get('/account/security', scoped, async (req: AuthedRequest, res) => {
  const sub = req.auth!.sub;
  const { rows: [id] } = await pool.query(
    `SELECT email, email_verified, mfa_enabled, password_hash, password_changed_at
       FROM identities WHERE sub = $1 AND deleted_at IS NULL`,
    [sub],
  );
  if (!id) return res.status(404).json({ error: 'not_found' });

  const authenticators = await mfa.listAuthenticators(sub);
  // Passkeys land next turn; return the list so the pane can show a count today.
  const { rows: passkeys } = await pool.query(
    `SELECT id, label, created_at, last_used_at FROM webauthn_credentials WHERE user_sub = $1 ORDER BY created_at`,
    [sub],
  );

  res.json({
    password: { is_set: !!id.password_hash, changed_at: id.password_changed_at },
    mfa: {
      enabled: id.mfa_enabled, // the account toggle — login challenges only when true
      email: { address: id.email, verified: id.email_verified },
      authenticators,
      passkeys,
    },
  });
});

// POST /account/password — change password. NO current-password field: the tiered
// step-up gate (requireSecurityStepup, fallback tier) proves it's you — a stale
// window shows the "confirm your password" challenge, a fresh login/step-up passes
// with none (Google-style). A changed password still signs out every OTHER session.
securityRouter.post('/account/password', scoped, requirePerm('profile.security.password.change'), requireSecurityStepup(FACTOR_STEPUP_MAX_S), async (req: AuthedRequest, res) => {
  const sub = req.auth!.sub;
  const { new_password } = (req.body ?? {}) as { new_password?: unknown };
  if (typeof new_password !== 'string' || !passwordComplexityOk(new_password)) {
    return res.status(400).json({
      error: 'weak_password',
      error_description: 'min 8 chars and 3 of: uppercase, lowercase, digit, special',
    });
  }
  const { rows: [id] } = await pool.query(
    `SELECT sub FROM identities WHERE sub = $1 AND deleted_at IS NULL`,
    [sub],
  );
  if (!id) return res.status(404).json({ error: 'not_found' });

  const hash = await argon2.hash(new_password, { type: argon2.argon2id });
  await pool.query(`UPDATE identities SET password_hash = $2, password_changed_at = now() WHERE sub = $1`, [sub, hash]);

  // A changed password signs out every OTHER session (stated on the page).
  // The caller's own master sid rides in from the BFF; without a valid one,
  // deny-safe: revoke everything.
  const currentSid = typeof req.headers['x-stepup-sid'] === 'string' ? req.headers['x-stepup-sid'] : '';
  const keep = /^[0-9a-f-]{36}$/.test(currentSid);
  const { rows: revoked } = await pool.query<{ sid: string; clients: string[] | null }>(
    keep
      ? `DELETE FROM sessions WHERE user_sub = $1 AND sid <> $2 RETURNING sid, clients`
      : `DELETE FROM sessions WHERE user_sub = $1 RETURNING sid, clients`,
    keep ? [sub, currentSid] : [sub],
  );
  await Promise.allSettled(revoked.map((r) => fanOutLogout(sub, r.sid, r.clients ?? [])));
  res.status(204).end();
});

// --- the account MFA toggle ---
// Turning it ON is open to everyone with the permission; turning it OFF is what
// the mfa.disable permission guards (deny for privileged roles — they can't drop
// the login challenge). Sign-in method availability (e.g. passkey first-factor)
// is NOT affected by the toggle.

securityRouter.post('/account/mfa/enable', scoped, requirePerm('profile.security.mfa.enable'), requireSecurityStepup(), async (req: AuthedRequest, res) => {
  await pool.query(`UPDATE identities SET mfa_enabled = true WHERE sub = $1 AND deleted_at IS NULL`, [req.auth!.sub]);
  res.status(204).end();
});

securityRouter.post('/account/mfa/disable', scoped, requirePerm('profile.security.mfa.disable'), requireSecurityStepup(), async (req: AuthedRequest, res) => {
  await pool.query(`UPDATE identities SET mfa_enabled = false WHERE sub = $1 AND deleted_at IS NULL`, [req.auth!.sub]);
  res.status(204).end();
});

// --- authenticator (TOTP) ---

securityRouter.post('/account/mfa/authenticator/setup', scoped, requirePerm('profile.security.mfa.totp.add'), requireSecurityStepup(FACTOR_STEPUP_MAX_S), async (req: AuthedRequest, res) => {
  const sub = req.auth!.sub;
  const { rows: [id] } = await pool.query(
    `SELECT username FROM identities WHERE sub = $1 AND deleted_at IS NULL`,
    [sub],
  );
  if (!id) return res.status(404).json({ error: 'not_found' });
  if ((await confirmedTotpCount(sub)) >= MAX_AUTHENTICATORS) {
    return res.status(422).json({ error: 'limit_reached', limit: MAX_AUTHENTICATORS });
  }
  const r = await mfa.startAuthenticatorSetup(sub, id.username, trimLabel(req.body?.label));
  if ('error' in r) return res.status(422).json(r);
  res.json(r);
});

securityRouter.post('/account/mfa/authenticator/confirm', scoped, requirePerm('profile.security.mfa.totp.add'), requireSecurityStepup(FACTOR_STEPUP_MAX_S), async (req: AuthedRequest, res) => {
  const sub = req.auth!.sub;
  const { id, code } = (req.body ?? {}) as { id?: unknown; code?: unknown };
  if (typeof id !== 'string' || typeof code !== 'string') {
    return res.status(422).json({ error: 'id_and_code_required' });
  }
  if ((await confirmedTotpCount(sub)) >= MAX_AUTHENTICATORS) {
    return res.status(422).json({ error: 'limit_reached', limit: MAX_AUTHENTICATORS });
  }
  const r = await mfa.confirmAuthenticator(sub, id, code, trimLabel(req.body?.label));
  if (!r.ok) return res.status(422).json({ error: r.reason ?? 'confirm_failed' });
  res.status(204).end();
});

securityRouter.patch('/account/mfa/authenticator/:id', scoped, requirePerm('profile.security.mfa.totp.rename'), async (req: AuthedRequest, res) => {
  const label = trimLabel(req.body?.label);
  if (!label) return res.status(422).json({ error: 'invalid_label' });
  const ok = await mfa.renameAuthenticator(req.auth!.sub, req.params.id, label);
  if (!ok) return res.status(404).json({ error: 'not_found' });
  res.status(204).end();
});

securityRouter.delete('/account/mfa/authenticator/:id', scoped, requirePerm('profile.security.mfa.totp.remove'), requireSecurityStepup(FACTOR_STEPUP_MAX_S), async (req: AuthedRequest, res) => {
  if (await blocksLastFactor(req.auth!.sub)) return permissionDenied(res, 'profile.security.mfa.disable', 'last_strong_factor');
  const ok = await mfa.removeAuthenticator(req.auth!.sub, req.params.id);
  if (!ok) return res.status(404).json({ error: 'not_found' });
  res.status(204).end();
});

// --- passkeys (WebAuthn) ---

securityRouter.post('/account/mfa/passkey/register-options', scoped, requirePerm('profile.security.mfa.passkey.add'), requireSecurityStepup(FACTOR_STEPUP_MAX_S), async (req: AuthedRequest, res) => {
  const sub = req.auth!.sub;
  const { rows: [id] } = await pool.query(
    `SELECT username, display_name FROM identities WHERE sub = $1 AND deleted_at IS NULL`,
    [sub],
  );
  if (!id) return res.status(404).json({ error: 'not_found' });
  if ((await passkeyCount(sub)) >= MAX_PASSKEYS) {
    return res.status(422).json({ error: 'limit_reached', limit: MAX_PASSKEYS });
  }
  const r = await webauthn.startRegistration(sub, id.username, id.display_name || id.username);
  if ('error' in r) return res.status(422).json(r);
  res.json(r);
});

securityRouter.post('/account/mfa/passkey/register', scoped, requirePerm('profile.security.mfa.passkey.add'), requireSecurityStepup(FACTOR_STEPUP_MAX_S), async (req: AuthedRequest, res) => {
  const { credential, label } = (req.body ?? {}) as { credential?: unknown; label?: unknown };
  if (!credential || typeof credential !== 'object') {
    return res.status(422).json({ error: 'credential_required' });
  }
  if ((await passkeyCount(req.auth!.sub)) >= MAX_PASSKEYS) {
    return res.status(422).json({ error: 'limit_reached', limit: MAX_PASSKEYS });
  }
  const r = await webauthn.finishRegistration(
    req.auth!.sub,
    credential as Parameters<typeof webauthn.finishRegistration>[1],
    typeof label === 'string' ? label : null,
  );
  if (!r.ok) return res.status(422).json({ error: r.reason ?? 'register_failed' });
  res.status(204).end(); // created; the client reloads the list
});

securityRouter.patch('/account/mfa/passkey/:id', scoped, requirePerm('profile.security.mfa.passkey.rename'), async (req: AuthedRequest, res) => {
  const label = trimLabel(req.body?.label);
  if (!label) return res.status(422).json({ error: 'invalid_label' });
  const ok = await webauthn.renamePasskey(req.auth!.sub, req.params.id, label);
  if (!ok) return res.status(404).json({ error: 'not_found' });
  res.status(204).end();
});

securityRouter.delete('/account/mfa/passkey/:id', scoped, requirePerm('profile.security.mfa.passkey.remove'), requireSecurityStepup(FACTOR_STEPUP_MAX_S), async (req: AuthedRequest, res) => {
  if (await blocksLastFactor(req.auth!.sub)) return permissionDenied(res, 'profile.security.mfa.disable', 'last_strong_factor');
  const ok = await webauthn.removePasskey(req.auth!.sub, req.params.id);
  if (!ok) return res.status(404).json({ error: 'not_found' });
  res.status(204).end();
});
