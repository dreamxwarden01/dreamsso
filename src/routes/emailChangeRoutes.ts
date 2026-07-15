import { Router, type Response } from 'express';
import { pool } from '../db.js';
import { config } from '../config.js';
import { getSetting, hasSetting } from '../settings.js';
import { requireScope, type AuthedRequest } from '../resourceAuth.js';
import { hasPerm, permissionDenied } from '../rbac/index.js';
import { isStepupFresh } from '../oidc/sessions.js';
import { acceptedStepupMethods, stepupSatisfies } from '../oidc/stepupPolicy.js';
import { maskEmail } from '../emailOtp.js';
import { sendEmail } from '../email.js';
import { renderEmailVerifyEmail, renderEmailChangedEmail } from '../emailTemplates.js';
import { reserveRegistrationSend, releaseRegistrationSend, pendingEmailExists } from '../registration.js';
import {
  getEmailChange, issueEmailChange, redeemEmailChange, cancelEmailChange,
  changePendingOwner, emailChangeValidityMinutes,
} from '../emailChange.js';
import { isPortalAssertion } from './reset.js';
import { audit, actorLabel } from '../audit.js';

// Email verification (change + confirm-current) — VERIFY-THEN-COMMIT: the
// account's email swaps only when the emailed link is clicked; until then the
// old address stays live for OTP/recovery. Starting a CHANGE is gated by the
// user's strongest tier (user rule): fresh step-up when a passkey/TOTP
// exists -> an OTP to the CURRENT address -> the current password when there
// is no email at all (the add case). The public verify hop rides the BFF over
// /internal/* with the portal client assertion, like reset/registration.
export const emailChangeRouter = Router();
const scoped = requireScope('profile');

const qstr = (v: unknown): string => (typeof v === 'string' ? v : '');
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const siteName = async () => (await getSetting('site_name', 'DreamSSO'))!;
const portalUrl = async () => (await getSetting('account_portal_url', config.accountPortalUrl))!;

interface IdentityRow {
  sub: string; username: string; display_name: string;
  email: string | null; email_verified: boolean; password_hash: string | null;
}
async function loadIdentity(sub: string): Promise<IdentityRow | null> {
  const { rows: [r] } = await pool.query(
    `SELECT sub, username, display_name, email, email_verified, password_hash
       FROM identities WHERE sub = $1 AND deleted_at IS NULL AND status = 'active'`,
    [sub],
  );
  return (r as IdentityRow) ?? null;
}

// Sensitive self-service changes (email + username) require a fresh FALLBACK-tier
// step-up window: the tiered challenge (passkey/totp if owned, else an OTP to the
// current email, else the password) is proven through /account/stepup/*, which
// stamps the master session — so this just checks the stamp (method ∈ accepted +
// freshness) like the personal-security gates, instead of a bespoke inline proof.
// Sends 403 step_up_required itself and returns false on failure. 10-min cap, same
// as factor management.
const STEPUP_MAX_S = 600;
async function requireFreshStepup(id: IdentityRow, req: AuthedRequest, res: Response): Promise<boolean> {
  const sid = qstr(req.headers['x-stepup-sid']);
  if (sid) {
    const { rows: [s] } = await pool.query<{ user_sub: string; stepup_at: string | null; stepup_method: string | null }>(
      'SELECT user_sub, EXTRACT(EPOCH FROM stepup_at)::text AS stepup_at, stepup_method FROM sessions WHERE sid = $1',
      [sid],
    );
    if (s && s.user_sub === id.sub) {
      const at = s.stepup_at ? Number(s.stepup_at) : null;
      const withinCap = at != null && Date.now() / 1000 - at < STEPUP_MAX_S;
      const { accepted } = await acceptedStepupMethods(id.sub, 'email-change');
      if (withinCap && stepupSatisfies(accepted, s.stepup_method, await isStepupFresh(at))) return true;
    }
  }
  res.status(403).json({ error: 'step_up_required' });
  return false;
}

// GET /account/email-change — the LIVE address + pending state + which gate
// applies. The portal renders email from here, not from its session claims —
// a verified swap lands SSO-side without touching the BFF session.
emailChangeRouter.get('/account/email-change', scoped, async (req: AuthedRequest, res: Response) => {
  const id = await loadIdentity(req.auth!.sub);
  if (!id) return res.status(404).json({ error: 'not_found' });
  const pending = await getEmailChange(id.sub);
  res.json({
    email: id.email,
    email_verified: id.email_verified,
    username: id.username,
    pending: pending
      ? { kind: pending.kind, new_email: pending.newEmail, last_sent: pending.lastSent }
      : null,
  });
});

// POST /account/email-change/check {new_email} — availability probe run the
// moment the user submits the new value, BEFORE the identity challenge (user
// rule: fail fast, don't waste a challenge). The same checks re-run at start
// and again at verify — this is UX, not enforcement.
emailChangeRouter.post('/account/email-change/check', scoped, async (req: AuthedRequest, res: Response) => {
  const id = await loadIdentity(req.auth!.sub);
  if (!id) return res.status(404).json({ error: 'not_found' });
  const newEmail = qstr((req.body ?? {}).new_email).trim();
  if (!EMAIL_RE.test(newEmail) || newEmail.length > 254) {
    return res.status(422).json({ errors: { new_email: 'invalid_email' } });
  }
  if ((id.email ?? '').toLowerCase() === newEmail.toLowerCase()) {
    return res.status(422).json({ errors: { new_email: 'same_email' } });
  }
  const { rows: [taken] } = await pool.query(
    'SELECT 1 FROM identities WHERE email = $1 AND sub <> $2 AND deleted_at IS NULL',
    [newEmail, id.sub],
  );
  const owner = await changePendingOwner(newEmail);
  if (taken || (await pendingEmailExists(newEmail)) || (owner != null && owner !== id.sub)) {
    return res.status(409).json({ errors: { new_email: 'email_taken' } });
  }
  res.status(204).end();
});

// POST /account/username-change/check {new_username} — same early probe.
emailChangeRouter.post('/account/username-change/check', scoped, async (req: AuthedRequest, res: Response) => {
  const id = await loadIdentity(req.auth!.sub);
  if (!id) return res.status(404).json({ error: 'not_found' });
  if (!(await hasPerm(id.sub, 'profile.username.change'))) {
    return permissionDenied(res, 'profile.username.change');
  }
  const newUsername = qstr((req.body ?? {}).new_username).trim();
  if (!/^[A-Za-z0-9_-]{3,20}$/.test(newUsername)) {
    return res.status(422).json({ errors: { new_username: 'invalid_username' } });
  }
  if (id.username.toLowerCase() === newUsername.toLowerCase()) {
    return res.status(422).json({ errors: { new_username: 'same_username' } });
  }
  const { rows: [taken] } = await pool.query(
    'SELECT 1 FROM identities WHERE username = $1 AND sub <> $2 AND deleted_at IS NULL',
    [newUsername, id.sub],
  );
  if (taken) return res.status(409).json({ errors: { new_username: 'username_taken' } });
  res.status(204).end();
});

// POST /account/email-change/start {new_email}
// (+ x-stepup-sid injected by the BFF — the fresh fallback step-up is the proof)
emailChangeRouter.post('/account/email-change/start', scoped, async (req: AuthedRequest, res: Response) => {
  const id = await loadIdentity(req.auth!.sub);
  if (!id) return res.status(404).json({ error: 'not_found' });
  const permKey = id.email == null ? 'profile.email.add' : 'profile.email.change';
  if (!(await hasPerm(id.sub, permKey))) return permissionDenied(res, permKey);

  const body = (req.body ?? {}) as Record<string, unknown>;
  const newEmail = qstr(body.new_email).trim();
  if (!EMAIL_RE.test(newEmail) || newEmail.length > 254) {
    return res.status(422).json({ errors: { new_email: 'invalid_email' } });
  }
  if ((id.email ?? '').toLowerCase() === newEmail.toLowerCase()) {
    return res.status(422).json({ errors: { new_email: 'same_email' } });
  }

  // Uniqueness BEFORE the gate: the OTP proof is single-use, and a doomed
  // request (taken address) must not burn a valid code.
  // identities (citext) + registration pendings + OTHER users' pending
  // changes (re-submitting your own pending address is a re-issue).
  const { rows: [taken] } = await pool.query(
    'SELECT 1 FROM identities WHERE email = $1 AND sub <> $2 AND deleted_at IS NULL',
    [newEmail, id.sub],
  );
  const owner = await changePendingOwner(newEmail);
  if (taken || (await pendingEmailExists(newEmail)) || (owner != null && owner !== id.sub)) {
    return res.status(409).json({ errors: { new_email: 'email_taken' } });
  }

  // Fresh fallback-tier step-up — ALWAYS enforced (no settings toggle).
  const gated = await requireFreshStepup(id, req, res);
  if (!gated) return;

  const [mailFrom, cfAccount, tokenSet] = await Promise.all([
    getSetting('mail_from'), getSetting('cf_account_id'), hasSetting('cf_api_token'),
  ]);
  if (!mailFrom || !cfAccount || !tokenSet) return res.status(503).json({ error: 'email_not_configured' });

  // Shared per-address limiter with registration — one inbox, one budget.
  const slot = await reserveRegistrationSend(newEmail);
  if (!slot.ok) {
    return res.status(429).json({ error: 'rate_limited', retry_after: slot.retryAfter, can_retry: slot.canRetry });
  }
  const { token } = await issueEmailChange(id.sub, 'change', newEmail);
  const [site, portal] = await Promise.all([siteName(), portalUrl()]);
  const sent = await sendEmail({
    to: newEmail,
    ...renderEmailVerifyEmail({
      siteName: site, kind: 'change',
      link: `${portal}/verify-email?token=${token}`,
      minutes: emailChangeValidityMinutes,
    }),
  });
  if (!sent.ok) {
    await releaseRegistrationSend(newEmail);
    return res.status(503).json({ error: 'send_failed' });
  }
  audit({
    actorSub: id.sub, actorLabel: await actorLabel(id.sub),
    action: 'email.change_request', detail: { to: maskEmail(newEmail) },
  });
  res.json({ sent: true, new_email: newEmail, resend_backoff: slot.nextBackoff });
});

// POST /account/email-change/resend — re-send the pending link (same token
// inside the 5-min window; the shared limiter still meters it).
emailChangeRouter.post('/account/email-change/resend', scoped, async (req: AuthedRequest, res: Response) => {
  const sub = req.auth!.sub;
  const pending = await getEmailChange(sub);
  if (!pending) return res.status(404).json({ error: 'no_pending' });
  const slot = await reserveRegistrationSend(pending.newEmail);
  if (!slot.ok) {
    return res.status(429).json({ error: 'rate_limited', retry_after: slot.retryAfter, can_retry: slot.canRetry });
  }
  const { token } = await issueEmailChange(sub, pending.kind, pending.newEmail);
  const [site, portal] = await Promise.all([siteName(), portalUrl()]);
  const sent = await sendEmail({
    to: pending.newEmail,
    ...renderEmailVerifyEmail({
      siteName: site, kind: pending.kind,
      link: `${portal}/verify-email?token=${token}`,
      minutes: emailChangeValidityMinutes,
    }),
  });
  if (!sent.ok) {
    await releaseRegistrationSend(pending.newEmail);
    return res.status(503).json({ error: 'send_failed' });
  }
  res.json({ sent: true, resend_backoff: slot.nextBackoff });
});

// DELETE /account/email-change — cancel the pending change (frees the address).
emailChangeRouter.delete('/account/email-change', scoped, async (req: AuthedRequest, res: Response) => {
  await cancelEmailChange(req.auth!.sub);
  res.status(204).end();
});

// POST /account/email/verify/send — confirm-CURRENT flow for a genuinely
// unverified existing address (legacy/migrated rows): same link machinery,
// no swap, no gate (proving the address you already own needs none).
emailChangeRouter.post('/account/email/verify/send', scoped, async (req: AuthedRequest, res: Response) => {
  const id = await loadIdentity(req.auth!.sub);
  if (!id || !id.email) return res.status(409).json({ error: 'no_email' });
  if (id.email_verified) return res.status(409).json({ error: 'already_verified' });
  const slot = await reserveRegistrationSend(id.email);
  if (!slot.ok) {
    return res.status(429).json({ error: 'rate_limited', retry_after: slot.retryAfter, can_retry: slot.canRetry });
  }
  const { token } = await issueEmailChange(id.sub, 'confirm', id.email);
  const [site, portal] = await Promise.all([siteName(), portalUrl()]);
  const sent = await sendEmail({
    to: id.email,
    ...renderEmailVerifyEmail({
      siteName: site, kind: 'confirm',
      link: `${portal}/verify-email?token=${token}`,
      minutes: emailChangeValidityMinutes,
    }),
  });
  if (!sent.ok) {
    await releaseRegistrationSend(id.email);
    return res.status(503).json({ error: 'send_failed' });
  }
  res.json({ sent: true, resend_backoff: slot.nextBackoff });
});

// POST /account/username-change {new_username, otp_code?, password?} — the
// SAME one-time verification as the email change (user rule), but committing
// immediately: usernames have no inbox to prove. Permission-gated by
// profile.username.change (superadmin-only by default).
emailChangeRouter.post('/account/username-change', scoped, async (req: AuthedRequest, res: Response) => {
  const id = await loadIdentity(req.auth!.sub);
  if (!id) return res.status(404).json({ error: 'not_found' });
  if (!(await hasPerm(id.sub, 'profile.username.change'))) {
    return permissionDenied(res, 'profile.username.change');
  }

  const body = (req.body ?? {}) as Record<string, unknown>;
  const newUsername = qstr(body.new_username).trim();
  if (!/^[A-Za-z0-9_-]{3,20}$/.test(newUsername)) {
    return res.status(422).json({ errors: { new_username: 'invalid_username' } });
  }
  if (id.username.toLowerCase() === newUsername.toLowerCase()) {
    return res.status(422).json({ errors: { new_username: 'same_username' } });
  }
  // Uniqueness BEFORE the gate (single-use OTP proof, same rule as email).
  const { rows: [taken] } = await pool.query(
    'SELECT 1 FROM identities WHERE username = $1 AND sub <> $2 AND deleted_at IS NULL',
    [newUsername, id.sub],
  );
  if (taken) return res.status(409).json({ errors: { new_username: 'username_taken' } });

  const gated = await requireFreshStepup(id, req, res);
  if (!gated) return;

  try {
    await pool.query('UPDATE identities SET username = $2 WHERE sub = $1', [id.sub, newUsername]);
  } catch (e) {
    if ((e as { code?: string }).code === '23505') {
      return res.status(409).json({ errors: { new_username: 'username_taken' } });
    }
    throw e;
  }
  audit({
    actorSub: id.sub, actorLabel: await actorLabel(id.sub),
    action: 'username.change', detail: { from: id.username, to: newUsername },
  });
  res.json({ username: newUsername });
});

// POST /internal/email-change/verify {token} — the public capability hop
// (clicker may be signed out; the token authorizes). Commits the swap (or the
// confirm), then notifies the OLD address — after everything, per the design.
emailChangeRouter.post('/internal/email-change/verify', async (req, res: Response) => {
  const body = (req.body ?? {}) as Record<string, unknown>;
  if (!(await isPortalAssertion(body))) return res.status(401).json({ error: 'invalid_client' });

  const rec = await redeemEmailChange(qstr(body.token));
  if (!rec) return res.status(422).json({ error: 'invalid_token' });
  const id = await loadIdentity(rec.sub);
  if (!id) return res.status(422).json({ error: 'invalid_token' });

  if (rec.kind === 'confirm') {
    // Only meaningful while the address is still the one the link was for.
    const { rowCount } = await pool.query(
      'UPDATE identities SET email_verified = true WHERE sub = $1 AND email = $2',
      [rec.sub, rec.newEmail],
    );
    if (!rowCount) return res.status(422).json({ error: 'invalid_token' });
    audit({ actorSub: rec.sub, actorLabel: await actorLabel(rec.sub), action: 'email.verify', detail: {} });
    return res.json({ ok: true, kind: 'confirm' });
  }

  // change: TOCTOU re-check — the address may have been taken since.
  const { rows: [taken] } = await pool.query(
    'SELECT 1 FROM identities WHERE email = $1 AND sub <> $2 AND deleted_at IS NULL',
    [rec.newEmail, rec.sub],
  );
  if (taken) return res.status(409).json({ error: 'email_taken' });

  const oldEmail = id.email;
  await pool.query(
    'UPDATE identities SET email = $2, email_verified = true WHERE sub = $1',
    [rec.sub, rec.newEmail],
  );
  audit({
    actorSub: rec.sub, actorLabel: await actorLabel(rec.sub),
    action: 'email.change', detail: { to: maskEmail(rec.newEmail) },
  });
  if (oldEmail) {
    // Fire-and-forget: the notice must never block the verify response.
    void (async () => {
      const [site, portal] = await Promise.all([siteName(), portalUrl()]);
      const sent = await sendEmail({
        to: oldEmail,
        ...renderEmailChangedEmail({
          siteName: site, username: id.username,
          newEmailMasked: maskEmail(rec.newEmail), portalUrl: portal,
        }),
      });
      if (!sent.ok) console.warn(`email-change notice to old address failed: ${sent.reason}`);
    })().catch((e) => console.warn('email-change notice failed:', (e as Error).message));
  }
  res.json({ ok: true, kind: 'change' });
});
