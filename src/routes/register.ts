import { Router, type Request, type Response } from 'express';
import crypto from 'node:crypto';
import argon2 from 'argon2';
import { uuidv7 } from 'uuidv7';
import { pool } from '../db.js';
import { config } from '../config.js';
import { getSetting, hasSetting } from '../settings.js';
import { createSession } from '../oidc/sessions.js';
import { createTxn } from '../oidc/transactions.js';
import { sendEmail } from '../email.js';
import { renderRegistrationEmail } from '../emailTemplates.js';
import { renderErrorPage } from '../views.js';
import { passwordComplexityOk } from './security.js';
import { isPortalAssertion } from './reset.js';
import { mintLoginTicket, redeemLoginTicket } from '../passwordReset.js';
import { audit } from '../audit.js';
import {
  getPending, issuePending, validatePending, dropPending,
  reserveRegistrationSend, releaseRegistrationSend,
  getLiveInvite, claimInviteUse, consumeInvite,
  registrationLinkValidityMinutes, CODE_RE,
} from '../registration.js';
import { changePendingForAddress } from '../emailChange.js';

// Self-serve registration — the SSO owns the ceremony (invitation codes,
// pending links, rate limits, identity creation, post-signup login ticket);
// the portal BFF fronts it (Turnstile/edge gate + input validation) over
// /internal/register/*, portal-client-assertion authed like /internal/reset/*.
//
// Check order (user rule): Turnstile at the BFF -> invitation code -> email.
// The identities table is never consulted without a valid code, so codes are
// the enumeration boundary. Unlike the reset flow, responses are STATEFUL —
// a code-holder is semi-trusted, and the user must know the email went out.
export const registerRouter = Router();

const siteName = async () => (await getSetting('site_name', 'DreamSSO'))!;
const portalUrl = async () => (await getSetting('account_portal_url', config.accountPortalUrl))!;
const qstr = (v: unknown): string => (typeof v === 'string' ? v : '');

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const USERNAME_RE = /^[A-Za-z0-9_-]{3,20}$/;

const registrationEnabled = async () => (await getSetting('enable_registration', 'false')) === 'true';
const invitationRequired = async () => (await getSetting('require_invitation_code', 'true')) === 'true';

// POST /internal/register/start {email, code?}
registerRouter.post('/internal/register/start', async (req: Request, res: Response) => {
  const body = (req.body ?? {}) as Record<string, unknown>;
  if (!(await isPortalAssertion(body))) return res.status(401).json({ error: 'invalid_client' });
  if (!(await registrationEnabled())) return res.status(403).json({ error: 'registration_closed' });

  const email = qstr(body.email).trim();
  const code = qstr(body.code).trim().toUpperCase();
  const needCode = await invitationRequired();

  // 1. invitation code BEFORE anything touches identities (enumeration boundary)
  let invite = null;
  if (needCode || code) {
    if (!CODE_RE.test(code)) return res.status(422).json({ errors: { code: 'invalid_code' } });
    invite = await getLiveInvite(code);
    if (!invite) return res.status(422).json({ errors: { code: 'invalid_code' } });
  }

  // 2. email shape, then uniqueness (citext -> case-insensitive)
  if (!EMAIL_RE.test(email) || email.length > 254) {
    return res.status(422).json({ errors: { email: 'invalid_email' } });
  }
  const { rows: [taken] } = await pool.query(
    'SELECT 1 FROM identities WHERE email = $1 AND deleted_at IS NULL', [email],
  );
  // A pending email CHANGE reserves its target address too (a registration's
  // OWN pending must not block its resends, so only the change family here).
  if (taken || (await changePendingForAddress(email))) {
    return res.status(422).json({ errors: { email: 'email_taken' } });
  }

  const [mailFrom, cfAccount, tokenSet] = await Promise.all([
    getSetting('mail_from'), getSetting('cf_account_id'), hasSetting('cf_api_token'),
  ]);
  if (!mailFrom || !cfAccount || !tokenSet) return res.status(503).json({ error: 'email_not_configured' });

  // 3. per-address send limiter (videosite policy: 5/24h, escalating backoff)
  const slot = await reserveRegistrationSend(email);
  if (!slot.ok) {
    return res.status(429).json({ error: 'rate_limited', retry_after: slot.retryAfter, can_retry: slot.canRetry });
  }

  // 4. claim the code use (same-email resend free; a switch counts; overuse voids)
  if (invite) {
    const use = await claimInviteUse(invite, email);
    if (use === 'voided') {
      await releaseRegistrationSend(email);
      return res.status(422).json({ errors: { code: 'invalid_code' } });
    }
  }

  const { token } = await issuePending(email, invite ? invite.code : null);
  const [site, portal] = await Promise.all([siteName(), portalUrl()]);
  const sent = await sendEmail({
    to: email,
    ...renderRegistrationEmail({
      siteName: site,
      link: `${portal}/register/complete?email=${encodeURIComponent(email)}&token=${token}`,
      minutes: registrationLinkValidityMinutes,
    }),
  });
  if (!sent.ok) {
    await releaseRegistrationSend(email); // nothing arrived — give the slot back
    return res.status(503).json({ error: 'send_failed' });
  }
  res.json({ sent: true, resend_backoff: slot.nextBackoff });
});

// POST /internal/register/validate {email, token} — is the emailed link usable?
registerRouter.post('/internal/register/validate', async (req: Request, res: Response) => {
  const body = (req.body ?? {}) as Record<string, unknown>;
  if (!(await isPortalAssertion(body))) return res.status(401).json({ error: 'invalid_client' });
  if (!(await registrationEnabled())) return res.status(403).json({ error: 'registration_closed' });
  const email = qstr(body.email).trim();
  const pending = await validatePending(email, qstr(body.token));
  if (!pending) return res.status(422).json({ error: 'invalid_token' });
  // The code must still be alive: an admin void (or overuse) kills the flow.
  if (pending.code && !(await getLiveInvite(pending.code))) {
    return res.status(422).json({ error: 'invalid_token' });
  }
  res.json({ valid: true });
});

// POST /internal/register/check-username {email, token, username} — on-blur
// availability for the complete form. Token-gated: not a public oracle.
registerRouter.post('/internal/register/check-username', async (req: Request, res: Response) => {
  const body = (req.body ?? {}) as Record<string, unknown>;
  if (!(await isPortalAssertion(body))) return res.status(401).json({ error: 'invalid_client' });
  const email = qstr(body.email).trim();
  if (!(await validatePending(email, qstr(body.token)))) return res.status(422).json({ error: 'invalid_token' });
  const username = qstr(body.username).trim();
  if (!USERNAME_RE.test(username)) return res.status(422).json({ errors: { username: 'invalid_username' } });
  const { rows: [hit] } = await pool.query(
    'SELECT 1 FROM identities WHERE username = $1 AND deleted_at IS NULL', [username],
  );
  res.json({ available: !hit });
});

// POST /internal/register/complete {email, token, username, display_name, password}
registerRouter.post('/internal/register/complete', async (req: Request, res: Response) => {
  const body = (req.body ?? {}) as Record<string, unknown>;
  if (!(await isPortalAssertion(body))) return res.status(401).json({ error: 'invalid_client' });
  if (!(await registrationEnabled())) return res.status(403).json({ error: 'registration_closed' });

  const email = qstr(body.email).trim();
  const pending = await validatePending(email, qstr(body.token));
  if (!pending) return res.status(422).json({ error: 'invalid_token' });

  const username = qstr(body.username).trim();
  const displayName = qstr(body.display_name).trim();
  const password = qstr(body.password);

  // Aggregate field errors (videosite behavior) so one round trip reports all.
  const errors: Record<string, string> = {};
  if (!USERNAME_RE.test(username)) errors.username = 'invalid_username';
  if (!displayName || displayName.length > 100) errors.display_name = 'invalid_display_name';
  if (/\s/.test(password) || !passwordComplexityOk(password)) errors.password = 'weak_password';
  if (Object.keys(errors).length) return res.status(422).json({ errors });

  // Uniqueness (both fields, case-insensitive via citext) — both reported.
  const { rows: dups } = await pool.query<{ u: boolean; e: boolean }>(
    `SELECT username = $1 AS u, email = $2 AS e FROM identities
      WHERE deleted_at IS NULL AND (username = $1 OR email = $2)`,
    [username, email],
  );
  for (const d of dups) {
    if (d.u) errors.username = 'username_taken';
    if (d.e) errors.email = 'email_taken';
  }
  if (Object.keys(errors).length) return res.status(422).json({ errors });

  // Org role: the invite's choice (validated at creation), else the org default.
  let roleSlug: string | null = null;
  if (pending.code) {
    const invite = await getLiveInvite(pending.code);
    if (!invite) return res.status(409).json({ error: 'invitation_gone' });
    roleSlug = invite.invited_role_slug;
  }
  if (!roleSlug) roleSlug = (await getSetting('default_org_role', 'standard_user'))!;

  const sub = uuidv7();
  const hash = await argon2.hash(password, { type: argon2.argon2id });
  const c = await pool.connect();
  try {
    await c.query('BEGIN');
    // email_verified: the emailed link proved ownership of the address.
    await c.query(
      `INSERT INTO identities (sub, username, display_name, email, email_verified, password_hash, password_changed_at)
       VALUES ($1, $2, $3, $4, true, $5, now())`,
      [sub, username, displayName, email, hash],
    );
    await c.query('INSERT INTO user_org_roles (user_sub, org_role_slug) VALUES ($1, $2)', [sub, roleSlug]);
    await c.query('COMMIT');
  } catch (e) {
    await c.query('ROLLBACK');
    // TOCTOU: a concurrent duplicate slipped past the SELECT — map, don't 500.
    if ((e as { code?: string }).code === '23505') {
      return res.status(422).json({ errors: { username: 'username_taken' } });
    }
    throw e;
  } finally {
    c.release();
  }

  if (pending.code && !(await consumeInvite(pending.code, sub))) {
    // Voided between validate and now: the account exists but the invitation is
    // gone — keep the account (it passed every gate while the code was live).
    console.warn(`registration: invite ${pending.code} vanished at consume for ${username}`);
  }
  await dropPending(email);
  audit({
    actorSub: sub, actorLabel: `${displayName} (${username})`,
    action: 'user.register', detail: { invite: pending.code ?? undefined, role: roleSlug },
  });

  const ticket = await mintLoginTicket({
    sub, amr: ['email'], acr: 'urn:dreamsso:1fa', userLabel: displayName || username,
  });
  res.json({ complete_url: `${config.issuer}/welcome?ticket=${ticket}` });
});

// GET /welcome?ticket= — the browser hop that turns a finished registration
// into a signed-in user; the same machinery as /reset/complete with
// registration-appropriate copy on a dead ticket.
registerRouter.get('/welcome', async (req: Request, res: Response) => {
  const ticket = await redeemLoginTicket(qstr(req.query.ticket));
  const site = await siteName();
  const portal = await portalUrl();
  if (!ticket) {
    const nonce = crypto.randomBytes(16).toString('base64');
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader(
      'Content-Security-Policy',
      `default-src 'none'; style-src 'nonce-${nonce}'; base-uri 'none'; frame-ancestors 'none'`,
    );
    return res.status(400).send(renderErrorPage(nonce, {
      title: 'Link expired',
      message: 'This sign-in link has expired or was already used. Your account was still created — just sign in normally.',
      code: 'ticket_expired',
      siteName: site,
      action: { href: portal, label: 'Open the account portal' },
    }));
  }
  const { sid } = await createSession(res, {
    userSub: ticket.sub,
    amr: ticket.amr,
    acr: ticket.acr,
    ip: req.ip,
    userAgent: qstr(req.headers['user-agent']),
    country: qstr(req.headers['cf-ipcountry']).trim() || undefined,
  });
  const next = `${portal}/auth/login`;
  const txnId = await createTxn({
    clientId: '', redirectUri: next, codeChallenge: '', codeChallengeMethod: '', scope: '',
    clientName: site, localNext: next,
    kmsi: {
      sid, sub: ticket.sub, userLabel: ticket.userLabel,
      amr: ticket.amr, acr: ticket.acr, authTime: Math.floor(Date.now() / 1000),
    },
  });
  res.redirect(`/login?txn=${encodeURIComponent(txnId)}`);
});
