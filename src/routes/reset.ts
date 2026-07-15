import { Router, type Request, type Response } from 'express';
import crypto from 'node:crypto';
import argon2 from 'argon2';
import { jwtVerify } from 'jose';
import { pool } from '../db.js';
import { config } from '../config.js';
import { getSetting, hasSetting, getSecretSetting } from '../settings.js';
import { findByUsernameOrEmail, type Identity } from '../oidc/identities.js';
import { createSession } from '../oidc/sessions.js';
import { createTxn } from '../oidc/transactions.js';
import { fanOutLogout } from '../oidc/backchannel.js';
import { countAuthenticators, verifyLoginTotp } from '../mfa.js';
import { countPasskeys, loginAuthOptions, verifyLoginAssertion } from '../webauthn.js';
import { sendEmail } from '../email.js';
import { renderPasswordResetEmail, renderPasswordChangedEmail } from '../emailTemplates.js';
import { renderErrorPage } from '../views.js';
import { passwordComplexityOk } from './security.js';
import { clientKeySet } from './token.js';
import {
  issueResetToken, getResetToken, bumpResetAttempts, consumeResetToken,
  reserveResetSend, releaseResetSend,
  storeResetPasskeyChallenge, takeResetPasskeyChallenge,
  mintLoginTicket, redeemLoginTicket,
  resetTokenValidityMinutes,
} from '../passwordReset.js';

// Password reset — the SSO owns the whole ceremony (lookup, rate limit, token,
// email, strong-factor challenge, password write, revocation, post-reset login
// ticket); the account portal's BFF fronts it (Turnstile gate + input
// validation) and proxies here over /internal/reset/*.
//
// Internal-endpoint auth: the SAME private_key_jwt client assertion the BFF
// already presents at /token, restricted to the account portal's client_id.
// The endpoints are otherwise capability-keyed (reset token), but /request
// takes a bare identifier and triggers email — without client auth it would
// be a public, Turnstile-free spray target.
export const resetRouter = Router();

const siteName = async () => (await getSetting('site_name', 'DreamSSO'))!;
const portalUrl = async () => (await getSetting('account_portal_url', config.accountPortalUrl))!;
const qstr = (v: unknown): string => (typeof v === 'string' ? v : '');

export async function isPortalAssertion(body: Record<string, unknown>): Promise<boolean> {
  if (
    body.client_assertion_type !== 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer' ||
    typeof body.client_assertion !== 'string'
  ) {
    return false;
  }
  const { rows } = await pool.query(
    'SELECT client_id, jwks, jwks_uri, disabled_at FROM oauth_clients WHERE client_id = $1',
    [config.accountClientId],
  );
  const client = rows[0];
  if (!client || client.disabled_at) return false;
  const keySet = clientKeySet(client);
  if (!keySet) return false;
  try {
    await jwtVerify(body.client_assertion, keySet, {
      issuer: client.client_id,
      subject: client.client_id,
      audience: [config.issuer, `${config.issuer}/token`],
    });
    return true;
  } catch {
    return false;
  }
}

// Same identifier rules as the portal's form (defense in depth): a bare
// username is videosite's 3–20 of [A-Za-z0-9_-]; anything with an @ is an
// email (RFC 5321 length cap).
export function identifierOk(id: string): boolean {
  if (id.includes('@')) return id.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(id);
  return /^[A-Za-z0-9_-]{3,20}$/.test(id);
}

// The reset's step-up requirement, mirroring the login challenge's method rule:
// only when the account MFA toggle is on AND a strong factor exists. Email OTP
// is never offered — the link already proved control of the email.
async function challengeFor(identity: Identity): Promise<{ methods: string[]; label: string } | null> {
  if (!identity.mfa_enabled) return null;
  const [passkeys, totp] = await Promise.all([
    countPasskeys(identity.sub),
    countAuthenticators(identity.sub),
  ]);
  const methods: string[] = [];
  if (passkeys > 0) methods.push('passkey');
  if (totp > 0) methods.push('totp');
  return methods.length ? { methods, label: identity.display_name || identity.username } : null;
}

async function liveIdentity(sub: string): Promise<Identity | null> {
  const { rows } = await pool.query(
    `SELECT sub, username, display_name, email, status, password_hash, mfa_enabled
       FROM identities WHERE sub = $1 AND deleted_at IS NULL`,
    [sub],
  );
  const id = rows[0] as Identity | undefined;
  return id && id.status === 'active' ? id : null;
}

// POST /internal/settings/turnstile — the BFF's server-side gate config. This
// hands over the sealed Turnstile secret (origin siteverify path) plus the
// edge gate's PUBLIC signing JWK (x-gate-assertion verification); assertion-
// authed, never public. Turnstile is enabled exactly when both keys are set.
resetRouter.post('/internal/settings/turnstile', async (req: Request, res: Response) => {
  const body = (req.body ?? {}) as Record<string, unknown>;
  if (!(await isPortalAssertion(body))) return res.status(401).json({ error: 'invalid_client' });
  const [siteKey, secret, gateJwkRaw] = await Promise.all([
    getSetting('turnstile_site_key'),
    getSecretSetting('turnstile_secret_key'),
    getSetting('gate_signing_public_jwk'),
  ]);
  let gateJwk: Record<string, unknown> | null = null;
  if (gateJwkRaw) {
    try { gateJwk = JSON.parse(gateJwkRaw) as Record<string, unknown>; } catch { /* unset */ }
  }
  res.setHeader('Cache-Control', 'no-store');
  res.json({
    enabled: !!siteKey && !!secret,
    site_key: siteKey,
    secret_key: secret,
    gate_public_jwk: gateJwk,
  });
});

// POST /internal/reset/request {identifier} — 204 up front, work in the
// background: existence, rate limit, and delivery are indistinguishable to the
// caller. The only sync failure is "email sending isn't configured at all"
// (503) — constant for every caller, so surfacing it leaks nothing per-user,
// and without it a misconfigured mailer would silently 204 forever.
resetRouter.post('/internal/reset/request', async (req: Request, res: Response) => {
  const body = (req.body ?? {}) as Record<string, unknown>;
  if (!(await isPortalAssertion(body))) return res.status(401).json({ error: 'invalid_client' });

  const identifier = qstr(body.identifier).trim();
  if (!identifierOk(identifier)) return res.status(422).json({ error: 'invalid_identifier' });

  const [mailFrom, cfAccount, tokenSet] = await Promise.all([
    getSetting('mail_from'), getSetting('cf_account_id'), hasSetting('cf_api_token'),
  ]);
  if (!mailFrom || !cfAccount || !tokenSet) return res.status(503).json({ error: 'email_not_configured' });

  res.status(204).end();

  void (async () => {
    const identity = await findByUsernameOrEmail(identifier);
    if (!identity || identity.status !== 'active' || !identity.email) return;
    if (!(await reserveResetSend(identity.email))) return; // 3/24h per address — silent
    const token = await issueResetToken(identity.sub);
    const [site, portal] = await Promise.all([siteName(), portalUrl()]);
    const sent = await sendEmail({
      to: identity.email,
      ...renderPasswordResetEmail({
        siteName: site,
        username: identity.username,
        link: `${portal}/reset?token=${token}`,
        minutes: resetTokenValidityMinutes,
      }),
    });
    if (!sent.ok) {
      await releaseResetSend(identity.email); // give the slot back — nothing arrived
      console.warn(`password reset email failed for ${identity.username}: ${sent.reason}`);
    }
  })().catch((e) => console.warn('password reset request processing failed:', (e as Error).message));
});

// POST /internal/reset/validate {token} — is the link usable, and will confirm
// demand a strong-factor challenge?
resetRouter.post('/internal/reset/validate', async (req: Request, res: Response) => {
  const body = (req.body ?? {}) as Record<string, unknown>;
  if (!(await isPortalAssertion(body))) return res.status(401).json({ error: 'invalid_client' });

  const rec = await getResetToken(qstr(body.token));
  const identity = rec ? await liveIdentity(rec.sub) : null;
  if (!rec || !identity) return res.json({ valid: false });
  res.json({ valid: true, challenge: await challengeFor(identity) });
});

// POST /internal/reset/passkey-options {token} — assertion options for the
// reset's passkey step; the challenge lives in Redis keyed by the token.
resetRouter.post('/internal/reset/passkey-options', async (req: Request, res: Response) => {
  const body = (req.body ?? {}) as Record<string, unknown>;
  if (!(await isPortalAssertion(body))) return res.status(401).json({ error: 'invalid_client' });

  const rec = await getResetToken(qstr(body.token));
  const identity = rec ? await liveIdentity(rec.sub) : null;
  if (!rec || !identity) return res.status(422).json({ error: 'invalid_token' });
  const ch = await challengeFor(identity);
  if (!ch || !ch.methods.includes('passkey')) return res.status(400).json({ error: 'method_unavailable' });

  const options = await loginAuthOptions(identity.sub);
  await storeResetPasskeyChallenge(rec.hash, options.challenge);
  res.json(options);
});

// POST /internal/reset/confirm {token, password, method?, code?, credential?}
// Verifies the challenge when one is required, writes the password, consumes
// the token, revokes every existing session (scoped back-channel fan-out),
// notifies by email, and mints the one-time login ticket for the SSO hop.
resetRouter.post('/internal/reset/confirm', async (req: Request, res: Response) => {
  const body = (req.body ?? {}) as Record<string, unknown>;
  if (!(await isPortalAssertion(body))) return res.status(401).json({ error: 'invalid_client' });

  const rec = await getResetToken(qstr(body.token));
  const identity = rec ? await liveIdentity(rec.sub) : null;
  if (!rec || !identity) return res.status(422).json({ error: 'invalid_token' });

  const password = body.password;
  if (typeof password !== 'string' || /\s/.test(password) || !passwordComplexityOk(password)) {
    return res.status(422).json({
      error: 'weak_password',
      error_description: 'At least 8 characters, no spaces, and 3 of: uppercase, lowercase, digits, special characters.',
    });
  }

  const ch = await challengeFor(identity);
  let challengeAmr: string | null = null;
  if (ch) {
    const method = qstr(body.method);
    const failed = async (error: string) => {
      const left = await bumpResetAttempts(rec);
      if (left === 0) return res.status(403).json({ error: 'too_many_attempts' });
      return res.status(401).json({ error, attempts_left: left });
    };
    if (method === 'totp' && ch.methods.includes('totp')) {
      const code = qstr(body.code).trim();
      if (!/^\d{6}$/.test(code) || !(await verifyLoginTotp(identity.sub, code))) {
        return failed('challenge_failed');
      }
      challengeAmr = 'otp';
    } else if (method === 'passkey' && ch.methods.includes('passkey')) {
      const expected = await takeResetPasskeyChallenge(rec.hash);
      if (!expected) return res.status(401).json({ error: 'challenge_expired' });
      let credential;
      try {
        credential = JSON.parse(qstr(body.credential));
      } catch {
        return failed('challenge_failed');
      }
      const v = await verifyLoginAssertion(credential, expected, identity.sub);
      if (!v.ok) return failed('challenge_failed');
      challengeAmr = 'passkey';
    } else {
      return res.status(401).json({ error: 'challenge_required', challenge: ch });
    }
  }

  const hash = await argon2.hash(password, { type: argon2.argon2id });
  await pool.query(
    `UPDATE identities SET password_hash = $2, password_changed_at = now() WHERE sub = $1`,
    [identity.sub, hash],
  );
  await consumeResetToken(rec);

  // Every pre-reset session dies — whoever held them no longer knows the
  // password. Scoped fan-out per session, same as the Devices pane.
  const { rows: revoked } = await pool.query<{ sid: string; clients: string[] | null }>(
    `DELETE FROM sessions WHERE user_sub = $1 RETURNING sid, clients`,
    [identity.sub],
  );
  await Promise.allSettled(revoked.map((r) => fanOutLogout(identity.sub, r.sid, r.clients ?? [])));

  // Best-effort notification — never blocks the reset.
  void (async () => {
    if (!identity.email) return;
    const [site, portal] = await Promise.all([siteName(), portalUrl()]);
    await sendEmail({
      to: identity.email,
      ...renderPasswordChangedEmail({ siteName: site, username: identity.username, portalUrl: portal }),
    });
  })().catch((e) => console.warn('password changed notification failed:', (e as Error).message));

  // amr reflects what the ceremony actually proved: the emailed link (email)
  // plus the strong factor when one was demanded — which also pre-clears the
  // step-up window via isStrongAmr, exactly like a strong-factor login.
  const amr = challengeAmr ? ['email', challengeAmr] : ['email'];
  const acr = challengeAmr ? 'urn:dreamsso:2fa' : 'urn:dreamsso:1fa';
  const ticket = await mintLoginTicket({
    sub: identity.sub, amr, acr,
    userLabel: identity.display_name || identity.username,
  });
  res.json({ complete_url: `${config.issuer}/reset/complete?ticket=${ticket}` });
});

// GET /reset/complete?ticket= — the browser hop that turns a finished reset
// into a signed-in user. On the SSO's own origin: redeem the one-time ticket,
// open the master session (transient — KMSI decides), then run the standard
// KMSI page via a local txn whose next stop is the portal's OIDC login start
// (silent code flow against the brand-new session).
resetRouter.get('/reset/complete', async (req: Request, res: Response) => {
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
      message: 'This sign-in link has expired or was already used. Your password was still changed — just sign in normally.',
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
    // No OIDC client — a local txn. redirectUri feeds the KMSI page's CSP
    // form-action (the post-answer redirect goes to the portal origin).
    clientId: '', redirectUri: next, codeChallenge: '', codeChallengeMethod: '', scope: '',
    clientName: site, localNext: next,
    kmsi: {
      sid, sub: ticket.sub, userLabel: ticket.userLabel,
      amr: ticket.amr, acr: ticket.acr, authTime: Math.floor(Date.now() / 1000),
    },
  });
  res.redirect(`/login?txn=${encodeURIComponent(txnId)}`);
});
