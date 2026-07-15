import { Router, type Request, type Response } from 'express';
import { getSession } from '../session.js';
import { SESSION_COOKIE } from './auth.js';
import { enforceTurnstileGate, s2sPost, mirror } from './reset.js';

// Public (no session) registration API for /register/start + /register/complete.
// The BFF is the Turnstile gate; the SSO owns everything real (codes, pending
// links, rate limits, identity creation, login ticket). Check order is the
// user's rule — Turnstile FIRST, then invitation code, then email — so the
// identities table is never consulted without a human + a valid code. Unlike
// the reset flow, responses are STATEFUL: the visitor holds a code and must
// know whether the email actually went out.
export const registerRouter = Router();

const qstr = (v: unknown): string => (typeof v === 'string' ? v : '');
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const CODE_RE = /^[A-Z0-9]{12}$/;
const USERNAME_RE = /^[A-Za-z0-9_-]{3,20}$/;

// POST /api/register/start {email, code?, turnstile_token?}
registerRouter.post('/api/register/start', async (req: Request, res: Response) => {
  try {
    if (await getSession(req.cookies?.[SESSION_COOKIE])) {
      return res.status(400).json({ error: 'already_authenticated' });
    }
    if (!(await enforceTurnstileGate(req, res))) return;

    const body = (req.body ?? {}) as Record<string, unknown>;
    const email = qstr(body.email).trim();
    const code = qstr(body.code).trim().toUpperCase().replace(/\s/g, '');
    // Shape only — required-ness and liveness are the SSO's call (it knows the
    // require_invitation_code toggle and checks the code BEFORE the email).
    if (code && !CODE_RE.test(code)) return res.status(422).json({ errors: { code: 'invalid_code' } });
    if (!EMAIL_RE.test(email) || email.length > 254) {
      return res.status(422).json({ errors: { email: 'invalid_email' } });
    }

    await mirror(res, await s2sPost('/internal/register/start', { email, code: code || undefined }));
  } catch (e) {
    console.error('register start proxy failed:', (e as Error).message);
    res.status(502).json({ error: 'upstream_unreachable' });
  }
});

// POST /api/register/validate {email, token} — is the emailed link usable?
registerRouter.post('/api/register/validate', async (req: Request, res: Response) => {
  try {
    const body = (req.body ?? {}) as Record<string, unknown>;
    await mirror(res, await s2sPost('/internal/register/validate', {
      email: qstr(body.email).trim(), token: qstr(body.token),
    }));
  } catch (e) {
    console.error('register validate proxy failed:', (e as Error).message);
    res.status(502).json({ error: 'upstream_unreachable' });
  }
});

// POST /api/register/check-username {email, token, username} — on-blur
// availability (token-gated upstream; not a public oracle).
registerRouter.post('/api/register/check-username', async (req: Request, res: Response) => {
  try {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const username = qstr(body.username).trim();
    if (!USERNAME_RE.test(username)) return res.status(422).json({ errors: { username: 'invalid_username' } });
    await mirror(res, await s2sPost('/internal/register/check-username', {
      email: qstr(body.email).trim(), token: qstr(body.token), username,
    }));
  } catch (e) {
    console.error('register check proxy failed:', (e as Error).message);
    res.status(502).json({ error: 'upstream_unreachable' });
  }
});

// POST /api/register/complete {email, token, username, display_name, password,
// confirm_password, turnstile_token?} — fresh Turnstile, then forward; the SSO
// answers {complete_url} for the /welcome sign-in hop.
registerRouter.post('/api/register/complete', async (req: Request, res: Response) => {
  try {
    if (await getSession(req.cookies?.[SESSION_COOKIE])) {
      return res.status(400).json({ error: 'already_authenticated' });
    }
    if (!(await enforceTurnstileGate(req, res))) return;

    const body = (req.body ?? {}) as Record<string, unknown>;
    const password = qstr(body.password);
    if (password !== qstr(body.confirm_password)) {
      return res.status(422).json({ errors: { confirm: 'mismatch' } });
    }
    await mirror(res, await s2sPost('/internal/register/complete', {
      email: qstr(body.email).trim(),
      token: qstr(body.token),
      username: qstr(body.username).trim(),
      display_name: qstr(body.display_name).trim(),
      password,
    }));
  } catch (e) {
    console.error('register complete proxy failed:', (e as Error).message);
    res.status(502).json({ error: 'upstream_unreachable' });
  }
});
