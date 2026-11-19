import { Router, type Request, type Response } from 'express';
import { getSession } from '../session.js';
import { SESSION_COOKIE } from './auth.js';
import { enforceTurnstileGate, s2sPost, mirror } from './reset.js';

// Public registration API for /register/start + /register/complete. The BFF
// gates mail sends and account creation with Turnstile; read-only invitation
// previews and mailbox-proof checks do not need another human challenge. The
// SSO owns binding, deadlines, delivery, quotas, identity creation and tickets.
// Mutations retain Turnstile -> invitation -> recipient-email validation order.
export const registerRouter = Router();

const qstr = (v: unknown): string => (typeof v === 'string' ? v : '');
const CODE_RE = /^[A-Z0-9]{12}$/;
const USERNAME_RE = /^[A-Za-z0-9_-]{3,20}$/;

// Read-only, code-keyed invitation preview. Opening a page never binds an
// address, sends mail or consumes the invitation; no Turnstile is needed.
registerRouter.post('/api/register/invitation', async (req: Request, res: Response) => {
  res.set('Cache-Control', 'no-store');
  try {
    const code = qstr((req.body ?? {}).code).trim().toUpperCase().replace(/\s/g, '');
    if (!CODE_RE.test(code)) return res.status(422).json({ error: 'invalid_invitation' });
    await mirror(res, await s2sPost('/internal/register/invitation', { code }));
  } catch (e) {
    console.error('register invitation proxy failed:', (e as Error).message);
    res.status(502).json({ error: 'upstream_unreachable' });
  }
});

// POST /api/register/start {email, code?, request_id?, turnstile_token?}
registerRouter.post('/api/register/start', async (req: Request, res: Response) => {
  try {
    // Turnstile FIRST — single-use token, consumed on every request incl. the
    // 400/422 paths, so the contract matches the edge worker and the client can
    // reset the widget after any error. Then session, then code/email.
    if (!(await enforceTurnstileGate(req, res))) return;

    if (await getSession(req.cookies?.[SESSION_COOKIE])) {
      return res.status(400).json({ error: 'already_authenticated' });
    }

    const body = (req.body ?? {}) as Record<string, unknown>;
    const email = qstr(body.email).trim();
    const code = qstr(body.code).trim().toUpperCase().replace(/\s/g, '');
    // The SSO owns the invitation toggle and validation order. Forward the
    // whitelisted values only after the human gate; do not reject an ignored
    // code or check email ahead of an enabled invitation's liveness check.
    await mirror(res, await s2sPost('/internal/register/start', {
      email, code: code || undefined, request_id: qstr(body.request_id) || undefined,
    }));
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
    // Turnstile FIRST — single-use token, consumed on every request (matches the
    // edge worker) so the client resets the widget after any error.
    if (!(await enforceTurnstileGate(req, res))) return;

    if (await getSession(req.cookies?.[SESSION_COOKIE])) {
      return res.status(400).json({ error: 'already_authenticated' });
    }

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
