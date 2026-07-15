// The thin JSON API the SPA talks to. Everything here runs against the
// server-side session; the browser never sees a token.
//   GET   /api/me       -> current identity + security summary
//   PATCH /api/profile  -> edit display_name / email (proxied to the SSO, Bearer access token)
import { Router, raw, type Request, type Response, type NextFunction } from 'express';
import { getSession, updateSession, type SessionData } from '../session.js';
import { config } from '../config.js';
import { s2sAssertion } from '../oidc.js';
import { s2sFetch } from '../s2sFetch.js';
import { SESSION_COOKIE } from './auth.js';

export const apiRouter = Router();

interface AuthedRequest extends Request {
  session?: SessionData;
  sid?: string;
}

// Public branding passthrough: the SSO owns site_name; the console consumes it via
// its own origin (no CORS). Cached 60s; serves the stale copy on an SSO hiccup.
let pubCache: { data: unknown; at: number } | null = null;
apiRouter.get('/api/settings/public', async (_req, res) => {
  if (pubCache && Date.now() - pubCache.at < 60_000) return res.json(pubCache.data);
  try {
    const r = await s2sFetch(config.internal + '/api/settings/public', {
      signal: AbortSignal.timeout(3000),
    });
    if (!r.ok) throw new Error('http_' + r.status);
    pubCache = { data: await r.json(), at: Date.now() };
    res.json(pubCache.data);
  } catch {
    res.json(pubCache?.data ?? { site_name: null });
  }
});

// Access tokens live 15 minutes; renew them in place against the SSO's
// session-bound /internal/token/renew (client assertion + the master-session
// sid) instead of 401-bouncing the SPA every expiry. Fails soft: a dead SSO
// session (logout, termination, window lapse) leaves the token expired and
// the downstream token_expired checks surface the 401 as before.
const RENEW_SKEW_S = 30;
async function renewAccessToken(s: SessionData): Promise<boolean> {
  if (!s.ssoSid) return false;
  try {
    const r = await s2sFetch(config.internal + '/internal/token/renew', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        client_assertion: await s2sAssertion(),
        sid: s.ssoSid,
        sub: s.sub,
      }),
      signal: AbortSignal.timeout(5000),
    });
    if (!r.ok) return false;
    const d = (await r.json().catch(() => null)) as { access_token?: string; expires_in?: number } | null;
    if (!d?.access_token) return false;
    s.accessToken = d.access_token;
    s.accessExpiresAt = Math.floor(Date.now() / 1000) + (typeof d.expires_in === 'number' ? d.expires_in : 900);
    return true;
  } catch {
    return false;
  }
}

// Attach the session or 401. The SPA treats 401 as "bounce to /auth/login".
async function requireSession(req: AuthedRequest, res: Response, next: NextFunction) {
  const sid = req.cookies[SESSION_COOKIE];
  const sess = await getSession(sid);
  if (!sess) return res.status(401).json({ error: 'unauthenticated' });
  if (sess.accessExpiresAt <= Math.floor(Date.now() / 1000) + RENEW_SKEW_S && (await renewAccessToken(sess))) {
    await updateSession(sid, sess);
  }
  req.session = sess;
  req.sid = sid;
  next();
}

function projectProfile(s: SessionData) {
  const c = s.claims;
  return {
    sub: s.sub,
    username: (c.preferred_username as string) ?? null,
    display_name: (c.name as string) ?? null,
    email: (c.email as string) ?? null,
    email_verified: Boolean(c.email_verified),
    picture: (c.picture as string) ?? null,
  };
}

// Best-effort fetch of the caller's granted permissions from the SSO. Returns null
// on any failure so /api/me can fall back to the cached set (never breaks on it).
async function fetchPermissions(accessToken: string): Promise<string[] | null> {
  try {
    const r = await s2sFetch(config.internal + '/account/permissions', {
      headers: { authorization: 'Bearer ' + accessToken },
    });
    if (!r.ok) return null;
    const d = (await r.json().catch(() => null)) as { permissions?: string[] } | null;
    return Array.isArray(d?.permissions) ? d!.permissions : null;
  } catch {
    return null;
  }
}

apiRouter.get('/api/me', requireSession, async (req: AuthedRequest, res) => {
  const s = req.session!;
  // Refresh permissions while the access token is alive (the client re-hits /api/me
  // on profile load and after a permission_denied). Stale token -> keep the cache.
  if (s.accessExpiresAt > Math.floor(Date.now() / 1000)) {
    const perms = await fetchPermissions(s.accessToken);
    if (perms) {
      s.permissions = perms;
      await updateSession(req.sid!, s);
    }
  }
  res.json({
    profile: projectProfile(s),
    security: { amr: s.amr, acr: s.acr ?? null, auth_time: s.authTime ?? null },
    permissions: s.permissions ?? [],
  });
});

// PATCH /api/profile — edit identity. The account console is the source of truth
// for display_name/email; the call is proxied to the SSO resource API with the
// session's access token. (username is immutable; never forwarded.)
apiRouter.patch('/api/profile', requireSession, async (req: AuthedRequest, res) => {
  const s = req.session!;
  if (s.accessExpiresAt <= Math.floor(Date.now() / 1000)) {
    // Access token expired (no refresh yet) — make the SPA re-authenticate.
    return res.status(401).json({ error: 'token_expired' });
  }

  const body = (req.body ?? {}) as { display_name?: unknown; email?: unknown };
  const patch: Record<string, string> = {};
  if (typeof body.display_name === 'string') patch.display_name = body.display_name.trim();
  if (typeof body.email === 'string') patch.email = body.email.trim();
  if (Object.keys(patch).length === 0) {
    return res.status(400).json({ error: 'no_fields', error_description: 'display_name and/or email required' });
  }

  let upstream: globalThis.Response;
  try {
    upstream = await s2sFetch(config.internal + '/account/profile', {
      method: 'PATCH',
      headers: { 'content-type': 'application/json', authorization: 'Bearer ' + s.accessToken },
      body: JSON.stringify(patch),
    });
  } catch (e) {
    console.error('profile proxy failed:', (e as Error).message);
    return res.status(502).json({ error: 'upstream_unreachable' });
  }

  const data = (await upstream.json().catch(() => ({}))) as Record<string, unknown>;
  if (!upstream.ok) return res.status(upstream.status).json(data);

  // Reflect the change into the cached session claims so /api/me stays current.
  const id = data.identity as { display_name?: string; email?: string; email_verified?: boolean } | undefined;
  if (id) {
    if (id.display_name !== undefined) s.claims.name = id.display_name;
    if (id.email !== undefined) s.claims.email = id.email;
    if (id.email_verified !== undefined) s.claims.email_verified = id.email_verified;
    await updateSession(req.sid!, s);
  }
  res.json({ profile: projectProfile(s) });
});

// --- Security pane: proxy /api/security/* to the SSO /account/* resource API,
//     authenticating with the session's access token. The SSO owns the state
//     (passwords, totp_credentials); the BFF just carries the bearer. ---
async function forward(
  req: AuthedRequest,
  res: Response,
  method: string,
  ssoPath: string,
  body?: unknown,
): Promise<void> {
  const s = req.session!;
  if (s.accessExpiresAt <= Math.floor(Date.now() / 1000)) {
    res.status(401).json({ error: 'token_expired' });
    return;
  }
  let upstream: globalThis.Response;
  try {
    upstream = await s2sFetch(config.internal + ssoPath, {
      method,
      headers: {
        authorization: 'Bearer ' + s.accessToken,
        ...(body !== undefined ? { 'content-type': 'application/json' } : {}),
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  } catch (e) {
    console.error('security proxy failed:', (e as Error).message);
    res.status(502).json({ error: 'upstream_unreachable' });
    return;
  }
  if (upstream.status === 204) {
    res.status(204).end();
    return;
  }
  const data = await upstream.json().catch(() => null);
  res.status(upstream.status).json(data);
}

// --- Org management: proxy /api/org/* to the SSO's /account/org/* resource
//     API. The caller's own master-session sid rides along in x-stepup-sid so
//     the SSO can re-check the sudo window server-side on mutations. ---
async function forwardOrg(req: AuthedRequest, res: Response, method: string, ssoPath: string, body?: unknown): Promise<void> {
  const s = req.session!;
  if (s.accessExpiresAt <= Math.floor(Date.now() / 1000)) {
    res.status(401).json({ error: 'token_expired' });
    return;
  }
  let upstream: globalThis.Response;
  try {
    upstream = await s2sFetch(config.internal + ssoPath, {
      method,
      headers: {
        authorization: 'Bearer ' + s.accessToken,
        'x-stepup-sid': s.ssoSid ?? '',
        ...(body !== undefined ? { 'content-type': 'application/json' } : {}),
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  } catch (e) {
    console.error('org proxy failed:', (e as Error).message);
    res.status(502).json({ error: 'upstream_unreachable' });
    return;
  }
  if (upstream.status === 204) {
    res.status(204).end();
    return;
  }
  res.status(upstream.status).json(await upstream.json().catch(() => null));
}
// Generic passthrough: every /api/org/* call maps 1:1 onto /account/org/*
// (path + query preserved), so new org endpoints need no BFF change.
apiRouter.use('/api/org', requireSession, (req: AuthedRequest, res) => {
  if (!['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) {
    res.status(405).json({ error: 'method_not_allowed' });
    return;
  }
  const hasBody = req.method !== 'GET' && req.method !== 'DELETE';
  return forwardOrg(req, res, req.method, '/account/org' + req.url, hasBody ? req.body ?? {} : undefined);
});

apiRouter.get('/api/security', requireSession, (req: AuthedRequest, res) =>
  forward(req, res, 'GET', '/account/security'),
);
// --- email verification (verify-then-commit): forwardOrg so the caller's
//     sid rides in x-stepup-sid — the stepup-tier gate re-checks it. ---
apiRouter.get('/api/email-change', requireSession, (req: AuthedRequest, res) =>
  forwardOrg(req, res, 'GET', '/account/email-change'),
);
apiRouter.post('/api/email-change/start', requireSession, (req: AuthedRequest, res) =>
  forwardOrg(req, res, 'POST', '/account/email-change/start', req.body ?? {}),
);
apiRouter.post('/api/email-change/resend', requireSession, (req: AuthedRequest, res) =>
  forwardOrg(req, res, 'POST', '/account/email-change/resend', {}),
);
apiRouter.delete('/api/email-change', requireSession, (req: AuthedRequest, res) =>
  forwardOrg(req, res, 'DELETE', '/account/email-change'),
);
apiRouter.post('/api/email/verify/send', requireSession, (req: AuthedRequest, res) =>
  forwardOrg(req, res, 'POST', '/account/email/verify/send', {}),
);
apiRouter.post('/api/username-change', requireSession, (req: AuthedRequest, res) =>
  forwardOrg(req, res, 'POST', '/account/username-change', req.body ?? {}),
);
apiRouter.post('/api/email-change/check', requireSession, (req: AuthedRequest, res) =>
  forwardOrg(req, res, 'POST', '/account/email-change/check', req.body ?? {}),
);
apiRouter.post('/api/username-change/check', requireSession, (req: AuthedRequest, res) =>
  forwardOrg(req, res, 'POST', '/account/username-change/check', req.body ?? {}),
);
// Change password rides forwardOrg so the caller's own sid travels along —
// the SSO keeps THAT session and signs out every other one.
// --- profile picture ---
// Upload: raw image bytes ride through to the SSO, which crops/re-encodes and
// returns the new FILE NAME; the cached session claim updates in place so
// /api/me is immediately fresh.
const AVATAR_RE = /^[0-9a-f-]{36}-[0-9a-f]{16}\.webp$/;
apiRouter.post(
  '/api/avatar',
  raw({ type: ['image/png', 'image/jpeg', 'image/webp'], limit: 8 * 1024 * 1024 }),
  requireSession,
  async (req: AuthedRequest, res: Response) => {
    const s = req.session!;
    if (s.accessExpiresAt <= Math.floor(Date.now() / 1000)) {
      return res.status(401).json({ error: 'token_expired' });
    }
    if (!Buffer.isBuffer(req.body) || req.body.length === 0) {
      return res.status(422).json({ error: 'unprocessable_image' });
    }
    let upstream: globalThis.Response;
    try {
      upstream = await s2sFetch(config.internal + '/account/avatar', {
        method: 'POST',
        headers: {
          authorization: 'Bearer ' + s.accessToken,
          'content-type': req.headers['content-type'] ?? 'application/octet-stream',
        },
        body: new Uint8Array(req.body),
      });
    } catch {
      return res.status(502).json({ error: 'upstream_unreachable' });
    }
    const data = (await upstream.json().catch(() => null)) as { avatar?: string } | null;
    if (upstream.ok && data?.avatar) {
      s.claims.picture = data.avatar;
      await updateSession(req.sid!, s);
    }
    res.status(upstream.status).json(data);
  },
);

apiRouter.delete('/api/avatar', requireSession, async (req: AuthedRequest, res: Response) => {
  const s = req.session!;
  if (s.accessExpiresAt <= Math.floor(Date.now() / 1000)) {
    return res.status(401).json({ error: 'token_expired' });
  }
  let upstream: globalThis.Response;
  try {
    upstream = await s2sFetch(config.internal + '/account/avatar', {
      method: 'DELETE',
      headers: { authorization: 'Bearer ' + s.accessToken },
    });
  } catch {
    return res.status(502).json({ error: 'upstream_unreachable' });
  }
  if (upstream.ok) {
    delete s.claims.picture;
    await updateSession(req.sid!, s);
  }
  if (upstream.status === 204) return res.status(204).end();
  res.status(upstream.status).json(await upstream.json().catch(() => null));
});

// Serve: session-gated, name-addressed. The file name changes with the content,
// so a year of private+immutable is exactly right; the portal reads straight
// from the SSO (same box) — no local cache layer needed.
apiRouter.get('/api/avatar/:file', requireSession, async (req: AuthedRequest, res: Response) => {
  const file = String(req.params.file);
  if (!AVATAR_RE.test(file)) return res.status(404).json({ error: 'not_found' });
  let upstream: globalThis.Response;
  try {
    upstream = await s2sFetch(config.internal + '/avatar/' + file);
  } catch {
    return res.status(502).json({ error: 'upstream_unreachable' });
  }
  if (!upstream.ok) return res.status(404).json({ error: 'not_found' });
  const buf = Buffer.from(await upstream.arrayBuffer());
  res.setHeader('Cache-Control', 'private, max-age=31536000, immutable');
  res.type('image/webp').send(buf);
});

apiRouter.post('/api/security/password', requireSession, (req: AuthedRequest, res) =>
  forwardOrg(req, res, 'POST', '/account/password', req.body ?? {}),
);
apiRouter.post('/api/security/mfa/enable', requireSession, (req: AuthedRequest, res) =>
  forwardOrg(req, res, 'POST', '/account/mfa/enable', {}),
);
apiRouter.post('/api/security/mfa/disable', requireSession, (req: AuthedRequest, res) =>
  forwardOrg(req, res, 'POST', '/account/mfa/disable', {}),
);
apiRouter.post('/api/security/authenticator/setup', requireSession, (req: AuthedRequest, res) =>
  forwardOrg(req, res, 'POST', '/account/mfa/authenticator/setup', req.body ?? {}),
);
apiRouter.post('/api/security/authenticator/confirm', requireSession, (req: AuthedRequest, res) =>
  forwardOrg(req, res, 'POST', '/account/mfa/authenticator/confirm', req.body ?? {}),
);
apiRouter.patch('/api/security/authenticator/:id', requireSession, (req: AuthedRequest, res) =>
  forward(req, res, 'PATCH', '/account/mfa/authenticator/' + encodeURIComponent(String(req.params.id)), req.body ?? {}),
);
apiRouter.delete('/api/security/authenticator/:id', requireSession, (req: AuthedRequest, res) =>
  forwardOrg(req, res, 'DELETE', '/account/mfa/authenticator/' + encodeURIComponent(String(req.params.id))),
);

apiRouter.post('/api/security/passkey/register-options', requireSession, (req: AuthedRequest, res) =>
  forwardOrg(req, res, 'POST', '/account/mfa/passkey/register-options', req.body ?? {}),
);
apiRouter.post('/api/security/passkey/register', requireSession, (req: AuthedRequest, res) =>
  forwardOrg(req, res, 'POST', '/account/mfa/passkey/register', req.body ?? {}),
);
apiRouter.patch('/api/security/passkey/:id', requireSession, (req: AuthedRequest, res) =>
  forward(req, res, 'PATCH', '/account/mfa/passkey/' + encodeURIComponent(String(req.params.id)), req.body ?? {}),
);
apiRouter.delete('/api/security/passkey/:id', requireSession, (req: AuthedRequest, res) =>
  forwardOrg(req, res, 'DELETE', '/account/mfa/passkey/' + encodeURIComponent(String(req.params.id))),
);

// --- Devices pane: list/terminate SSO sessions. The access token carries no `sid`,
//     so only the BFF knows which session is the caller's (session.ssoSid). GET is
//     post-processed to mark is_current; DELETE refuses the current session (that's
//     logout); terminate-others keeps that same sid. ---
apiRouter.get('/api/sessions', requireSession, async (req: AuthedRequest, res) => {
  const s = req.session!;
  if (s.accessExpiresAt <= Math.floor(Date.now() / 1000)) {
    return res.status(401).json({ error: 'token_expired' });
  }
  let upstream: globalThis.Response;
  try {
    upstream = await s2sFetch(config.internal + '/account/sessions', {
      headers: { authorization: 'Bearer ' + s.accessToken },
    });
  } catch (e) {
    console.error('sessions proxy failed:', (e as Error).message);
    return res.status(502).json({ error: 'upstream_unreachable' });
  }
  const data = (await upstream.json().catch(() => null)) as { sessions?: Array<{ sid: string }> } | null;
  if (!upstream.ok || !data) {
    return res.status(upstream.status).json(data ?? { error: 'upstream_error' });
  }
  const sessions = (data.sessions ?? []).map((x) => ({ ...x, is_current: x.sid === s.ssoSid }));
  res.json({ sessions });
});

apiRouter.delete('/api/sessions/:sid', requireSession, (req: AuthedRequest, res) => {
  const s = req.session!;
  const sid = String(req.params.sid);
  if (sid === s.ssoSid) {
    // Terminating your current session is logout, not a device action.
    return res.status(409).json({ error: 'is_current_session' });
  }
  return forward(req, res, 'DELETE', '/account/sessions/' + encodeURIComponent(sid));
});

apiRouter.post('/api/sessions/terminate-others', requireSession, (req: AuthedRequest, res) => {
  const s = req.session!;
  if (!s.ssoSid) return res.status(409).json({ error: 'no_current_session' });
  return forward(req, res, 'POST', '/account/sessions/terminate-others', { keep_sid: s.ssoSid });
});

// --- Step-up (sudo window): the BFF supplies the master-session sid; the SSO
//     verifies it belongs to the token's subject and stamps it on success. ---
apiRouter.get('/api/stepup/status', requireSession, async (req: AuthedRequest, res) => {
  const s = req.session!;
  if (!s.ssoSid) return res.status(409).json({ error: 'no_current_session' });
  if (s.accessExpiresAt <= Math.floor(Date.now() / 1000)) {
    return res.status(401).json({ error: 'token_expired' });
  }
  // `mode` picks the acceptance rule (strong-mandatory for org/admin, fallback for
  // personal security, email-change for the email/username change); default strong.
  const m = String(req.query.mode ?? '');
  const mode = m === 'fallback' || m === 'email-change' ? m : 'strong-mandatory';
  try {
    const r = await fetch(
      config.internal + '/account/stepup/status?sid=' + encodeURIComponent(s.ssoSid) + '&mode=' + mode,
      { headers: { authorization: 'Bearer ' + s.accessToken } },
    );
    res.status(r.status).json(await r.json().catch(() => null));
  } catch (e) {
    console.error('stepup status proxy failed:', (e as Error).message);
    res.status(502).json({ error: 'upstream_unreachable' });
  }
});
apiRouter.post('/api/stepup/passkey-options', requireSession, (req: AuthedRequest, res) => {
  const s = req.session!;
  if (!s.ssoSid) return res.status(409).json({ error: 'no_current_session' });
  return forward(req, res, 'POST', '/account/stepup/passkey-options', { sid: s.ssoSid });
});
apiRouter.post('/api/stepup/verify', requireSession, (req: AuthedRequest, res) => {
  const s = req.session!;
  if (!s.ssoSid) return res.status(409).json({ error: 'no_current_session' });
  const b = (req.body ?? {}) as { method?: unknown; code?: unknown; credential?: unknown; password?: unknown };
  return forward(req, res, 'POST', '/account/stepup/verify', {
    sid: s.ssoSid, method: b.method, code: b.code, credential: b.credential, password: b.password,
  });
});
apiRouter.post('/api/stepup/send-email', requireSession, (req: AuthedRequest, res) => {
  const s = req.session!;
  if (!s.ssoSid) return res.status(409).json({ error: 'no_current_session' });
  return forward(req, res, 'POST', '/account/stepup/send-email', { sid: s.ssoSid });
});
