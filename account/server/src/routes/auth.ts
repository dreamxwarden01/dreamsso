// OIDC relying-party auth routes for the account console BFF.
//   GET  /auth/login    -> PKCE+state+nonce, 302 to the SSO /authorize
//   GET  /auth/callback -> exchange code, verify id_token, open a server session
//   GET  /auth/error    -> standalone failure page with a Retry button
//   GET  /auth/logout   -> destroy the server session + front-channel logout to the SSO
import { Router, type Request } from 'express';
import * as oidc from '../oidc.js';
import { config } from '../config.js';
import { createSession, destroySession, getSession, revokeBySsoSid } from '../session.js';

export const authRouter = Router();

export const SESSION_COOKIE = 'acct_sid';
const FLOW_COOKIE = 'acct_flow';

// secure tracks the actual scheme: true behind Caddy (x-forwarded-proto=https,
// trust proxy), false for a plain-http localhost/Vite dev run.
function cookieOpts(req: Request, maxAge?: number) {
  return {
    httpOnly: true,
    secure: req.secure,
    sameSite: 'lax' as const,
    path: '/',
    ...(maxAge ? { maxAge } : {}),
  };
}

function sanitizeReturnTo(rt: unknown): string {
  // A safe returnTo is a same-origin absolute PATH. Reject anything a browser could
  // resolve off-origin: a scheme (`://`), protocol-relative `//`, a backslash
  // (browsers normalize `\` -> `/`, so `/\evil.com` becomes `//evil.com`), or the
  // control chars (tab/newline/CR) the WHATWG URL parser strips before re-forming one.
  if (
    typeof rt !== 'string' ||
    !rt.startsWith('/') ||
    rt.startsWith('//') ||
    rt.includes('\\') ||
    rt.includes('://') ||
    /[\x00-\x1f]/.test(rt)
  ) {
    return '/';
  }
  return rt;
}

function esc(s: unknown): string {
  return String(s).replace(
    /[&<>"]/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c] as string,
  );
}

function renderAuthErrorPage(code?: string, detail?: string): string {
  return `<!DOCTYPE html><meta charset="utf-8"><title>Sign-in failed</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<body style="font-family:-apple-system,system-ui,sans-serif;max-width:520px;margin:12vh auto;padding:0 20px;color:#1f2937">
  <h1 style="font-size:20px;margin-bottom:4px">Couldn't sign you in</h1>
  <p style="color:#6b7280">Something went wrong while completing sign-in. You can try again.</p>
  <pre style="background:#f0f2f5;border:1px solid #e5e7eb;border-radius:8px;padding:12px;white-space:pre-wrap;word-break:break-word;color:#9f2330;font-size:13px">${esc(code || 'unknown')}${detail ? '\n' + esc(detail) : ''}</pre>
  <p style="margin-top:24px"><a href="/auth/login" style="display:inline-block;background:#1a73e8;color:#fff;text-decoration:none;padding:10px 18px;border-radius:8px;font-weight:600">Try again</a></p>
</body>`;
}

// GET /auth/login -> bounce to the SSO.
authRouter.get('/auth/login', (req, res) => {
  const returnTo = sanitizeReturnTo(req.query.returnTo);
  const { verifier, challenge, state, nonce } = oidc.beginFlow();
  res.cookie(FLOW_COOKIE, JSON.stringify({ verifier, state, nonce, returnTo }), cookieOpts(req, 10 * 60 * 1000));
  res.redirect(oidc.authorizeUrl({ challenge, state, nonce }));
});

// GET /auth/callback -> exchange the code, establish the server session.
authRouter.get('/auth/callback', async (req, res) => {
  let flow: { verifier?: string; state?: string; nonce?: string; returnTo?: string } = {};
  try {
    flow = JSON.parse(req.cookies[FLOW_COOKIE] || '{}');
  } catch {
    /* malformed flow cookie -> treated as bad_state below */
  }
  res.clearCookie(FLOW_COOKIE, { path: '/' });

  if (req.query.error) {
    const q =
      '?code=' +
      encodeURIComponent(String(req.query.error)) +
      (req.query.error_description ? '&detail=' + encodeURIComponent(String(req.query.error_description)) : '');
    return res.redirect('/auth/error' + q);
  }
  if (!req.query.code || !flow.state || req.query.state !== flow.state) {
    return res.redirect('/auth/error?code=bad_state');
  }

  try {
    const tok = await oidc.exchangeCode(String(req.query.code), flow.verifier!);
    const claims = await oidc.verifyIdToken(tok.id_token, flow.nonce!);
    // userinfo carries the freshest profile (the id_token may omit some claims).
    const info = await oidc.userinfo(tok.access_token);
    const merged = { ...claims, ...(info ?? {}) };

    const now = Math.floor(Date.now() / 1000);
    // Rotate: one live BFF session per SSO session — drop the browser's prior
    // session for this `sid` (e.g. after a silent re-auth on browser reopen).
    const ssoSid = typeof claims.sid === 'string' ? claims.sid : undefined;
    if (ssoSid) await revokeBySsoSid(ssoSid);
    // Session durability follows the SSO's KMSI claims: the BFF session TTL is
    // capped at the SSO session's absolute expiry, and the cookie is persistent
    // only when the user chose "stay signed in" (else browser-session).
    const persistent = claims.sess_persistent === true;
    const sessExp = typeof claims.sess_exp === 'number' ? claims.sess_exp : null;
    const ttl = Math.max(60, sessExp ? Math.min(config.sessionTtl, sessExp - now) : config.sessionTtl);
    const sid = await createSession({
      sub: String(claims.sub),
      ssoSid,
      claims: merged,
      accessToken: tok.access_token,
      idToken: tok.id_token,
      accessExpiresAt: now + (tok.expires_in ?? 900),
      amr: Array.isArray(claims.amr) ? (claims.amr as string[]) : [],
      acr: typeof claims.acr === 'string' ? claims.acr : undefined,
      authTime: typeof claims.auth_time === 'number' ? claims.auth_time : undefined,
      createdAt: now,
    }, ttl);
    res.cookie(SESSION_COOKIE, sid, persistent ? cookieOpts(req, ttl * 1000) : cookieOpts(req));
    return res.redirect(sanitizeReturnTo(flow.returnTo));
  } catch (err) {
    const e = err as Error & { detail?: { error?: string } };
    const detail =
      e.message === 'token_endpoint_error' ? e.detail?.error || 'token_exchange_failed' : e.message;
    console.error('OIDC callback failed:', e.message, e.detail || '');
    return res.redirect('/auth/error?code=' + encodeURIComponent(detail || 'callback_failed'));
  }
});

// GET /auth/error
authRouter.get('/auth/error', (req, res) => {
  res
    .status(400)
    .type('html')
    .send(renderAuthErrorPage(req.query.code as string, req.query.detail as string));
});

// GET /auth/logout -> destroy the BFF session, then front-channel RP-initiated
// logout to the SSO (ends the master session + back-channel fan-out to the other
// apps), landing on the SSO's "signed out" page. The SPA navigates here directly.
authRouter.get('/auth/logout', async (req, res) => {
  const sid = req.cookies[SESSION_COOKIE];
  const sess = await getSession(sid);
  try {
    await destroySession(sid);
  } catch (e) {
    console.error('logout destroySession:', (e as Error).message);
  }
  res.clearCookie(SESSION_COOKIE, { path: '/' });
  res.redirect(oidc.endSessionUrl(sess?.idToken));
});
