import { Router, type Request, type Response } from 'express';
import crypto from 'node:crypto';
import { pool } from '../db.js';
import { createTxn, getTxn, consumeTxn, updateTxn, type LoginTxn } from '../oidc/transactions.js';
import { createCode } from '../oidc/codes.js';
import { createSession, loadSession, stampStepup, persistSession, methodFromAmr } from '../oidc/sessions.js';
import { findByUsernameOrEmail, verifyPassword } from '../oidc/identities.js';
import { countAuthenticators, verifyLoginTotp } from '../mfa.js';
import { countPasskeys, loginAuthOptions, verifyLoginAssertion } from '../webauthn.js';
import { issueEmailOtp, verifyEmailOtp, maskEmail, otpValidityMinutes } from '../emailOtp.js';
import { sendEmail } from '../email.js';
import { renderOtpEmail } from '../emailTemplates.js';
import { renderLoginPage, renderPasskeyLoginPage, renderChallengePage, renderKmsiPage, renderErrorPage, renderStepupEnrollPage, AUTH_BG_SVG, FAVICON_SVG, type ChallengeMethod } from '../views.js';
import { CHALLENGE_HTML } from '../challengePage.js';
import { config } from '../config.js';
import { getSetting } from '../settings.js';
import { appAccessAllowed } from '../rbac/appRoles.js';

export const authorizeRouter = Router();

// acr stamped on an OIDC step-up code (the succeed() stepupReturn fork). Distinct
// from the login acrs (1fa/2fa) so an RP can prove the code came from a fresh
// factor challenge, not a silent session reuse. RPs validate this on the return.
const STEPUP_ACR = 'urn:dreamsso:stepup';

const siteName = async () => (await getSetting('site_name', 'DreamSSO'))!;
// The password-reset entrance beside the password label; the flow lives on the
// account portal (settings-driven, never hardcoded).
const forgotUrl = async () =>
  `${(await getSetting('account_portal_url', config.accountPortalUrl))!}/forgot`;
// The "Sign up" strip below the card — only while registration is on. The
// txn rides along so the register page's "Already have an account? Sign in"
// can land BACK on this exact login transaction (unintentional clicks).
const registerUrl = async (txn?: string) =>
  (await getSetting('enable_registration', 'false')) === 'true'
    ? `${(await getSetting('account_portal_url', config.accountPortalUrl))!}/register/start${txn ? `?txn=${encodeURIComponent(txn)}` : ''}`
    : undefined;

// Pre-redirect failures (unknown/disabled client, bad redirect_uri, expired txn):
// nowhere safe to bounce, so render a terminal styled page.
async function errorPage(res: Response, status: number, title: string, message: string, code?: string) {
  const nonce = htmlPage(res);
  return res.status(status).send(renderErrorPage(nonce, { title, message, code, siteName: await siteName() }));
}
const txnExpired = (res: Response) =>
  errorPage(res, 400, 'Session expired', 'This sign-in attempt expired. Go back to the app and try signing in again.', 'txn_expired');

// CSRF for the login-card POSTs: the synchronizer token (csrf) is the primary
// defense; Origin / Sec-Fetch-Site are belt-and-suspenders. Origin can
// legitimately be "null" (Referrer-Policy: no-referrer, or a Safari quirk) —
// that's not an attack signal, so don't fail on it.
function csrfOk(req: Request, txn: LoginTxn, csrf: unknown): boolean {
  const origin = req.headers.origin;
  const originOk =
    !origin || origin === 'null' ||
    (() => { try { return new URL(origin).host === req.headers.host; } catch { return false; } })();
  const sfs = req.headers['sec-fetch-site'];
  const sfsOk = !sfs || sfs === 'same-origin' || sfs === 'none';
  return csrf === txn.csrf && originOk && sfsOk;
}

// Authentication complete (password-only, password+factor, or first-factor
// passkey): open the master session (TRANSIENT — browser-session cookie) and ask
// "Stay signed in?". The txn completes at POST /login/stay. Silent session reuse
// never comes through here, so KMSI is asked exactly once per session.
async function finishLogin(
  req: Request,
  res: Response,
  txnId: string,
  txn: LoginTxn,
  sub: string,
  amr: string[],
  acr: string,
  userLabel: string,
): Promise<void> {
  const { sid } = await createSession(res, {
    userSub: sub, amr, acr, ip: req.ip, userAgent: qstr(req.headers['user-agent']),
    country: qstr(req.headers['cf-ipcountry']).trim() || undefined, // Cloudflare edge header; absent locally -> Unknown
  });
  txn.kmsi = { sid, sub, userLabel, amr, acr, authTime: Math.floor(Date.now() / 1000) };
  await updateTxn(txnId, txn);
  return renderKmsi(res, txnId, txn);
}

// Profile picture for the identity chip — fetched fresh by sub at render time
// (tiny query; keeps the txn payload as-is).
async function avatarOf(sub: string): Promise<string | null> {
  const { rows } = await pool.query<{ avatar: string | null }>(
    'SELECT avatar FROM identities WHERE sub = $1 AND deleted_at IS NULL',
    [sub],
  );
  return rows[0]?.avatar ?? null;
}

async function renderKmsi(res: Response, txnId: string, txn: LoginTxn): Promise<void> {
  const nonce = htmlPage(res, txn.redirectUri);
  res.status(200).send(
    renderKmsiPage({
      txn: txnId, csrf: txn.csrf, nonce, userLabel: txn.kmsi!.userLabel,
      avatar: await avatarOf(txn.kmsi!.sub), siteName: await siteName(),
    }),
  );
}

// Render the challenge in a given state. Default method = strongest owned
// (methods[] is ordered passkey > totp > email at creation). Rendering the
// passkey state mints a fresh assertion challenge into the txn (any previous one
// was consumed by a verification attempt or superseded).
async function renderChallenge(
  res: Response,
  txnId: string,
  txn: LoginTxn,
  o: { error?: string; method?: string; resendIn?: number } = {},
): Promise<void> {
  const mfa = txn.mfa!;
  const method = (o.method && mfa.methods.includes(o.method) ? o.method : mfa.methods[0]) as ChallengeMethod;
  let passkeyOptions: string | undefined;
  if (method === 'passkey') {
    const options = await loginAuthOptions(mfa.sub);
    mfa.passkeyChallenge = options.challenge;
    await updateTxn(txnId, txn);
    passkeyOptions = JSON.stringify(options);
  }
  // OIDC step-up txns get a Cancel that returns to the RP as access_denied (the RP
  // treats it as a user cancel). Login/admin-door challenges have no such link.
  let cancelUrl: string | undefined;
  if (mfa.stepupReturn) {
    const u = new URL(txn.redirectUri);
    u.searchParams.set('error', 'access_denied');
    if (txn.state) u.searchParams.set('state', txn.state);
    cancelUrl = u.toString();
  }
  const nonce = htmlPage(res, txn.redirectUri);
  res.status(o.error ? 401 : 200).send(
    renderChallengePage({
      txn: txnId, csrf: txn.csrf, nonce, userLabel: mfa.userLabel,
      method, methods: mfa.methods, maskedEmail: mfa.maskedEmail, emailSent: mfa.emailSent,
      resendIn: o.resendIn, otpMinutes: otpValidityMinutes, passkeyOptions, error: o.error,
      avatar: await avatarOf(mfa.sub), siteName: await siteName(), cancelUrl,
    }),
  );
}

// The login form always carries first-factor passkey options (conditional UI +
// button). The challenge is minted once per txn and REUSED across re-renders and
// sheet-reopens; a verification attempt consumes it (failure mints fresh).
async function loginPasskeyOptions(txnId: string, txn: LoginTxn): Promise<string> {
  if (!txn.passkey) {
    const options = await loginAuthOptions();
    txn.passkey = options.challenge;
    await updateTxn(txnId, txn);
    return JSON.stringify(options);
  }
  return JSON.stringify({
    challenge: txn.passkey,
    rpId: config.webauthnRpId,
    timeout: 600_000,
    userVerification: 'required',
  });
}

function htmlPage(res: Response, redirectUri?: string): string {
  const nonce = crypto.randomBytes(16).toString('base64');
  res.setHeader('Cache-Control', 'no-store');
  // form-action must allow 'self' (the POST to /login + error re-renders) AND the
  // client's redirect_uri origin — browsers enforce form-action on the post-submit
  // REDIRECT too, so without the RP origin the OIDC redirect back to the app is blocked.
  let formAction = "'self'";
  if (redirectUri) {
    try { formAction += ' ' + new URL(redirectUri).origin; } catch { /* ignore bad uri */ }
  }
  // connect-src 'self': Cloudflare injects same-origin telemetry beacons into
  // this page — the managed-challenge JS-detection ping (/cdn-cgi/challenge-platform/
  // …/jsd/oneshot/…) that fires post-solve, and the Web Analytics RUM beacon
  // (/cdn-cgi/rum). Both are same-origin (CF serves /cdn-cgi/* at the edge), so
  // 'self' unblocks them without opening any external origin. Blocking the jsd
  // ping would degrade the very bot signal the /login managed challenge exists to
  // collect. Our own inline script is nonce-gated and makes no fetches.
  res.setHeader(
    'Content-Security-Policy',
    `default-src 'none'; img-src 'self'; style-src 'nonce-${nonce}'; script-src 'nonce-${nonce}'; connect-src 'self'; form-action ${formAction}; base-uri 'none'; frame-ancestors 'none'`,
  );
  return nonce;
}

const qstr = (v: unknown): string => (typeof v === 'string' ? v : '');

// The auth-page background bloom. Public, cacheable, same-origin (satisfies the
// auth pages' img-src 'self' CSP). Loaded as an <img>-style CSS background, so no
// script execution concern. (Whitelist this ahead of any first-run interceptor.)
authorizeRouter.get('/auth-bg.svg', (_req: Request, res: Response) => {
  res.type('image/svg+xml');
  res.setHeader('Cache-Control', 'public, max-age=86400');
  res.send(AUTH_BG_SVG);
});

// Brand favicon (referenced by every page's <head>). Same-origin so it satisfies
// the strict CSP; a day's cache. Legacy /favicon.ico auto-requests redirect here.
authorizeRouter.get('/favicon.svg', (_req: Request, res: Response) => {
  res.type('image/svg+xml');
  res.setHeader('Cache-Control', 'public, max-age=86400');
  res.send(FAVICON_SVG);
});
authorizeRouter.get('/favicon.ico', (_req: Request, res: Response) => res.redirect(301, '/favicon.svg'));

// Zone-level Cloudflare custom challenge page. CF fetches + stores this and
// serves its own copy from the edge, so runtime has no origin dependency (all
// inlined); the cache header just governs CF's fetch. Not matched by the login
// challenge rule, so CF can fetch it without being challenged.
authorizeRouter.get('/challenge.html', (_req: Request, res: Response) => {
  res.type('html');
  res.setHeader('Cache-Control', 'public, max-age=120');
  res.send(CHALLENGE_HTML);
});

// GET /authorize — validate the OIDC request, open a login transaction, send to /login.
authorizeRouter.get('/authorize', async (req: Request, res: Response) => {
  const clientId = qstr(req.query.client_id);
  const redirectUri = qstr(req.query.redirect_uri);

  const { rows } = await pool.query(
    'SELECT client_id, redirect_uris, name, disabled_at FROM oauth_clients WHERE client_id = $1',
    [clientId],
  );
  const client = rows[0];
  // Pre-redirect validation errors must NOT redirect (open-redirect / unknown client).
  if (!client) {
    return errorPage(res, 400, 'Unknown application', 'This sign-in request came from an application DreamSSO doesn’t recognize.', 'unknown_client');
  }
  if (client.disabled_at) {
    return errorPage(res, 403, 'Application disabled', `${client.name} is currently disabled. Contact your administrator.`, 'client_disabled');
  }
  if (!client.redirect_uris.includes(redirectUri)) {
    return errorPage(res, 400, 'Invalid request', 'The application’s return address doesn’t match its registration.', 'invalid_redirect_uri');
  }

  const responseType = qstr(req.query.response_type);
  const scope = qstr(req.query.scope);
  const codeChallenge = qstr(req.query.code_challenge);
  const codeChallengeMethod = qstr(req.query.code_challenge_method);
  const state = req.query.state ? qstr(req.query.state) : undefined;

  // redirect_uri is trusted now -> protocol errors go back to the RP per OAuth.
  const errorRedirect = (error: string, desc?: string) => {
    const u = new URL(redirectUri);
    u.searchParams.set('error', error);
    if (desc) u.searchParams.set('error_description', desc);
    if (state) u.searchParams.set('state', state);
    return res.redirect(u.toString());
  };
  if (responseType !== 'code') return errorRedirect('unsupported_response_type');
  if (!scope.split(' ').includes('openid')) return errorRedirect('invalid_scope', 'openid required');
  if (!codeChallenge || codeChallengeMethod !== 'S256') {
    return errorRedirect('invalid_request', 'PKCE S256 required');
  }
  const nonce = req.query.nonce ? qstr(req.query.nonce) : undefined;

  // --- session reuse (SSO silent auth) ---
  // prompt=login/select_account forces a fresh login; max_age forces it when the
  // existing session's auth_time is too old. Otherwise an active master session
  // yields a code with no re-prompt. prompt=none requires a usable session.
  const prompt = qstr(req.query.prompt).split(' ').filter(Boolean);
  const maxAge = req.query.max_age != null ? Number(qstr(req.query.max_age)) : undefined;
  const forceReauth = prompt.includes('login') || prompt.includes('select_account');

  const session = forceReauth ? null : await loadSession(req);
  const tooOld =
    session != null && maxAge != null && Number.isFinite(maxAge) &&
    Math.floor(Date.now() / 1000) - session.authTime > maxAge;

  // --- OIDC step-up (the SSO takes over an RP's challenge; e.g. videosite) ---
  // A `stepup` param carries the RP's accepted method set (e.g. "totp,passkey").
  // With an existing session we FORCE a fresh factor challenge (never a silent
  // reuse) and return a code whose amr is that factor — the RP records its own
  // sudo window. With no session we fall through to a normal login (a fresh strong
  // login satisfies it; the RP re-checks amr on return). The RP binds identity by
  // matching the returned token's sub against its own session, so a mid-flight
  // account switch here is caught there, not by us.
  const stepupSet = qstr(req.query.stepup).split(',').map((s) => s.trim()).filter(Boolean);
  if (stepupSet.length > 0 && session && !tooOld) {
    if (!(await appAccessAllowed(clientId, session.userSub))) {
      return errorRedirect('access_denied', 'You do not have access to this application');
    }
    // Only strong factors are honoured for an OIDC step-up (email stays a login-
    // only floor; it never reaches the stepupReturn fork). Intersect the requested
    // set with what the user owns, in strength order passkey > totp.
    const wantPasskey = stepupSet.includes('passkey');
    const wantTotp = stepupSet.includes('totp');
    const [pkCount, totpCount] = await Promise.all([
      wantPasskey ? countPasskeys(session.userSub) : Promise.resolve(0),
      wantTotp ? countAuthenticators(session.userSub) : Promise.resolve(0),
    ]);
    const methods: string[] = [];
    if (wantPasskey && pkCount > 0) methods.push('passkey');
    if (wantTotp && totpCount > 0) methods.push('totp');

    if (methods.length === 0) {
      // No accepted factor — the SSO-hosted enroll card. Its Cancel returns to the
      // RP as access_denied (the RP treats that identically to a user cancel).
      const cspNonce = htmlPage(res, redirectUri);
      const portal = (await getSetting('account_portal_url', config.accountPortalUrl))!;
      const cancel = new URL(redirectUri);
      cancel.searchParams.set('error', 'access_denied');
      if (state) cancel.searchParams.set('state', state);
      return res.status(403).send(renderStepupEnrollPage(cspNonce, {
        siteName: await siteName(), appName: client.name,
        securityUrl: `${portal}/security`, cancelUrl: cancel.toString(),
      }));
    }

    const { rows: [id] } = await pool.query(
      'SELECT username, display_name FROM identities WHERE sub = $1', [session.userSub],
    );
    const txnId = await createTxn({
      clientId, redirectUri, state, nonce, codeChallenge, codeChallengeMethod, scope,
      clientName: client.name,
      mfa: {
        sub: session.userSub,
        userLabel: id?.display_name || id?.username || 'your account',
        methods,
        attempts: 0,
        stepupReturn: { sid: session.sid },
      },
    });
    return res.redirect(`/login?txn=${encodeURIComponent(txnId)}`);
  }

  if (session && !tooOld) {
    // Sign-in safeguard: clients with a synced role catalog refuse users whose
    // effective app role is No access (or references a removed role).
    if (!(await appAccessAllowed(clientId, session.userSub))) {
      return errorRedirect('access_denied', 'You do not have access to this application');
    }
    const code = await createCode({
      clientId,
      redirectUri,
      userSub: session.userSub,
      sid: session.sid,
      codeChallenge,
      codeChallengeMethod,
      nonce,
      scope,
      amr: session.amr,
      acr: session.acr,
      authTime: session.authTime,
    });
    const u = new URL(redirectUri);
    u.searchParams.set('code', code);
    if (state) u.searchParams.set('state', state);
    return res.redirect(u.toString());
  }
  if (prompt.includes('none')) return errorRedirect('login_required');

  const txnId = await createTxn({
    clientId,
    redirectUri,
    state,
    nonce,
    codeChallenge,
    codeChallengeMethod,
    scope,
    acrValues: req.query.acr_values ? qstr(req.query.acr_values) : undefined,
    clientName: client.name,
  });
  res.redirect(`/login?txn=${encodeURIComponent(txnId)}`);
});

// GET /login — render the form for an open transaction.
authorizeRouter.get('/login', async (req: Request, res: Response) => {
  const txnId = qstr(req.query.txn);
  const txn = await getTxn(txnId);
  if (!txn) return txnExpired(res);
  // Refresh-safe: a txn past authentication re-renders its current phase — the
  // KMSI question or the challenge — never the password form.
  if (txn.kmsi) return renderKmsi(res, txnId, txn);
  if (txn.mfa) return renderChallenge(res, txnId, txn, { method: qstr(req.query.use) || undefined });
  const passkeyOptions = await loginPasskeyOptions(txnId, txn);
  const nonce = htmlPage(res, txn.redirectUri);
  res.status(200).send(
    renderLoginPage({
      txn: txnId, csrf: txn.csrf, nonce, appName: txn.clientName, siteName: await siteName(), passkeyOptions,
      forgotUrl: await forgotUrl(),
      registerUrl: await registerUrl(txnId),
    }),
  );
});

// POST /login — verify credentials, create the session, issue the code.
authorizeRouter.post('/login', async (req: Request, res: Response) => {
  const { txn: txnId, csrf, username, password } = req.body ?? {};
  const txn = await getTxn(qstr(txnId));
  if (!txn) return txnExpired(res);
  if (txn.kmsi) return renderKmsi(res, qstr(txnId), txn); // already authenticated
  if (txn.mfa) return renderChallenge(res, qstr(txnId), txn); // already past the password phase
  if (!csrfOk(req, txn, csrf)) {
    return res.status(403).type('text/plain').send('Bad request.');
  }

  const reRender = async (msg: string) => {
    const passkeyOptions = await loginPasskeyOptions(qstr(txnId), txn);
    const nonce = htmlPage(res, txn.redirectUri);
    return res.status(401).send(
      renderLoginPage({
        txn: qstr(txnId), csrf: txn.csrf, error: msg, username: qstr(username), nonce,
        appName: txn.clientName, siteName: await siteName(), passkeyOptions,
        forgotUrl: await forgotUrl(),
        registerUrl: await registerUrl(qstr(txnId)),
      }),
    );
  };

  const identity = await findByUsernameOrEmail(qstr(username).trim());
  if (!identity || identity.status !== 'active' || !(await verifyPassword(identity, qstr(password)))) {
    return reRender('Invalid username or password.'); // enumeration-safe
  }

  // Password verified. Challenge ONLY when the account MFA toggle is on —
  // owning factors alone never challenges. Methods = what the user owns, ordered
  // strongest first; email is the FLOOR, offered only with no strong factor.
  if (identity.mfa_enabled) {
    const [passkeyCount, totpCount] = await Promise.all([
      countPasskeys(identity.sub),
      countAuthenticators(identity.sub),
    ]);
    const methods: string[] = [];
    if (passkeyCount > 0) methods.push('passkey');
    if (totpCount > 0) methods.push('totp');
    if (methods.length === 0 && identity.email) methods.push('email');
    if (methods.length > 0) {
      txn.mfa = {
        sub: identity.sub,
        userLabel: qstr(username).trim(), // the identifier the user just typed (username or email)
        kmsiLabel: identity.display_name || identity.username, // display name for the KMSI step after MFA
        methods,
        attempts: 0,
        maskedEmail: methods.includes('email') && identity.email ? maskEmail(identity.email) : undefined,
      };
      await updateTxn(qstr(txnId), txn);
      return renderChallenge(res, qstr(txnId), txn);
    }
  }

  // No MFA: straight to KMSI, which shows the authenticated identity (display name).
  return finishLogin(req, res, qstr(txnId), txn, identity.sub, ['pwd'], 'urn:dreamsso:1fa',
    identity.display_name || identity.username);
});

// POST /login/stay — the "Stay signed in?" answer. Yes upgrades the (already
// set) transient session to persistent — the UPDATE is bound to the caller's own
// cookie; then the txn completes: code for an OIDC login, localNext for /admin.
authorizeRouter.post('/login/stay', async (req: Request, res: Response) => {
  const { txn: txnId, csrf, choice } = req.body ?? {};
  const txn = await getTxn(qstr(txnId));
  if (!txn || !txn.kmsi) return txnExpired(res);
  if (!csrfOk(req, txn, csrf)) {
    return res.status(403).type('text/plain').send('Bad request.');
  }
  if (qstr(choice) === 'yes') {
    await persistSession(req, res, txn.kmsi.sid); // no-op if the cookie doesn't match the sid
  }
  const k = txn.kmsi;
  if (txn.localNext) {
    await consumeTxn(qstr(txnId));
    return res.redirect(txn.localNext);
  }
  // Same sign-in safeguard as silent reuse: No access -> back to the app with
  // access_denied instead of a code.
  if (!(await appAccessAllowed(txn.clientId, k.sub))) {
    await consumeTxn(qstr(txnId));
    const u = new URL(txn.redirectUri);
    u.searchParams.set('error', 'access_denied');
    u.searchParams.set('error_description', 'You do not have access to this application');
    if (txn.state) u.searchParams.set('state', txn.state);
    return res.redirect(u.toString());
  }
  const code = await createCode({
    clientId: txn.clientId,
    redirectUri: txn.redirectUri,
    userSub: k.sub,
    sid: k.sid,
    codeChallenge: txn.codeChallenge,
    codeChallengeMethod: txn.codeChallengeMethod,
    nonce: txn.nonce,
    scope: txn.scope,
    amr: k.amr,
    acr: k.acr,
    authTime: k.authTime,
  });
  await consumeTxn(qstr(txnId));
  const u = new URL(txn.redirectUri);
  u.searchParams.set('code', code);
  if (txn.state) u.searchParams.set('state', txn.state);
  res.redirect(u.toString());
});

// GET /login/passkey?txn= — the dedicated passkey page (the login page's
// button navigates here; conditional-UI autofill stays on the form). The
// txn's existing challenge is REUSED — rendering this page mints nothing new.
authorizeRouter.get('/login/passkey', async (req: Request, res: Response) => {
  const txnId = qstr(req.query.txn);
  const txn = await getTxn(txnId);
  if (!txn) return txnExpired(res);
  if (txn.kmsi) return renderKmsi(res, txnId, txn);
  if (txn.mfa) return renderChallenge(res, txnId, txn);
  const passkeyOptions = await loginPasskeyOptions(txnId, txn);
  const nonce = htmlPage(res, txn.redirectUri);
  res.send(renderPasskeyLoginPage({
    txn: txnId, csrf: txn.csrf, nonce, appName: txn.clientName, siteName: await siteName(), passkeyOptions,
  }));
});

// POST /login/passkey — first-factor (username-less) passkey sign-in from the
// login page. A user-verified passkey is both factors: full auth, NO further MFA
// step, and the account MFA toggle is irrelevant here.
authorizeRouter.post('/login/passkey', async (req: Request, res: Response) => {
  const { txn: txnId, csrf, credential } = req.body ?? {};
  const txn = await getTxn(qstr(txnId));
  if (!txn) return txnExpired(res);
  if (txn.kmsi) return renderKmsi(res, qstr(txnId), txn);
  if (txn.mfa) return renderChallenge(res, qstr(txnId), txn);
  if (!csrfOk(req, txn, csrf)) {
    return res.status(403).type('text/plain').send('Bad request.');
  }

  const failBack = async (reason: string) => {
    // Consume the used challenge, mint a fresh one, land back on the login form —
    // "sign in with your password" is right there, per the design.
    txn.passkey = undefined;
    await updateTxn(qstr(txnId), txn);
    const passkeyOptions = await loginPasskeyOptions(qstr(txnId), txn);
    const nonce = htmlPage(res, txn.redirectUri);
    return res.status(401).send(
      renderLoginPage({
        txn: qstr(txnId), csrf: txn.csrf, nonce, appName: txn.clientName, siteName: await siteName(),
        passkeyOptions, forgotUrl: await forgotUrl(),
      registerUrl: await registerUrl(qstr(txnId)),
        error: `Couldn't sign in with your passkey — try again or sign in with your password. [${reason}]`,
      }),
    );
  };

  const challenge = txn.passkey;
  if (!challenge) return failBack('challenge_expired');
  let parsed;
  try {
    parsed = JSON.parse(qstr(credential));
  } catch {
    return failBack('malformed');
  }
  const v = await verifyLoginAssertion(parsed, challenge);
  if (!v.ok) return failBack(v.reason);

  const { rows: [id] } = await pool.query(
    `SELECT status, display_name, username FROM identities WHERE sub = $1 AND deleted_at IS NULL`,
    [v.sub],
  );
  if (!id || id.status !== 'active') return failBack('account_unavailable');

  // Passkey = full auth, no MFA step — straight to KMSI with the display name.
  return finishLogin(req, res, qstr(txnId), txn, v.sub, ['passkey'], 'urn:dreamsso:2fa',
    id.display_name || id.username);
});

// POST /login/challenge/send-email — the email offer's explicit send (and resend).
// Cooldown/daily caps live in emailOtp; a resend within the validity window
// re-sends the SAME code.
authorizeRouter.post('/login/challenge/send-email', async (req: Request, res: Response) => {
  const { txn: txnId, csrf } = req.body ?? {};
  const txn = await getTxn(qstr(txnId));
  if (!txn || !txn.mfa) return txnExpired(res);
  if (!csrfOk(req, txn, csrf) || !txn.mfa.methods.includes('email')) {
    return res.status(403).type('text/plain').send('Bad request.');
  }

  const issued = await issueEmailOtp(txn.mfa.sub, 'login');
  if (!issued.ok) {
    if (issued.reason === 'daily_limit') {
      return renderChallenge(res, qstr(txnId), txn, { method: 'email', error: 'Daily code limit reached — try again later.' });
    }
    return renderChallenge(res, qstr(txnId), txn, {
      method: 'email', resendIn: issued.retryAfter,
      error: `Please wait ${issued.retryAfter}s before requesting another code.`,
    });
  }

  const { rows: [id] } = await pool.query(`SELECT email FROM identities WHERE sub = $1`, [txn.mfa.sub]);
  const sent = id?.email
    ? await sendEmail({
        to: id.email,
        ...renderOtpEmail({ siteName: (await siteName())!, code: issued.code, minutes: otpValidityMinutes }),
      })
    : ({ ok: false, reason: 'no_email' } as const);
  if (!sent.ok) {
    return renderChallenge(res, qstr(txnId), txn, { method: 'email', error: `Couldn't send the code — try again. [${sent.reason}]` });
  }
  txn.mfa.emailSent = true;
  await updateTxn(qstr(txnId), txn);
  return renderChallenge(res, qstr(txnId), txn, { method: 'email', resendIn: 60 });
});

// POST /login/challenge — verify the second factor and complete the login.
// Attempts are capped per txn; hitting the cap burns the txn (start over).
const MAX_CHALLENGE_ATTEMPTS = 5;

authorizeRouter.post('/login/challenge', async (req: Request, res: Response) => {
  const { txn: txnId, csrf, method, code, credential } = req.body ?? {};
  const txn = await getTxn(qstr(txnId));
  if (!txn) return txnExpired(res);
  if (txn.kmsi) return renderKmsi(res, qstr(txnId), txn);
  if (!txn.mfa) return txnExpired(res);
  if (!csrfOk(req, txn, csrf) || !txn.mfa.methods.includes(qstr(method))) {
    return res.status(403).type('text/plain').send('Bad request.');
  }
  const mfa = txn.mfa;

  // Shared strong-factor failure path: count txn attempts, burn at the cap.
  const strongFail = async (m: string, msg: string) => {
    mfa.attempts += 1;
    if (mfa.attempts >= MAX_CHALLENGE_ATTEMPTS) {
      await consumeTxn(qstr(txnId));
      // A step-up (RP) txn must return to the app, not dead-end on the SSO — the RP
      // shows its "didn't complete" card. A non-access_denied error distinguishes
      // the cap from a user cancel (which the RP treats silently).
      if (mfa.stepupReturn) {
        const u = new URL(txn.redirectUri);
        u.searchParams.set('error', 'login_required');
        u.searchParams.set('error_description', 'too_many_attempts');
        if (txn.state) u.searchParams.set('state', txn.state);
        return res.redirect(u.toString());
      }
      return errorPage(res, 403, 'Too many attempts',
        'Too many failed attempts. Go back to the app and start signing in again.', 'too_many_attempts');
    }
    await updateTxn(qstr(txnId), txn);
    return renderChallenge(res, qstr(txnId), txn, { method: m, error: msg });
  };

  // Step-up mode: the challenge belongs to an EXISTING session (the /admin door).
  // Success stamps its sudo window and returns to the local path — no new session,
  // no code. Normal login-challenge mode falls through to finishLogin.
  const succeed = async (amr: string[], acr: string) => {
    if (mfa.stepupReturn) {
      // OIDC step-up (an RP): mint a code for the EXISTING session carrying just
      // the fresh factor's amr (strip the implicit 'pwd' — no password was typed),
      // then return it to the RP. No new session, no KMSI, no SSO-session stamp —
      // the RP owns its own sudo window.
      // Re-check app access at completion — the txn lived up to 10 min and access
      // may have been revoked mid-flight (matches silent-reuse + login-stay).
      if (!(await appAccessAllowed(txn.clientId, mfa.sub))) {
        await consumeTxn(qstr(txnId));
        const u = new URL(txn.redirectUri);
        u.searchParams.set('error', 'access_denied');
        if (txn.state) u.searchParams.set('state', txn.state);
        return res.redirect(u.toString());
      }
      const stepAmr = amr.filter((a) => a !== 'pwd');
      const code = await createCode({
        clientId: txn.clientId,
        redirectUri: txn.redirectUri,
        userSub: mfa.sub,
        sid: mfa.stepupReturn.sid,
        codeChallenge: txn.codeChallenge,
        codeChallengeMethod: txn.codeChallengeMethod,
        nonce: txn.nonce,
        scope: txn.scope,
        amr: stepAmr,
        // Distinct acr — ONLY this fresh-challenge fork sets it. It's the freshness
        // signal the RP validates: a silently-reused login code carries the original
        // login's acr/amr, so requiring this acr stops a stale strong-factor session
        // from being accepted as a satisfied step-up.
        acr: STEPUP_ACR,
        authTime: Math.floor(Date.now() / 1000),
      });
      await consumeTxn(qstr(txnId));
      const u = new URL(txn.redirectUri);
      u.searchParams.set('code', code);
      if (txn.state) u.searchParams.set('state', txn.state);
      return res.redirect(u.toString());
    }
    if (mfa.stepupSid) {
      await stampStepup(mfa.stepupSid, methodFromAmr(amr));
      await consumeTxn(qstr(txnId));
      return res.redirect(txn.localNext || '/admin');
    }
    // KMSI shows the authenticated identity — the display name, not the typed one.
    return finishLogin(req, res, qstr(txnId), txn, mfa.sub, amr, acr, mfa.kmsiLabel ?? mfa.userLabel);
  };

  if (qstr(method) === 'totp') {
    const valid = await verifyLoginTotp(mfa.sub, qstr(code).trim());
    if (!valid) return strongFail('totp', 'That code is incorrect or expired — enter the current one.');
    return succeed(['pwd', 'otp'], 'urn:dreamsso:2fa');
  }

  if (qstr(method) === 'passkey') {
    // Consume the assertion challenge on ANY verification attempt; a failure
    // re-render mints a fresh one (renderChallenge).
    const challenge = mfa.passkeyChallenge;
    mfa.passkeyChallenge = undefined;
    if (!challenge) return strongFail('passkey', 'Verification expired — try again. [challenge_expired]');
    let parsed;
    try {
      parsed = JSON.parse(qstr(credential));
    } catch {
      return strongFail('passkey', 'Couldn’t verify your passkey — try again. [malformed]');
    }
    const v = await verifyLoginAssertion(parsed, challenge, mfa.sub);
    if (!v.ok) return strongFail('passkey', `Couldn't verify your passkey — try again. [${v.reason}]`);
    return succeed(['pwd', 'passkey'], 'urn:dreamsso:2fa');
  }

  // email — the code enforces its own per-code attempt/expiry rules (videosite
  // semantics: 5 fails or expiry -> mustResend); the txn counter stays out of it
  // so the resend path remains reachable. Send caps bound abuse.
  const r = await verifyEmailOtp(mfa.sub, 'login', qstr(code).trim());
  if (!r.valid) {
    return renderChallenge(res, qstr(txnId), txn, {
      method: 'email',
      error: r.mustResend
        ? 'That code has expired or had too many attempts — send a new one.'
        : 'That code is incorrect — check the latest email.',
    });
  }
  // (Email never appears in a step-up txn's methods — strong-only — so this stays
  // the plain login path.) KMSI shows the display name, not the typed identifier.
  return finishLogin(req, res, qstr(txnId), txn, mfa.sub, ['pwd', 'email'], 'urn:dreamsso:2fa',
    mfa.kmsiLabel ?? mfa.userLabel);
});
