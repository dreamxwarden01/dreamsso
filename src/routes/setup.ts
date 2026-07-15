import express from 'express';
import type { Request, Response, NextFunction } from 'express';
import crypto from 'node:crypto';
import { isSetupComplete, isSetupConfigured } from '../setup/state.js';
import { verifySetupToken } from '../setup/token.js';
import { renderUnavailablePage } from '../views.js';
import {
  readEnvState,
  regenKek,
  resolveInput,
  validateConfig,
  testDb,
  testRedis,
  applyAndPersist,
} from '../setup/config.js';
import { validateFinish, runFinishTransaction } from '../setup/finish.js';
import { renderWizard } from '../setup/wizard.js';
import { createSession } from '../oidc/sessions.js';

const qstr = (v: unknown): string => (typeof v === 'string' ? v : '');

export const setupRouter = express.Router();

// Paths that stay reachable while setup is incomplete (besides /setup*).
const OPEN_PATHS = new Set(['/healthz', '/auth-bg.svg', '/favicon.svg', '/favicon.ico']);

// The neutral pre-setup response for anything not explicitly allowed — the same
// page an attacker sees at /setup without a token, so the wizard is never
// advertised (no config hint, no CTA).
function serveUnavailable(res: Response): void {
  const nonce = crypto.randomBytes(16).toString('base64');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader(
    'Content-Security-Policy',
    `default-src 'none'; img-src 'self'; style-src 'nonce-${nonce}'; base-uri 'none'; frame-ancestors 'none'`,
  );
  res.status(503).type('html').send(renderUnavailablePage(nonce));
}

// Mounted FIRST. Once setup is complete (RAM latch) this is a no-op except that
// /setup* returns 404 (the wizard no longer exists). While incomplete, only
// /setup* and the whitelist pass; everything else gets the neutral 503.
export function setupGate(req: Request, res: Response, next: NextFunction): void {
  const isSetupPath = req.path === '/setup' || req.path.startsWith('/setup/');
  if (isSetupComplete()) {
    if (isSetupPath) {
      res.status(404).type('text/plain').send('Not found');
      return;
    }
    return next();
  }
  if (isSetupPath) return next(); // handled below (token-gated)
  if (OPEN_PATHS.has(req.path)) return next();
  serveUnavailable(res);
}

// Token gate for the wizard itself. A missing/invalid token yields the SAME
// unavailable page (not a distinct 403), so /setup is indistinguishable from any
// other path without the token.
function requireToken(req: Request, res: Response, next: NextFunction): void {
  const fromQuery = typeof req.query.token === 'string' ? req.query.token : undefined;
  const tok = fromQuery ?? (req.cookies?.setup_token as string | undefined);
  if (!verifySetupToken(tok)) {
    serveUnavailable(res);
    return;
  }
  // A valid ?token= drops a scoped cookie so subsequent SPA/API calls don't need
  // it in the URL.
  if (fromQuery) {
    res.cookie('setup_token', fromQuery, { httpOnly: true, sameSite: 'strict', path: '/setup' });
  }
  next();
}

setupRouter.use('/setup', requireToken);

// The first-run wizard page (served for a valid token; nonce'd CSP allows the
// inline style/script + same-origin fetches to the setup API).
setupRouter.get('/setup', (_req, res) => {
  const nonce = crypto.randomBytes(16).toString('base64');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader(
    'Content-Security-Policy',
    `default-src 'none'; img-src 'self'; style-src 'nonce-${nonce}'; script-src 'nonce-${nonce}'; ` +
      `connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'`,
  );
  res.type('html').send(renderWizard(nonce));
});

setupRouter.get('/setup/state', (_req, res) => {
  res.json({ complete: isSetupComplete(), configured: isSetupConfigured() });
});

// Step 1 data: which infra values are already in .env (3-state UI) + a freshly
// generated encryption-key candidate when none exists. ?regen=1 rolls the key.
setupRouter.get('/setup/env', (req, res) => {
  if (req.query.regen) regenKek();
  res.json({ configured: isSetupConfigured(), ...readEnvState() });
});

// Account-portal reachability probe for the Site step. Non-blocking (the portal/BFF
// may be brought up AFTER the SSO), so this only INFORMS — it fetches the portal's
// jwks.json (the endpoint the SSO will read the client key from) and reports whether
// it's online + serving keys. Only status/reason is returned, never the body.
setupRouter.get('/setup/probe-portal', async (req, res) => {
  const raw = typeof req.query.url === 'string' ? req.query.url.trim().replace(/\/+$/, '') : '';
  let target: string;
  try {
    if (new URL(raw).protocol !== 'https:') throw new Error('scheme');
    target = raw + '/.well-known/jwks.json';
  } catch {
    res.json({ ok: false, reachable: false, reason: 'bad_url' });
    return;
  }
  try {
    const r = await fetch(target, { signal: AbortSignal.timeout(4000) });
    if (r.status !== 200) {
      res.json({ ok: false, reachable: true, status: r.status, reason: 'no_jwks' });
      return;
    }
    const body = (await r.json().catch(() => null)) as { keys?: unknown[] } | null;
    const hasKeys = !!body && Array.isArray(body.keys) && body.keys.length > 0;
    res.json({ ok: hasKeys, reachable: true, status: 200, reason: hasKeys ? undefined : 'no_keys' });
  } catch (err) {
    res.json({ ok: false, reachable: false, reason: (err as Error).name === 'TimeoutError' ? 'timeout' : 'unreachable' });
  }
});

// Step 1 save: validate → probe DB/Redis → apply schema + write .env + adopt the
// config in-process (no restart). Field errors mirror the client's red-on-blur.
setupRouter.post('/setup/config', async (req, res) => {
  const resolved = resolveInput((req.body ?? {}) as Record<string, unknown>);
  const errors = validateConfig(resolved);
  if (Object.keys(errors).length) {
    res.status(422).json({ errors });
    return;
  }
  const dbErr = await testDb(resolved.databaseUrl);
  if (dbErr) {
    res.status(422).json({ errors: { database: `Could not connect: ${dbErr}` } });
    return;
  }
  const redisErr = await testRedis(resolved.redisUrl);
  if (redisErr) {
    res.status(422).json({ errors: { redis: `Could not connect: ${redisErr}` } });
    return;
  }
  try {
    await applyAndPersist(resolved);
    res.status(204).end();
  } catch (err) {
    console.error('setup/config failed:', err);
    res.status(500).json({ errors: { database: `Setup failed: ${(err as Error).message}` } });
  }
});

// Finish: seed RBAC + create the superadmin + register the account client + persist
// site/email settings + setup_complete, all atomically, then sign the operator in
// and flip out of setup mode. Requires step 1 to have configured the DB.
setupRouter.post('/setup/finish', async (req, res) => {
  if (!isSetupConfigured()) {
    res.status(409).json({ error: 'not_configured' });
    return;
  }
  const input = (req.body ?? {}) as Record<string, unknown>;
  const errors = validateFinish(input);
  if (Object.keys(errors).length) {
    res.status(422).json({ errors });
    return;
  }
  try {
    const { sub } = await runFinishTransaction(input);
    await createSession(res, {
      userSub: sub,
      amr: ['pwd'],
      acr: 'urn:dreamsso:1fa',
      ip: req.ip,
      userAgent: qstr(req.headers['user-agent']),
      country: qstr(req.headers['cf-ipcountry']).trim() || undefined,
    });
    res.status(204).end(); // the wizard navigates to /admin (now unlocked)
  } catch (err) {
    if ((err as { code?: string }).code === '23505') {
      res.status(422).json({ errors: { username: 'That username is already taken.' } });
      return;
    }
    console.error('setup/finish failed:', err);
    res.status(500).json({ error: 'setup_failed', message: (err as Error).message });
  }
});
