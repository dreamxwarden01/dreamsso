import express from 'express';
import type { Request, Response, NextFunction } from 'express';
import crypto from 'node:crypto';
import { config, isConfigured } from '../config.js';
import { isSetupComplete, markComplete } from '../setup/state.js';
import { verifySetupToken, clearSetupToken } from '../setup/token.js';
import { renderUnavailablePage, AUTH_BG_SVG } from '../setup/views.js';
import { renderWizard } from '../setup/wizard.js';
import {
  readEnvState,
  resolveInput,
  validateConfig,
  testRedis,
  probeSso,
  applyAndPersist,
  derived,
} from '../setup/config.js';
import * as mtls from '../mtls.js';

export const setupRouter = express.Router();

// Paths that stay reachable while setup is incomplete (besides /setup*).
const OPEN_PATHS = new Set(['/healthz']);

// The neutral pre-setup response for anything not explicitly allowed — the same
// page an attacker sees at /setup without a token, so the wizard is never
// advertised (no config hint, no CTA).
function serveUnavailable(res: Response): void {
  const nonce = crypto.randomBytes(16).toString('base64');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader(
    'Content-Security-Policy',
    `default-src 'none'; style-src 'nonce-${nonce}'; base-uri 'none'; frame-ancestors 'none'`,
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
  // A valid ?token= drops a scoped cookie so the wizard's own fetches (and the
  // background image) don't need it in the URL.
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

// Bloom backdrop for the wizard + the unavailable page. Under /setup so the token
// cookie covers it and it disappears with the rest of the wizard.
setupRouter.get('/setup/bg.svg', (_req, res) => {
  res.type('image/svg+xml').set('Cache-Control', 'public, max-age=3600').send(AUTH_BG_SVG);
});

setupRouter.get('/setup/state', (_req, res) => {
  res.json({ complete: isSetupComplete(), configured: isConfigured() });
});

// Step 1 data: which values are already in .env (3-state UI) + whether we already
// hold an OIDC client key.
setupRouter.get('/setup/env', (_req, res) => {
  res.json({ configured: isConfigured(), ...readEnvState() });
});

// SSO reachability probe for the config step. Non-blocking (the SSO may legitimately
// be brought up after the portal), so this only INFORMS — it reads the discovery
// document and checks that the `issuer` it advertises is the one we were given.
setupRouter.get('/setup/probe-sso', async (req, res) => {
  res.json(await probeSso(typeof req.query.url === 'string' ? req.query.url.trim() : ''));
});

// Step 1 save: validate → probe Redis → mint the client key + write .env + adopt the
// config in-process (no restart). Field errors mirror the client's red-on-blur.
setupRouter.post('/setup/config', async (req, res) => {
  const resolved = resolveInput((req.body ?? {}) as Record<string, unknown>);
  const errors = validateConfig(resolved);
  if (Object.keys(errors).length) {
    res.status(422).json({ errors });
    return;
  }
  const redisErr = await testRedis(resolved.redisUrl);
  if (redisErr) {
    res.status(422).json({ errors: { redis: `Could not connect: ${redisErr}` } });
    return;
  }
  try {
    const key = await applyAndPersist(resolved);
    res.json({ ...key, clientId: config.clientId, ...derived(resolved.publicUrl) });
  } catch (err) {
    console.error('setup/config failed:', err);
    res.status(500).json({ errors: { publicUrl: `Setup failed: ${(err as Error).message}` } });
  }
});

// --- mTLS client certificate (optional step) --------------------------------
// The portal presents this cert on every S2S call to the SSO once the edge enforces
// mTLS. It's skippable here: nothing breaks without it until enforcement is turned
// on at Cloudflare, and the same generate → CSR → install flow can be re-run later.

setupRouter.get('/setup/mtls', (_req, res) => {
  res.json(mtls.getStatus());
});

// Generate an ECDSA P-256 key (kept here, never leaves) + the PKCS#10 CSR to paste
// into Cloudflare. Re-callable: a fresh CSR simply supersedes the pending key.
setupRouter.post('/setup/mtls/start', async (req, res) => {
  const cn = typeof (req.body ?? {}).cn === 'string' ? (req.body.cn as string) : undefined;
  try {
    res.json(await mtls.startSetup(cn));
  } catch (err) {
    console.error('setup/mtls/start failed:', err);
    res.status(500).json({ error: 'csr_failed' });
  }
});

// Install the issued certificate (leaf, or a full chain in any order). Validated
// against the key we hold; a valid install auto-enables enforcement.
setupRouter.post('/setup/mtls/install', (req, res) => {
  const cert = typeof (req.body ?? {}).cert === 'string' ? (req.body.cert as string) : '';
  const result = mtls.installCert(cert);
  if (!result.ok) {
    res.status(422).json({ error: 'invalid_cert', reason: result.reason });
    return;
  }
  res.json({ ok: true, ...mtls.getStatus() });
});

setupRouter.post('/setup/mtls/reset', (_req, res) => {
  mtls.reset();
  res.status(204).end();
});

// Finish: flip the latch and burn the token. From here the gate is a no-op, /setup
// 404s, and the portal serves the SPA. Requires the config step to have run.
setupRouter.post('/setup/finish', (_req, res) => {
  if (!isConfigured()) {
    res.status(409).json({ error: 'not_configured' });
    return;
  }
  markComplete();
  clearSetupToken();
  res.status(204).end();
});
