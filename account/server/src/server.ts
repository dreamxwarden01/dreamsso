import {ServiceLifecycle,installShutdownSignals,safeLifecycleError} from './lifecycle.js';
import {closeS2SFetch,destroyS2SFetch} from './s2sFetch.js';
import {stopClientKeyWorkers,killClientKeyWorkers} from './client-key-state.js';
import express from 'express';
import cookieParser from 'cookie-parser';
import fs from 'node:fs';
import path from 'node:path';
import { createRemoteJWKSet } from 'jose';
import {createClientKeyRouter} from './routes/client-key.js';
import { config } from './config.js';
import { redis } from './redis.js';
import {rotateClientKey,clientKeyStatus,publicClientJwks} from './oidc.js';
import { authRouter } from './routes/auth.js';
import { apiRouter } from './routes/api.js';
import { backchannelRouter } from './routes/backchannel.js';
import { resetRouter } from './routes/reset.js';
import {createAccountJwksRouter} from './routes/jwks.js';
import { registerRouter } from './routes/register.js';
import { setupGate, setupRouter } from './routes/setup.js';
import { resolveSetupState, isSetupComplete } from './setup/state.js';
import { ensureSetupToken, clearSetupToken, SETUP_TOKEN_FILE } from './setup/token.js';

const lifecycle=new ServiceLifecycle({
 quiesce:()=>{},drain:stopClientKeyWorkers,
 close:async()=>{const results=await Promise.allSettled([closeS2SFetch(),redis.quit()]);if(results.some(result=>result.status==='rejected'))throw Error('Client cleanup failed.');},
 force:()=>{killClientKeyWorkers();redis.disconnect();destroyS2SFetch();},
 exit:code=>process.exit(code),report:code=>console.warn('Account lifecycle: '+code),
});
installShutdownSignals(lifecycle);
const app = express();
app.use((_req,res,next)=>{if(lifecycle.stopping){res.set({'Connection':'close','Cache-Control':'no-store'}).status(503).json({error:'service_stopping'});return;}next();});
app.set('trust proxy', 1); // behind Caddy (dev) / OpenResty (prod)
app.disable('x-powered-by');
// API responses must never be cached or 304-revalidated: no auto-ETag on
// dynamic responses (express.static keeps its own for the hashed bundles),
// and every JSON body is no-store unless a route set an explicit header.
app.set('etag', false);
app.use((_req, res, next) => {
  const json = res.json.bind(res);
  res.json = (body: unknown) => {
    if (!res.get('Cache-Control')) res.set('Cache-Control', 'no-store');
    return json(body);
  };
  next();
});
app.use(cookieParser());
// Baseline headers + a SPA-friendly CSP. HSTS is owned at the edge (like the SSO).
app.use((_req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('X-XSS-Protection', '0');
  // challenges.cloudflare.com: the Turnstile widget on /forgot (script + iframe).
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; " +
      "script-src 'self' https://challenges.cloudflare.com; connect-src 'self'; font-src 'self' data:; " +
      "frame-src https://challenges.cloudflare.com; " +
      "base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
  );
  next();
});

// Public key methods are resolved before parsers, including malformed non-GET bodies.
// This route applies the same setup gate before reading any key material.
app.use(createAccountJwksRouter(async()=>JSON.stringify(await publicClientJwks()),setupGate));

// rawBody: the edge gate signs a hash of the exact body BYTES it forwards —
// verification must hash what we received, not a re-serialization.
app.use(express.json({
  verify: (req, _res, buf) => { (req as express.Request & { rawBody?: Buffer }).rawBody = buf; },
}));
app.use(express.urlencoded({ extended: false }));

// The remaining routes use the same first-run gate as JWKS above: until configured,
// nothing but /setup (token-gated) and /healthz answers — everything else gets a
// neutral 503. Once configured it's a no-op and /setup 404s.
app.use(setupGate);
app.use(setupRouter);

// SSO-triggered client-key rotation (the "Rotate client key" button on the
// SSO admin's Account-portal card). The key is RP-owned, so the SSO can't
// rotate it — it asks us to, with a short-lived signed request verified
// against ITS keys (same trust as the back-channel), jti replay-guarded.
// Built on first use: config.internal is empty until the wizard runs, and
// `new URL('' + '/jwks')` would throw at import.
let _ssoJwks: ReturnType<typeof createRemoteJWKSet> | undefined;
const ssoJwks = () => (_ssoJwks ??= createRemoteJWKSet(new URL(config.internal + '/jwks')));
app.use(createClientKeyRouter({
  issuer:()=>config.issuer,audience:()=>config.clientId,
  verificationKey:(header,token)=>ssoJwks()(header,token),
  claimNonce:async key=>(await redis.set(key,'1','EX',300,'NX'))==='OK',
  schedule:rotateClientKey,status:clientKeyStatus,
}));

app.get('/healthz', async (_req, res) => {
  try {
    await redis.ping();
    res.setHeader('Cache-Control', 'no-store');
    res.json({ status: 'ok', client: config.clientId, issuer: config.issuer });
  } catch (err) {
    res.status(503).json({ status: 'degraded', error: (err as Error).message });
  }
});

app.use(authRouter);
app.use(apiRouter);
app.use(resetRouter); // public: no session required (the /forgot + /reset pages)
app.use(registerRouter); // public: /register/start + /register/complete
app.use(backchannelRouter); // before the SPA fallback (POST, no /api or /auth prefix)

// --- serve the built SPA (client/dist) with a client-side-routing fallback ---
const indexHtml = path.join(config.spaDist, 'index.html');

// Legacy /favicon.ico (auto-requested by browsers, bookmarks, tab restore) -> the
// SVG icon so it never 404s; the 301 is itself cacheable.
app.get('/favicon.ico', (_req, res) => res.redirect(301, '/favicon.svg'));

app.use(express.static(config.spaDist, {
  index: false,
  setHeaders: (res, filePath) => {
    // Vite content-hashes everything under /assets, so those bundles can cache
    // forever; unhashed root files (favicon.svg, auth-bg.svg) get a day so an
    // update still propagates.
    res.setHeader(
      'Cache-Control',
      filePath.includes(`${path.sep}assets${path.sep}`)
        ? 'public, max-age=31536000, immutable'
        : 'public, max-age=86400',
    );
  },
}));

// Express 5: no string '*' route — a final middleware handles the SPA fallback.
app.use((req, res) => {
  if (req.method !== 'GET') return res.status(404).json({ error: 'not_found' });
  if (req.path.startsWith('/api/') || req.path.startsWith('/auth/')) {
    return res.status(404).json({ error: 'not_found' });
  }
  // Only client-routes (extensionless) get index.html. A missing asset/probe like
  // /favicon.ico must 404 here, not be served the HTML shell as text/html.
  if ((req.path.split('/').pop() || '').includes('.')) {
    return res.status(404).json({ error: 'not_found' });
  }
  // The shell references content-hashed bundles, so a short cache is safe and
  // lets a deploy roll out within ~2 min without a hard reload.
  if (fs.existsSync(indexHtml)) return res.sendFile(indexHtml, { maxAge: 120_000 });
  res
    .status(200)
    .type('html')
    .send(
      '<!doctype html><meta charset="utf-8"><title>account console</title>' +
        '<body style="font-family:-apple-system,system-ui,sans-serif;max-width:560px;margin:12vh auto;padding:0 20px;color:#1f2937">' +
        '<h1 style="font-size:20px">Account console BFF is up</h1>' +
        '<p style="color:#6b7280">The SPA bundle isn\'t built yet. Build it with ' +
        '<code>npm --prefix account/client install &amp;&amp; npm --prefix account/client run build</code>, ' +
        'or run Vite for HMR.</p></body>',
    );
});

function main(): void {
  resolveSetupState();

  // First-run: boot in setup mode. The gate answers everything with a neutral 503
  // except the token-locked wizard, which writes .env + the client key and flips
  // the latch in-process (no restart).
  if (!isSetupComplete()) {
    const token = ensureSetupToken();
    lifecycle.listen(()=>app.listen(config.port, () => {
      console.log(`account portal — FIRST-RUN SETUP on :${config.port}`);
      console.log(`  open:  /setup?token=${token}`);
      console.log(`  token: ${SETUP_TOKEN_FILE}`);
    }));
    return;
  }

  // Configured: no wizard, so no lock. Drops a token left behind by an install that
  // was interrupted between the config step and finish (the portal is usable either
  // way — the latch derives from .env + the client key).
  clearSetupToken();
  lifecycle.listen(()=>app.listen(config.port, () => {
    console.log(`account BFF listening on :${config.port} — RP ${config.clientId} @ ${config.issuer}`);
  }));
}

lifecycle.boot(main).catch(error=>{
 console.error('Account startup failed: '+safeLifecycleError(error));
 void lifecycle.stop(1);
});
