import express from 'express';
import cookieParser from 'cookie-parser';
import { config } from './config.js';
import { getSetting, hasSetting } from './settings.js';
import { securityHeaders } from './security.js';
import { wellKnownRouter } from './routes/wellknown.js';
import { authorizeRouter } from './routes/authorize.js';
import { tokenRouter } from './routes/token.js';
import { accountRouter } from './routes/account.js';
import { avatarRouter } from './routes/avatar.js';
import { securityRouter } from './routes/security.js';
import { devicesRouter } from './routes/devices.js';
import { stepupRouter } from './routes/stepup.js';
import { adminRouter } from './routes/admin.js';
import { logoutRouter } from './routes/logout.js';
import { resetRouter } from './routes/reset.js';
import { registerRouter } from './routes/register.js';
import { emailChangeRouter } from './routes/emailChangeRoutes.js';
import { portalTokenRouter } from './routes/portalToken.js';
import { eventsRouter } from './routes/events.js';
import { orgRouter } from './routes/org.js';
import { setupGate, setupRouter } from './routes/setup.js';
import { resolveSetupState, isSetupComplete } from './setup/state.js';
import { ensureSetupToken, SETUP_TOKEN_FILE } from './setup/token.js';
import { startEventPump } from './events.js';
import { sweepInvitations } from './registration.js';
import { pool } from './db.js';
import { redis } from './redis.js';
import { getSigningKey } from './keys.js';
import { cleanExpiredSessions } from './oidc/sessions.js';

const app = express();
app.set('trust proxy', 1); // behind Caddy (dev) / OpenResty (prod)
app.disable('x-powered-by');
// API responses must never be cached or 304-revalidated: no auto-ETag on
// dynamic responses (static assets keep their own), and every JSON body is
// no-store unless the route already set an explicit Cache-Control.
app.set('etag', false);
app.use((_req, res, next) => {
  const json = res.json.bind(res);
  res.json = (body: unknown) => {
    if (!res.get('Cache-Control')) res.set('Cache-Control', 'no-store');
    return json(body);
  };
  next();
});
app.use(securityHeaders);
app.use(cookieParser());
app.use(express.urlencoded({ extended: false }));
app.use(express.json()); // resource APIs (e.g. /account/*) take JSON bodies

// First-run setup gate (mounted before all app routes): while the install is
// incomplete, only /setup (token-gated) and a tiny whitelist are reachable —
// everything else gets the neutral 503. Once complete it's a no-op (and /setup 404s).
app.use(setupGate);
app.use(setupRouter);

// The bare SSO hostname is not a destination — send end users to the account portal.
app.get('/', async (_req, res) =>
  res.redirect((await getSetting('account_portal_url', config.accountPortalUrl))!));

// Public (unauthenticated) settings — for static-HTML apps that need live branding
// (the admin SPA's header/tab title; the account console can consume it later).
app.get('/api/settings/public', async (_req, res) => {
  const [tsSiteKey, tsSecretSet, regEnabled, inviteRequired] = await Promise.all([
    getSetting('turnstile_site_key'),
    hasSetting('turnstile_secret_key'),
    getSetting('enable_registration', 'false'),
    getSetting('require_invitation_code', 'true'),
  ]);
  res.json({
    site_name: await getSetting('site_name', 'DreamSSO'),
    account_portal_url: await getSetting('account_portal_url', config.accountPortalUrl),
    sso_url: config.issuer, // the portal's "Site settings" link -> {sso_url}/admin
    // Turnstile is ON exactly when both keys are set (no toggle). null = the
    // client renders no widget/label and never loads the Turnstile script.
    turnstile_site_key: tsSiteKey && tsSecretSet ? tsSiteKey : null,
    registration_enabled: regEnabled === 'true',
    invitation_required: inviteRequired === 'true',
  });
});
app.use(wellKnownRouter);
app.use(authorizeRouter);
app.use(tokenRouter);
app.use(accountRouter);
app.use(avatarRouter);
app.use(securityRouter);
app.use(devicesRouter);
app.use(stepupRouter);
app.use(adminRouter);
app.use(logoutRouter);
app.use(resetRouter);
app.use(registerRouter);
app.use(emailChangeRouter);
app.use(portalTokenRouter);
app.use(eventsRouter);
app.use(orgRouter);

app.get('/healthz', async (_req, res) => {
  try {
    await pool.query('SELECT 1');
    await redis.ping();
    res.json({ status: 'ok', db: 'up', redis: 'up', issuer: config.issuer });
  } catch (err) {
    res.status(503).json({ status: 'degraded', error: (err as Error).message });
  }
});

async function main() {
  await resolveSetupState();

  // First-run: boot in setup mode (no DB writes, no pumps) and serve only /setup.
  if (!isSetupComplete()) {
    const token = ensureSetupToken();
    app.listen(config.port, () => {
      console.log(`DreamSSO — FIRST-RUN SETUP on :${config.port}`);
      console.log(`  open:  /setup?token=${token}`);
      console.log(`  token: ${SETUP_TOKEN_FILE}`);
    });
    return;
  }

  const { kid } = await getSigningKey();
  // DB backstop: prune sessions past the idle/absolute windows (hourly + at boot).
  cleanExpiredSessions();
  setInterval(cleanExpiredSessions, 60 * 60 * 1000).unref();
  // Expired unused invitation codes die by the hour; consumed rows are forever.
  sweepInvitations();
  setInterval(sweepInvitations, 60 * 60 * 1000).unref();
  startEventPump(); // boot drain + 60s retry sweep + archive pruning
  app.listen(config.port, () => {
    console.log(`DreamSSO listening on :${config.port} — issuer ${config.issuer} — signing kid ${kid}`);
  });
}

main().catch((err) => {
  console.error('Fatal boot error:', err);
  process.exit(1);
});
