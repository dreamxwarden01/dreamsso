import crypto from 'node:crypto';
import path from 'node:path';
import fs from 'node:fs';
import express, { Router, type Request, type Response, type NextFunction } from 'express';
import { pool } from '../db.js';
import { redis } from '../redis.js';
import { config } from '../config.js';
import { loadSession, isStepupFresh, type ActiveSession } from '../oidc/sessions.js';
import { acceptedStepupMethods, stepupSatisfies } from '../oidc/stepupPolicy.js';
import { createTxn } from '../oidc/transactions.js';
import { hasPerm } from '../rbac/index.js';
import { countAuthenticators } from '../mfa.js';
import { countPasskeys } from '../webauthn.js';
import { getJwks, rotateSigningKey, getSigningKey } from '../keys.js';
import { SignJWT } from 'jose';
import { s2sFetch } from '../s2sFetch.js';
import * as mtls from '../mtls.js';
import { renderErrorPage } from '../views.js';
import {
  normalizeHostname, normalizePath, normalizeSlug, normalizeName, composeUrl, decomposeUrl,
} from '../clientNormalize.js';
import { getSetting, setSetting, setSecretSetting, hasSetting } from '../settings.js';
import { enqueueEvents } from '../events.js';
import { sendEmail } from '../email.js';
import { renderTestEmail } from '../emailTemplates.js';

// The SSO admin panel's API (/admin/api/*) — infrastructure administration:
// OIDC client registry, signing keys, settings. Same-origin with the SSO, so it
// authenticates with the MASTER SESSION COOKIE directly (no OIDC dance, no BFF),
// gated by org.siteSettings.sso. Mutations require the CSRF token issued by
// /admin/api/me (synchronizer token in the response body, echoed in a header —
// same principle as the login form's hidden field).
export const adminRouter = Router();

interface AdminRequest extends Request {
  adminSession?: ActiveSession;
}

const CSRF_KEY = (sid: string) => `admin:csrf:${sid}`;
const CSRF_TTL = 60 * 60 * 12; // matches the master session's 12h

async function requireAdmin(req: AdminRequest, res: Response, next: NextFunction): Promise<void> {
  const session = await loadSession(req);
  if (!session) {
    res.status(401).json({ error: 'unauthenticated' });
    return;
  }
  if (!(await hasPerm(session.userSub, 'org.siteSettings.sso'))) {
    res.status(403).json({ error: 'permission_denied', permission: 'org.siteSettings.sso' });
    return;
  }
  req.adminSession = session;
  next();
}

async function requireCsrf(req: AdminRequest, res: Response, next: NextFunction): Promise<void> {
  const token = req.headers['x-csrf-token'];
  const expected = await redis.get(CSRF_KEY(req.adminSession!.sid));
  if (!expected || typeof token !== 'string' || token !== expected) {
    res.status(403).json({ error: 'csrf_failed' });
    return;
  }
  next();
}

function htmlNonce(res: Response): string {
  const nonce = crypto.randomBytes(16).toString('base64');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader(
    'Content-Security-Policy',
    `default-src 'none'; style-src 'nonce-${nonce}'; base-uri 'none'; frame-ancestors 'none'`,
  );
  return nonce;
}

// The console SPA (Vite build). Assets are public (bundles aren't secrets — the
// data is behind /admin/api); the SHELL is gated like any app's front door.
const ADMIN_DIST = path.resolve(process.cwd(), 'admin-ui/dist');
adminRouter.use('/admin/assets', express.static(path.join(ADMIN_DIST, 'assets'), { immutable: true, maxAge: '1y' }));

// GET /admin (+ the SPA's client-side routes) — gated like any app: no session ->
// login bounce (landing back here), no permission -> styled denial, else the shell.
adminRouter.get(['/admin', '/admin/clients', '/admin/clients/:id', '/admin/keys', '/admin/settings'],
  async (req: Request, res: Response) => {
    const session = await loadSession(req);
    if (!session) return res.redirect('/admin/start-login');
    const siteName = (await getSetting('site_name', 'DreamSSO'))!;
    if (!(await hasPerm(session.userSub, 'org.siteSettings.sso'))) {
      const nonce = htmlNonce(res);
      return res.status(403).send(renderErrorPage(nonce, {
        title: 'No access',
        message: `You don't have access to the ${siteName} admin console. Contact your administrator if you believe this is a mistake.`,
        code: 'permission_denied',
        siteName,
      }));
    }
    // Step-up door: the console requires a fresh sudo window (setting-controlled,
    // OFF by default). STRONG-MANDATORY — passkey/totp per the admin's owned
    // factors (passkey preempts totp), fresh AND the recorded method matches; a
    // strong-factor login pre-clears it, so this fires when the stamp is absent,
    // aged out, or was a weaker method (e.g. a password-only login).
    if ((await getSetting('stepup_admin_required', 'false')) === 'true') {
      const { accepted: methods, enroll_required } = await acceptedStepupMethods(session.userSub, 'strong-mandatory');
      const fresh = await isStepupFresh(session.stepupAt);
      if (!stepupSatisfies(methods, session.stepupMethod, fresh)) {
        if (enroll_required) {
          // Links + names come from settings — never hardcoded.
          const portal = (await getSetting('account_portal_url', config.accountPortalUrl))!;
          const nonce = htmlNonce(res);
          return res.status(403).send(renderErrorPage(nonce, {
            title: 'Verification required',
            message: `The ${siteName} admin console requires a passkey or authenticator app. Add one in your account's Security settings, then come back.`,
            code: 'stepup_enroll_required',
            siteName,
            action: { href: portal + '/security', label: 'Open the account portal' },
          }));
        }
        const { rows: [id] } = await pool.query(
          'SELECT username, display_name FROM identities WHERE sub = $1',
          [session.userSub],
        );
        const next = req.path.startsWith('/admin') ? req.path : '/admin';
        const txnId = await createTxn({
          clientId: '', redirectUri: '', codeChallenge: '', codeChallengeMethod: '', scope: '',
          clientName: `${siteName} Admin`, localNext: next,
          mfa: {
            sub: session.userSub,
            // Step-up = already authenticated -> show the display name (fallback username).
            userLabel: id?.display_name || id?.username || 'your account',
            methods,
            attempts: 0,
            stepupSid: session.sid,
          },
        });
        return res.redirect(`/login?txn=${encodeURIComponent(txnId)}`);
      }
    }

    const index = path.join(ADMIN_DIST, 'index.html');
    if (!fs.existsSync(index)) {
      const nonce = htmlNonce(res);
      return res.status(200).send(renderErrorPage(nonce, {
        title: `${siteName} Admin`,
        message: 'The console UI is not built yet (admin-ui: npm run build) — the admin API is live.',
        code: 'shell_missing',
        siteName,
      }));
    }
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader(
      'Content-Security-Policy',
      "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'",
    );
    res.sendFile(index);
  });

// GET /admin/start-login — local first-party login bounce for the panel. No OIDC
// client: the txn carries a local `next` path and POST /login just opens a session.
adminRouter.get('/admin/start-login', async (req: Request, res: Response) => {
  const raw = typeof req.query.next === 'string' ? req.query.next : '/admin';
  const next = raw.startsWith('/') && !raw.startsWith('//') ? raw : '/admin';
  const txnId = await createTxn({
    clientId: '', redirectUri: '', codeChallenge: '', codeChallengeMethod: '', scope: '',
    clientName: `${(await getSetting('site_name', 'DreamSSO'))!} Admin`, localNext: next,
  });
  res.redirect(`/login?txn=${encodeURIComponent(txnId)}`);
});

adminRouter.use('/admin/api', requireAdmin);

// When the admin step-up door is on, MUTATIONS demand a fresh sudo window too —
// the shell redirect only protects page entry; without this, a live session +
// CSRF token could keep mutating long after the window lapsed. GETs stay open
// (the door still gates the shell). The SPA reacts to 403 step_up_required by
// reloading through the shell, which routes into the challenge and back.
adminRouter.use('/admin/api', async (req: AdminRequest, res: Response, next: NextFunction) => {
  if (req.method === 'GET') return next();
  if ((await getSetting('stepup_admin_required', 'false')) !== 'true') return next();
  const { accepted } = await acceptedStepupMethods(req.adminSession!.userSub, 'strong-mandatory');
  const fresh = await isStepupFresh(req.adminSession!.stepupAt);
  if (!stepupSatisfies(accepted, req.adminSession!.stepupMethod, fresh)) {
    return res.status(403).json({ error: 'step_up_required' });
  }
  next();
});

// GET /admin/api/me — who am I + the CSRF token for mutations.
adminRouter.get('/admin/api/me', async (req: AdminRequest, res: Response) => {
  const s = req.adminSession!;
  const { rows: [id] } = await pool.query(
    'SELECT username, display_name, email, avatar FROM identities WHERE sub = $1',
    [s.userSub],
  );
  let csrf = await redis.get(CSRF_KEY(s.sid));
  if (!csrf) {
    csrf = crypto.randomBytes(24).toString('base64url');
    await redis.set(CSRF_KEY(s.sid), csrf, 'EX', CSRF_TTL);
  }
  res.json({
    username: id?.username,
    display_name: id?.display_name,
    email: id?.email ?? null,
    avatar: id?.avatar ?? null,
    portal: (await getSetting('account_portal_url', config.accountPortalUrl))!,
    csrf,
  });
});

// --- OIDC client registry ---
// The API works in the same decomposed model as the form: ONE https hostname +
// relative paths; full URLs are composed server-side into the stored columns, so
// the /authorize exact-match layer is untouched. Normalization/validation comes
// from the SHARED module (src/clientNormalize.ts) the SPA also imports.

const SCOPES = ['openid', 'profile', 'email'];
// jwks_uri stays a full URL at the API (install-time bootstrap may point anywhere;
// http allowed for loopback only — local dev / tests).
const isUrl = (v: unknown): boolean => {
  if (typeof v !== 'string') return false;
  try {
    const u = new URL(v);
    if (u.protocol === 'https:') return true;
    return u.protocol === 'http:' && (u.hostname === 'localhost' || u.hostname === '127.0.0.1');
  } catch {
    return false;
  }
};

interface ClientInput {
  name: string;
  hostname: string;
  redirect_paths: string[];
  events_path: string | null;
  jwks_uri: string | null;
  jwks: { keys: unknown[] } | null;
  allowed_scopes: string[];
  is_first_party: boolean;
  entry_policy: 'opt_in' | 'baseline';
}

// Normalize + validate the full decomposed shape (PATCH merges over the current
// row first, so validation always sees the complete picture).
function validateClientInput(body: Record<string, unknown>): { errors: Record<string, string>; value: ClientInput } {
  const errors: Record<string, string> = {};
  const v = {} as ClientInput;

  const name = normalizeName(typeof body.name === 'string' ? body.name : '');
  if (name.error) errors.name = name.error;
  v.name = name.value;

  const host = normalizeHostname(typeof body.hostname === 'string' ? body.hostname : '');
  if (host.error) errors.hostname = host.error;
  v.hostname = host.value;

  if (!Array.isArray(body.redirect_paths) || body.redirect_paths.length === 0) {
    errors.redirect_paths = 'At least one redirect path';
    v.redirect_paths = [];
  } else {
    v.redirect_paths = [];
    for (const [i, raw] of body.redirect_paths.entries()) {
      const p = normalizePath(typeof raw === 'string' ? raw : '', v.hostname, { required: true });
      if (p.error) errors[`redirect_paths.${i}`] = p.error;
      v.redirect_paths.push(p.value);
    }
  }

  const bc = normalizePath(typeof body.events_path === 'string' ? body.events_path : '', v.hostname);
  if (bc.error) errors.events_path = bc.error;
  v.events_path = bc.value || null;

  if (body.jwks_uri != null && !isUrl(body.jwks_uri)) errors.jwks_uri = 'Valid https:// URL or null';
  v.jwks_uri = (body.jwks_uri as string) ?? null;

  const jwks = body.jwks as { keys?: unknown[] } | null | undefined;
  if (jwks != null && !(typeof jwks === 'object' && Array.isArray(jwks.keys) && jwks.keys.length > 0)) {
    errors.jwks = 'JWKS object with a non-empty keys array, or null';
  }
  v.jwks = (jwks as { keys: unknown[] }) ?? null;
  if (!v.jwks_uri && !v.jwks && !errors.jwks_uri && !errors.jwks) {
    errors.jwks = 'Provide jwks_uri or an inline JWKS (the client cannot authenticate without a key)';
  }

  if (!Array.isArray(body.allowed_scopes) || body.allowed_scopes.length === 0 ||
      !body.allowed_scopes.every((s) => SCOPES.includes(s as string))) {
    errors.allowed_scopes = `Subset of: ${SCOPES.join(', ')}`;
  }
  v.allowed_scopes = (body.allowed_scopes as string[]) ?? SCOPES;

  if (typeof body.is_first_party !== 'boolean') errors.is_first_party = 'Must be boolean';
  v.is_first_party = body.is_first_party as boolean;

  if (body.entry_policy !== 'opt_in' && body.entry_policy !== 'baseline') errors.entry_policy = 'opt_in or baseline';
  v.entry_policy = body.entry_policy as 'opt_in' | 'baseline';

  return { errors, value: v };
}

// Registration-time key fetch — the "confirm" step of the install flow: the app
// is expected to be live and serving its JWKS BEFORE it's registered here, so a
// jwks_uri that can't produce keys right now is a config error, not a race.
// (Install-time bootstrap for a not-yet-live app = paste the inline JWKS instead.)
// On success the fetched JWKS is returned and stored alongside the uri as a
// snapshot: jwks_uri non-null = automatic fetch active (what /token prefers),
// while the snapshot gives the edit form's paste view real content — saving in
// paste mode then pins those keys and clears the uri (fetch off).
async function verifyJwksUri(url: string): Promise<{ error: string | null; jwks?: { keys: unknown[] } }> {
  try {
    const r = await fetch(url, { headers: { accept: 'application/json' }, signal: AbortSignal.timeout(3000) });
    if (!r.ok) return { error: `JWKS fetch failed (HTTP ${r.status})` };
    const j = (await r.json().catch(() => null)) as { keys?: unknown[] } | null;
    if (!j || !Array.isArray(j.keys) || j.keys.length === 0) return { error: 'URL did not return a JWKS with keys' };
    return { error: null, jwks: j as { keys: unknown[] } };
  } catch {
    return { error: 'Could not reach the JWKS URL' };
  }
}

interface ClientRow {
  client_id: string;
  name: string;
  is_first_party: boolean;
  entry_policy: string;
  redirect_uris: string[];
  events_uri: string | null;
  jwks_uri: string | null;
  jwks: { keys: unknown[] } | null;
  has_inline_jwks: boolean;
  allowed_scopes: string[];
  is_system: boolean;
  disabled_at: string | null;
  created_at: string;
  updated_at: string;
}

// Derive the decomposed form-model from the stored full URLs.
function decomposeRow(row: ClientRow) {
  let hostname = '';
  try {
    hostname = new URL(row.redirect_uris[0]).hostname.toLowerCase();
  } catch { /* empty registration */ }
  return {
    ...row,
    hostname,
    redirect_paths: row.redirect_uris.map((u) => decomposeUrl(u, hostname)).filter((p): p is string => p != null),
    events_path: row.events_uri ? decomposeUrl(row.events_uri, hostname) : null,
  };
}

// jwks is PUBLIC key material — returned so the edit form can display the
// registered key instead of an empty paste box.
const CLIENT_COLS = `client_id, name, is_first_party, entry_policy, redirect_uris,
  events_uri, jwks_uri, jwks, (jwks IS NOT NULL) AS has_inline_jwks,
  allowed_scopes, is_system, disabled_at, created_at, updated_at`;

adminRouter.get('/admin/api/clients', async (_req: AdminRequest, res: Response) => {
  const { rows } = await pool.query<ClientRow>(`SELECT ${CLIENT_COLS} FROM oauth_clients ORDER BY created_at`);
  res.json({ clients: rows.map(decomposeRow) });
});

adminRouter.post('/admin/api/clients', requireCsrf, async (req: AdminRequest, res: Response) => {
  const body = (req.body ?? {}) as Record<string, unknown>;
  const { errors, value } = validateClientInput(body);
  // client_id: username-like slug, immutable after creation (it's the PK and it's
  // baked into the RP's own config).
  const slug = normalizeSlug(typeof body.client_id === 'string' ? body.client_id : '');
  if (slug.error) errors.client_id = slug.error;
  if (Object.keys(errors).length) return res.status(422).json({ errors });

  // Confirm the registration by actually fetching the client's key; keep the
  // result as the inline snapshot.
  if (value.jwks_uri) {
    const fetched = await verifyJwksUri(value.jwks_uri);
    if (fetched.error) return res.status(422).json({ errors: { jwks_uri: fetched.error } });
    value.jwks = fetched.jwks!;
  }

  try {
    const { rows } = await pool.query<ClientRow>(
      `INSERT INTO oauth_clients
         (client_id, name, is_first_party, entry_policy, redirect_uris,
          events_uri, jwks_uri, jwks, allowed_scopes)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
       RETURNING ${CLIENT_COLS}`,
      [slug.value, value.name, value.is_first_party, value.entry_policy,
       value.redirect_paths.map((p) => composeUrl(value.hostname, p)),
       value.events_path ? composeUrl(value.hostname, value.events_path) : null,
       value.jwks_uri, value.jwks, value.allowed_scopes],
    );
    res.status(201).json({ client: decomposeRow(rows[0]) });
  } catch (err) {
    if ((err as { code?: string }).code === '23505') {
      return res.status(409).json({ error: 'client_id_taken' });
    }
    console.error('create client failed:', (err as Error).message);
    res.status(500).json({ error: 'server_error' });
  }
});

// PATCH: merge the provided fields over the current row's decomposed model, then
// validate the COMPLETE shape — so a hostname change re-validates every path, and
// a path change is checked against the effective hostname.
adminRouter.patch('/admin/api/clients/:id', requireCsrf, async (req: AdminRequest, res: Response) => {
  const { rows: cur } = await pool.query<ClientRow>(
    `SELECT ${CLIENT_COLS} FROM oauth_clients WHERE client_id = $1`,
    [req.params.id],
  );
  if (!cur[0]) return res.status(404).json({ error: 'not_found' });
  const current = decomposeRow(cur[0]);
  const body = (req.body ?? {}) as Record<string, unknown>;
  const merged: Record<string, unknown> = {
    name: current.name,
    hostname: current.hostname,
    redirect_paths: current.redirect_paths,
    events_path: current.events_path,
    jwks_uri: current.jwks_uri,
    jwks: cur[0].jwks,
    allowed_scopes: current.allowed_scopes,
    is_first_party: current.is_first_party,
    entry_policy: current.entry_policy,
    ...body,
  };
  const { errors, value } = validateClientInput(merged);
  if (Object.keys(errors).length) return res.status(422).json({ errors });

  // Re-confirm the key only when the jwks_uri actually changed; the fetch
  // result refreshes the inline snapshot.
  if (body.jwks_uri !== undefined && value.jwks_uri && value.jwks_uri !== current.jwks_uri) {
    const fetched = await verifyJwksUri(value.jwks_uri);
    if (fetched.error) return res.status(422).json({ errors: { jwks_uri: fetched.error } });
    value.jwks = fetched.jwks!;
  }

  await pool.query(
    `UPDATE oauth_clients SET
       name = $2, is_first_party = $3, entry_policy = $4, redirect_uris = $5,
       events_uri = $6, jwks_uri = $7, jwks = $8, allowed_scopes = $9
     WHERE client_id = $1`,
    [req.params.id, value.name, value.is_first_party, value.entry_policy,
     value.redirect_paths.map((p) => composeUrl(value.hostname, p)),
     value.events_path ? composeUrl(value.hostname, value.events_path) : null,
     value.jwks_uri, value.jwks, value.allowed_scopes],
  );
  res.status(204).end();
});

// POST /admin/api/clients/:id/request-role-sync — the manual refresh: ask the
// RP (roles.sync_request through the event channel, coalesced) to push its
// latest role catalog. The reply lands asynchronously in app_roles.
adminRouter.post('/admin/api/clients/:id/request-role-sync', requireCsrf, async (req: AdminRequest, res: Response) => {
  const { rows: [client] } = await pool.query(
    'SELECT client_id, events_uri, disabled_at FROM oauth_clients WHERE client_id = $1',
    [req.params.id],
  );
  if (!client) return res.status(404).json({ error: 'not_found' });
  if (client.disabled_at) return res.status(409).json({ error: 'client_disabled' });
  if (!client.events_uri) return res.status(409).json({ error: 'no_events_endpoint' });
  await enqueueEvents(client.client_id, [{ type: 'roles.sync_request', payload: {} }]);
  res.status(204).end();
});

// GET /admin/api/clients/:id/role-catalog — channel visibility: the mirrored
// catalog + sync freshness (the Org UI's role list reads this too).
adminRouter.get('/admin/api/clients/:id/role-catalog', async (req: AdminRequest, res: Response) => {
  const { rows: [cat] } = await pool.query(
    'SELECT default_role_id, synced_at FROM app_role_catalogs WHERE client_id = $1',
    [req.params.id],
  );
  // Sort: higher privilege (smaller level) first; ties by role_id.
  const { rows: roles } = await pool.query(
    'SELECT role_id, name, level, is_system FROM app_roles WHERE client_id = $1 ORDER BY level ASC, role_id ASC',
    [req.params.id],
  );
  res.json({
    synced_at: cat?.synced_at ?? null,
    default_role_id: cat?.default_role_id ?? null,
    roles,
  });
});

adminRouter.post('/admin/api/clients/:id/disable', requireCsrf, async (req: AdminRequest, res: Response) => {
  // System clients (the account portal) are part of the SSO itself — disabling
  // one would lock everyone out of their own account management.
  const { rowCount } = await pool.query(
    'UPDATE oauth_clients SET disabled_at = now() WHERE client_id = $1 AND disabled_at IS NULL AND NOT is_system',
    [req.params.id],
  );
  if (!rowCount) {
    const { rows } = await pool.query('SELECT is_system FROM oauth_clients WHERE client_id = $1', [req.params.id]);
    return res.status(rows[0]?.is_system ? 409 : 404).json({ error: rows[0]?.is_system ? 'system_client' : 'not_found' });
  }
  res.status(204).end();
});

adminRouter.post('/admin/api/clients/:id/enable', requireCsrf, async (req: AdminRequest, res: Response) => {
  const { rowCount } = await pool.query(
    'UPDATE oauth_clients SET disabled_at = NULL WHERE client_id = $1 AND disabled_at IS NOT NULL',
    [req.params.id],
  );
  if (!rowCount) return res.status(404).json({ error: 'not_found' });
  res.status(204).end();
});

// Permanent delete — only from the disabled state (the UI shows a strong warning).
adminRouter.delete('/admin/api/clients/:id', requireCsrf, async (req: AdminRequest, res: Response) => {
  const { rows } = await pool.query('SELECT disabled_at, is_system FROM oauth_clients WHERE client_id = $1', [req.params.id]);
  if (!rows[0]) return res.status(404).json({ error: 'not_found' });
  if (rows[0].is_system) return res.status(409).json({ error: 'system_client' });
  if (!rows[0].disabled_at) return res.status(409).json({ error: 'must_disable_first' });
  await pool.query('DELETE FROM oauth_clients WHERE client_id = $1', [req.params.id]);
  res.status(204).end();
});

// --- signing keys ---
adminRouter.get('/admin/api/keys', async (_req: AdminRequest, res: Response) => {
  const { rows } = await pool.query(
    `SELECT kid, alg, status, created_at, activated_at, retired_at FROM signing_keys ORDER BY created_at DESC`,
  );
  // in_jwks lets the UI distinguish "retired, still verifying" from "retired,
  // out of the published set" without re-deriving the 24h window client-side.
  const jwks = await getJwks();
  const published = new Set(jwks.keys.map((k) => k.kid as string));
  res.json({
    // Fully-retired keys (aged past the 24h JWKS window, no longer trusted) are
    // dropped from the list — the row stays in the DB as an audit trail, but the
    // settings page only shows keys that still matter (current / next / verifying).
    keys: rows
      .map((k) => ({ ...k, in_jwks: published.has(k.kid) }))
      .filter((k) => k.status !== 'retired' || k.in_jwks),
    jwks,
  });
});

// Rotate: new key signs immediately; the old one keeps verifying from the JWKS
// for 24h. Both first-party RPs re-fetch the JWKS on an unknown kid, so there
// is no propagation delay to wait out.
adminRouter.post('/admin/api/keys/rotate', requireCsrf, async (_req: AdminRequest, res: Response) => {
  const kid = await rotateSigningKey();
  res.json({ kid });
});

// Rotate the ACCOUNT PORTAL's client key. The key is RP-owned (the BFF signs
// with it), so this relays a short-lived SSO-signed request to the portal's
// internal endpoint; the portal generates + publishes the new key itself and
// we pick it up via its jwks_uri on the next unknown kid.
adminRouter.post('/admin/api/account-portal/rotate-client-key', requireCsrf, async (_req: AdminRequest, res: Response) => {
  const portal = ((await getSetting('account_portal_url', config.accountPortalUrl))!).replace(/\/+$/, '');
  const { kid, privateKey } = await getSigningKey();
  const now = Math.floor(Date.now() / 1000);
  const token = await new SignJWT({})
    .setProtectedHeader({ alg: 'EdDSA', kid, typ: 'rotate+jwt' })
    .setIssuer(config.issuer)
    .setAudience(config.accountClientId)
    .setIssuedAt(now)
    .setExpirationTime(now + 60)
    .setJti(crypto.randomUUID())
    .sign(privateKey);
  let r: globalThis.Response;
  try {
    r = await s2sFetch(portal + '/internal/rotate-client-key', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ token }),
      signal: AbortSignal.timeout(5000),
    });
  } catch {
    return res.status(502).json({ error: 'portal_unreachable' });
  }
  if (!r.ok) return res.status(502).json({ error: 'rotate_failed' });
  res.json(await r.json());
});

// --- service-to-service mTLS (client certificate presented at the CF edge) ---
adminRouter.get('/admin/api/mtls', async (_req: AdminRequest, res: Response) => {
  res.json(await mtls.getStatus());
});

adminRouter.post('/admin/api/mtls/csr', requireCsrf, async (req: AdminRequest, res: Response) => {
  const cn = typeof (req.body as { cn?: unknown })?.cn === 'string' ? (req.body as { cn: string }).cn : undefined;
  res.json(await mtls.startSetup(cn));
});

adminRouter.post('/admin/api/mtls/cert', requireCsrf, async (req: AdminRequest, res: Response) => {
  const r = await mtls.installCert((req.body as { cert?: unknown })?.cert);
  if (!r.ok) return res.status(422).json({ error: r.reason });
  res.json(r);
});

adminRouter.put('/admin/api/mtls/enforce', requireCsrf, async (req: AdminRequest, res: Response) => {
  const r = await mtls.setEnforce(!!(req.body as { enabled?: unknown })?.enabled);
  if (!r.ok) return res.status(422).json({ error: r.reason });
  res.status(204).end();
});

adminRouter.delete('/admin/api/mtls', requireCsrf, async (_req: AdminRequest, res: Response) => {
  await mtls.reset();
  res.status(204).end();
});

// --- settings: env summary (view-only) + admin-editable site/email settings ---

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

adminRouter.get('/admin/api/settings', async (_req: AdminRequest, res: Response) => {
  const [siteName, portalUrl, mailFrom, cfAccountId, tokenSet, idleDays, maxDays, transientMax, suAdmin, suPortal, suMinutes,
         tsSiteKey, tsSecretSet, gateJwkRaw, regEnabled, invRequired] =
    await Promise.all([
      getSetting('site_name', 'DreamSSO'),
      getSetting('account_portal_url', config.accountPortalUrl),
      getSetting('mail_from'),
      getSetting('cf_account_id'),
      hasSetting('cf_api_token'),
      getSetting('session_idle_hours', '72'),
      getSetting('session_max_hours', '168'),
      getSetting('session_transient_max_hours', '24'),
      getSetting('stepup_admin_required', 'false'),
      getSetting('stepup_portal_required', 'false'),
      getSetting('stepup_validity_minutes', '30'),
      getSetting('turnstile_site_key'),
      hasSetting('turnstile_secret_key'),
      getSetting('gate_signing_public_jwk'),
      getSetting('enable_registration', 'false'),
      getSetting('require_invitation_code', 'true'),
    ]);
  // Edge-gate signing key: only the PUBLIC JWK is stored; surface its identity.
  let gateKey: { kid: string; created_at: string } | null = null;
  if (gateJwkRaw) {
    try {
      const j = JSON.parse(gateJwkRaw) as { kid?: string; created_at?: string };
      gateKey = { kid: j.kid ?? '?', created_at: j.created_at ?? '' };
    } catch { /* corrupt row -> treat as unset */ }
  }
  res.json({
    // view-only env
    issuer: config.issuer,
    webauthn_rp_id: config.webauthnRpId,
    webauthn_origins: config.webauthnOrigins,
    // editable (cf_api_token is write-only: only its presence is reported)
    site_name: siteName,
    account_portal_url: portalUrl,
    session_idle_hours: idleDays,
    session_max_hours: maxDays,
    session_transient_max_hours: transientMax,
    stepup_admin_required: suAdmin === 'true',
    stepup_portal_required: suPortal === 'true',
    stepup_validity_minutes: suMinutes,
    mail_from: mailFrom,
    cf_account_id: cfAccountId,
    cf_token_set: tokenSet,
    // No enable toggle: Turnstile is ON exactly when both keys are set
    // (clearing the site key turns it off) — removes videosite's
    // toggle/worker coordination problem.
    turnstile_site_key: tsSiteKey,
    turnstile_secret_set: tsSecretSet,
    gate_key: gateKey,
    enable_registration: regEnabled === 'true',
    require_invitation_code: invRequired === 'true',
  });
});

// PUT /admin/api/settings — partial update of the editable settings. The token is
// write-only and never returned: blank/absent = unchanged, a value = replace
// (sealed at rest). There is deliberately NO empty-string-clears path — an
// accidental save with a focused empty field must not destroy the credential.
adminRouter.put('/admin/api/settings', requireCsrf, async (req: AdminRequest, res: Response) => {
  const body = (req.body ?? {}) as Record<string, unknown>;
  const errors: Record<string, string> = {};
  const str = (k: string) => (typeof body[k] === 'string' ? (body[k] as string).trim() : undefined);

  const siteName = str('site_name');
  if (siteName !== undefined && (!siteName || siteName.length > 100)) errors.site_name = 'Required, max 100 chars';
  // Portal = protocol + bare hostname (videosite-style): no path/port/query. The
  // hostname goes through the SHARED normalizer, same as the client form.
  let portal = str('account_portal_url');
  if (portal !== undefined) {
    let u: URL | null = null;
    try { u = new URL(portal); } catch { /* invalid */ }
    const host = u ? normalizeHostname(u.hostname) : { value: '', error: 'invalid' };
    if (!u || (u.protocol !== 'https:' && u.protocol !== 'http:') || u.port ||
        (u.pathname !== '/' && u.pathname !== '') || u.search || u.hash || host.error) {
      errors.account_portal_url = 'Protocol + bare hostname only (no path or port)';
    } else {
      portal = `${u.protocol}//${host.value}`;
    }
  }
  // Session windows: whole HOURS — idle 1–2160 (90d), absolute 1–8760 (1y),
  // idle ≤ absolute (equal is fine — absolute just can't be smaller). Validated
  // as a pair against the effective (merged) values so a partial update can't
  // invert them.
  const idleRaw = str('session_idle_hours');
  const maxRaw = str('session_max_hours');
  const hourVal = (v: string | undefined, field: string, hi: number): number | undefined => {
    if (v === undefined) return undefined;
    if (!/^\d{1,4}$/.test(v) || +v < 1 || +v > hi) {
      errors[field] = `Whole hours, 1–${hi}`;
      return undefined;
    }
    return +v;
  };
  const idleNum = hourVal(idleRaw, 'session_idle_hours', 2160);
  const maxNum = hourVal(maxRaw, 'session_max_hours', 8760);
  const transRaw = str('session_transient_max_hours');
  const transNum = hourVal(transRaw, 'session_transient_max_hours', 8760);
  if ((idleRaw !== undefined || maxRaw !== undefined || transRaw !== undefined) &&
      !errors.session_idle_hours && !errors.session_max_hours && !errors.session_transient_max_hours) {
    const effIdle = idleNum ?? parseInt((await getSetting('session_idle_hours', '72'))!, 10);
    const effMax = maxNum ?? parseInt((await getSetting('session_max_hours', '168'))!, 10);
    const effTrans = transNum ?? parseInt((await getSetting('session_transient_max_hours', '24'))!, 10);
    if (effMax < effIdle) errors.session_max_hours = 'Can’t be smaller than the idle timeout';
    if (effTrans > effMax) errors.session_transient_max_hours = 'Can’t exceed the persistent maximum';
  }

  // Step-up: two booleans + a validity window in whole minutes (1–1440).
  const suMin = str('stepup_validity_minutes');
  if (suMin !== undefined && (!/^\d{1,4}$/.test(suMin) || +suMin < 1 || +suMin > 1440)) {
    errors.stepup_validity_minutes = 'Whole minutes, 1–1440';
  }
  const boolField = (k: string): boolean | undefined =>
    typeof body[k] === 'boolean' ? (body[k] as boolean) : undefined;
  const suAdminV = boolField('stepup_admin_required');
  const suPortalV = boolField('stepup_portal_required');
  // Registration: two plain toggles (videosite parity). Fail-closed defaults —
  // off, and codes required whenever it's on.
  const regEnabledV = boolField('enable_registration');
  const invRequiredV = boolField('require_invitation_code');
  // Turning a step-up requirement ON demands the enabling admin already own a
  // strong factor — the door would challenge THEM immediately (lockout guard).
  if (suAdminV === true || suPortalV === true) {
    const [pk, totp] = await Promise.all([
      countPasskeys(req.adminSession!.userSub),
      countAuthenticators(req.adminSession!.userSub),
    ]);
    if (pk + totp === 0) {
      const msg = 'Add a passkey or authenticator app to your account first — enabling this requires step-up verification immediately.';
      if (suAdminV === true) errors.stepup_admin_required = msg;
      if (suPortalV === true) errors.stepup_portal_required = msg;
    }
  }

  // Turnstile gate for the account portal's public flows (password reset now,
  // registration later). No enable toggle: configured ⟺ enabled — both keys
  // set turns the gate on; CLEARING the site key turns it off. The secret is
  // write-only + sealed like cf_api_token: blank = unchanged, no empty-clears.
  const tsSiteKey = str('turnstile_site_key');
  const tsSecret = str('turnstile_secret_key');
  if (tsSiteKey !== undefined && tsSiteKey !== '' && !/^\S{1,100}$/.test(tsSiteKey)) {
    errors.turnstile_site_key = 'No spaces, max 100 chars';
  }

  const mailFrom = str('mail_from');
  if (mailFrom !== undefined && mailFrom !== '' && !EMAIL_RE.test(mailFrom)) errors.mail_from = 'Must be a valid email address';
  const cfAccount = str('cf_account_id');
  if (cfAccount !== undefined && cfAccount !== '' && !/^[0-9a-f]{32}$/.test(cfAccount)) {
    errors.cf_account_id = 'Must be a 32-char hex Cloudflare account ID';
  }
  // Hidden test/mock override — API-only, never surfaced in the UI.
  const apiBase = str('cf_api_base');
  if (apiBase !== undefined && apiBase !== '' &&
      !/^https:\/\//.test(apiBase) && !/^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(apiBase)) {
    errors.cf_api_base = 'https URL (or loopback http for tests)';
  }
  if (Object.keys(errors).length) return res.status(422).json({ errors });

  if (siteName !== undefined) {
    const prevName = await getSetting('site_name', 'DreamSSO');
    await setSetting('site_name', siteName);
    if (prevName !== siteName) {
      // Org-name handover: broadcast to event-connected apps (the portal reads
      // settings directly).
      const { rows: dests } = await pool.query(
        `SELECT client_id FROM oauth_clients
          WHERE events_uri IS NOT NULL AND disabled_at IS NULL AND client_id <> $1`,
        [config.accountClientId],
      );
      for (const d of dests) {
        enqueueEvents(d.client_id, [{ type: 'org.settings', payload: { site_name: siteName } }])
          .catch((e) => console.warn('org.settings enqueue failed:', (e as Error).message));
      }
    }
  }
  if (portal !== undefined) await setSetting('account_portal_url', portal);
  if (idleNum !== undefined) await setSetting('session_idle_hours', String(idleNum));
  if (maxNum !== undefined) await setSetting('session_max_hours', String(maxNum));
  if (transNum !== undefined) await setSetting('session_transient_max_hours', String(transNum));
  if (suAdminV !== undefined) await setSetting('stepup_admin_required', String(suAdminV));
  if (suPortalV !== undefined) await setSetting('stepup_portal_required', String(suPortalV));
  if (regEnabledV !== undefined) await setSetting('enable_registration', String(regEnabledV));
  if (invRequiredV !== undefined) await setSetting('require_invitation_code', String(invRequiredV));
  if (suMin !== undefined) await setSetting('stepup_validity_minutes', suMin);
  if (mailFrom !== undefined) await setSetting('mail_from', mailFrom || null);
  if (cfAccount !== undefined) await setSetting('cf_account_id', cfAccount || null);
  if (apiBase !== undefined) await setSetting('cf_api_base', apiBase || null);
  if (typeof body.cf_api_token === 'string' && body.cf_api_token !== '') {
    await setSecretSetting('cf_api_token', body.cf_api_token);
  }
  if (tsSiteKey !== undefined) await setSetting('turnstile_site_key', tsSiteKey || null);
  if (tsSecret !== undefined && tsSecret !== '') await setSecretSetting('turnstile_secret_key', tsSecret);
  res.status(204).end();
});

// POST /admin/api/settings/generate-gate-key — mint the edge gate's Ed25519
// signing keypair. The PUBLIC JWK is stored (plain — nothing to seal) for the
// BFF to verify x-gate-assertion; the PRIVATE JWK is returned ONCE for
// `wrangler secret put GATE_SIGNING_KEY` and never persisted. Generating
// again rotates: the old worker key stops verifying immediately.
adminRouter.post('/admin/api/settings/generate-gate-key', requireCsrf, async (_req: AdminRequest, res: Response) => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const kid = crypto.randomBytes(6).toString('base64url');
  const created = new Date().toISOString();
  const pubJwk = { ...(publicKey.export({ format: 'jwk' }) as Record<string, unknown>), kid, created_at: created };
  await setSetting('gate_signing_public_jwk', JSON.stringify(pubJwk));
  res.json({
    private_jwk: { ...(privateKey.export({ format: 'jwk' }) as Record<string, unknown>), kid },
    kid,
    created_at: created,
  });
});

// POST /admin/api/settings/test-email { to } — verify the pipeline end to end.
adminRouter.post('/admin/api/settings/test-email', requireCsrf, async (req: AdminRequest, res: Response) => {
  const to = typeof (req.body ?? {}).to === 'string' ? (req.body.to as string).trim() : '';
  if (!EMAIL_RE.test(to)) return res.status(422).json({ errors: { to: 'Must be a valid email address' } });
  const siteName = (await getSetting('site_name', 'DreamSSO'))!;
  const r = await sendEmail({ to, ...renderTestEmail({ siteName }) });
  if (!r.ok) return res.status(502).json({ error: r.reason, ...(r.detail ? { detail: r.detail } : {}) });
  res.status(204).end();
});
