import argon2 from 'argon2';
import { uuidv7 } from 'uuidv7';
import { pool } from '../db.js';
import { SYSTEM_ROLES, PERMISSIONS } from '../rbac/catalog.js';
import { sealSecret } from '../secretbox.js';
import { passwordComplexityOk } from '../routes/security.js';
import { markComplete } from './state.js';
import { clearSetupToken } from './token.js';

const str = (v: unknown): string => (typeof v === 'string' ? v.trim() : '');
const USERNAME_RE = /^[A-Za-z0-9_-]{3,20}$/; // matches the portal register page
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const ENC_PREFIX = 'enc:v1:'; // mirrors settings.ts (secret settings)

export type FinishInput = {
  username?: unknown;
  displayName?: unknown;
  email?: unknown;
  password?: unknown;
  siteName?: unknown;
  accountPortalUrl?: unknown;
  emailEnabled?: unknown;
  mailFrom?: unknown;
  cfAccountId?: unknown;
  cfApiToken?: unknown;
};

export function validateFinish(input: FinishInput): Record<string, string> {
  const e: Record<string, string> = {};
  const username = str(input.username);
  const displayName = str(input.displayName);
  const email = str(input.email);
  const password = typeof input.password === 'string' ? input.password : '';
  const siteName = str(input.siteName);
  const portal = str(input.accountPortalUrl);

  if (!USERNAME_RE.test(username)) e.username = 'Usernames are 3-20 characters: letters, digits, - and _.';
  if (!displayName || displayName.length > 100) e.displayName = 'Display names are 1-100 characters.';
  if (!EMAIL_RE.test(email)) e.email = 'Enter a valid email address.';
  if (/\s/.test(password) || !passwordComplexityOk(password)) {
    e.password = 'Use at least 8 characters with 3 of: uppercase, lowercase, digit, symbol.';
  }
  if (!siteName || siteName.length > 100) e.siteName = 'Enter a site name (up to 100 characters).';
  try {
    if (new URL(portal).protocol !== 'https:') e.accountPortalUrl = 'The portal must be an https:// URL.';
  } catch {
    e.accountPortalUrl = 'Enter a full URL, e.g. https://account.example.com';
  }
  if (input.emailEnabled) {
    if (!EMAIL_RE.test(str(input.mailFrom))) e.mailFrom = 'Enter a valid From address.';
    if (!str(input.cfAccountId)) e.cfAccountId = 'Enter your Cloudflare account ID.';
    if (!str(input.cfApiToken)) e.cfApiToken = 'Enter an API token.';
  }
  return e;
}

// The finish transaction — one atomic commit: seed the RBAC catalog, create the
// first identity + promote it to superadmin, register the `account` client via
// jwks_uri, and persist the site/email settings + the setup_complete marker. Then
// flip the RAM latch and burn the setup token. createSession is the caller's job
// (it needs res). Assumes validateFinish passed.
export async function runFinishTransaction(input: FinishInput): Promise<{ sub: string }> {
  const username = str(input.username);
  const displayName = str(input.displayName);
  const email = str(input.email);
  const siteName = str(input.siteName);
  const portal = str(input.accountPortalUrl).replace(/\/+$/, '');
  const sub = uuidv7();
  const hash = await argon2.hash(String(input.password), { type: argon2.argon2id });

  const c = await pool.connect();
  try {
    await c.query('BEGIN');

    // RBAC catalog (idempotent) — supersedes scripts/seed-rbac.ts.
    for (const r of SYSTEM_ROLES) {
      await c.query(
        `INSERT INTO org_roles (slug, label, level) VALUES ($1, $2, $3)
           ON CONFLICT (slug) DO UPDATE SET label = EXCLUDED.label, level = EXCLUDED.level`,
        [r.slug, r.label, r.level],
      );
    }
    for (const def of PERMISSIONS) {
      for (const r of SYSTEM_ROLES) {
        await c.query(
          `INSERT INTO role_permissions (role_slug, perm_key, effect) VALUES ($1, $2, $3)
             ON CONFLICT (role_slug, perm_key) DO UPDATE SET effect = EXCLUDED.effect`,
          [r.slug, def.key, def.defaults[r.slug]],
        );
      }
    }

    // First identity (email_verified: the operator owns this deployment) + superadmin.
    await c.query(
      `INSERT INTO identities (sub, username, display_name, email, email_verified, password_hash, password_changed_at)
       VALUES ($1, $2, $3, $4, true, $5, now())`,
      [sub, username, displayName, email, hash],
    );
    await c.query(`INSERT INTO user_org_roles (user_sub, org_role_slug) VALUES ($1, 'superadmin')`, [sub]);

    // The account console client — jwks_uri only (BFF self-serves its public key;
    // the SSO fetches it lazily at /token). Clears any inline jwks on re-run.
    await c.query(
      `INSERT INTO oauth_clients
         (client_id, name, is_first_party, entry_policy, redirect_uris, post_logout_redirect_uris,
          events_uri, token_endpoint_auth_method, jwks_uri, jwks, allowed_scopes, is_system)
       VALUES ('account', 'DreamSSO Account', true, 'opt_in', $1, $2, $3, 'private_key_jwt', $4, NULL,
               ARRAY['openid','profile','email'], true)
       ON CONFLICT (client_id) DO UPDATE SET
         name = EXCLUDED.name, redirect_uris = EXCLUDED.redirect_uris,
         post_logout_redirect_uris = EXCLUDED.post_logout_redirect_uris, events_uri = EXCLUDED.events_uri,
         jwks_uri = EXCLUDED.jwks_uri, jwks = NULL, is_system = true, entry_policy = EXCLUDED.entry_policy`,
      [
        [`${portal}/auth/callback`],
        [`${portal}/`],
        `${portal}/backchannel/events`,
        `${portal}/.well-known/jwks.json`,
      ],
    );

    // Settings — written inline (not via setSetting) so they're atomic with the txn.
    const putSetting = (k: string, v: string) =>
      c.query(
        `INSERT INTO settings (key, value) VALUES ($1, $2)
           ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
        [k, v],
      );
    await putSetting('site_name', siteName);
    await putSetting('account_portal_url', portal);
    if (input.emailEnabled) {
      await putSetting('mail_from', str(input.mailFrom));
      await putSetting('cf_account_id', str(input.cfAccountId));
      await putSetting('cf_api_token', ENC_PREFIX + sealSecret(String(input.cfApiToken)).toString('base64'));
    }
    await putSetting('setup_complete', new Date().toISOString());

    await c.query('COMMIT');
  } catch (e) {
    await c.query('ROLLBACK');
    throw e;
  } finally {
    c.release();
  }

  markComplete(); // gate flips to normal; /setup 404s
  clearSetupToken();
  return { sub };
}
