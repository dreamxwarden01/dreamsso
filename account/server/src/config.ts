import 'dotenv/config';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// Mutable config singleton. Missing essentials no longer throw at import — the BFF
// boots in "setup mode" and its first-run /setup wizard collects them, writes .env,
// and calls applyConfig() to populate this in place (no restart). Consumers read
// these fields at request time, so late population is safe.

const issuer = process.env.SSO_ISSUER ?? '';

export const config = {
  port: Number(process.env.PORT ?? 4000),
  nodeEnv: process.env.NODE_ENV ?? 'development',

  // OpenID Provider
  issuer,
  internal: process.env.SSO_INTERNAL || issuer, // back-channel base (/token,/jwks,/userinfo)

  // This relying party (registered in the SSO's oauth_clients as `account`)
  clientId: process.env.OIDC_CLIENT_ID ?? 'account',
  redirectUri: process.env.OIDC_REDIRECT_URI ?? '',
  postLogoutRedirect: process.env.OIDC_POST_LOGOUT_REDIRECT ?? '/',
  clientKeyFile:
    process.env.OIDC_CLIENT_KEY_FILE ?? path.resolve(process.cwd(), '.account-client-key.json'),

  // The portal's own public origin — the base for its redirect_uri and for the
  // jwks_uri the SSO reads our client key from.
  publicUrl: (process.env.PUBLIC_URL ?? '').replace(/\/+$/, ''),

  redisUrl: process.env.REDIS_URL ?? 'redis://127.0.0.1:6379',
  // 1 day: the BFF session is just a local cache of an SSO login — the daily
  // silent-reauth bounce re-validates against the master session (which owns the
  // real idle/absolute windows), so a shorter local TTL costs little and keeps
  // Redis state fresher.
  sessionTtl: Number(process.env.SESSION_TTL_SECONDS ?? 60 * 60 * 24),

  // Built SPA. Both src/ (tsx) and dist/ (tsc) sit one level under server/, so
  // '../../client/dist' resolves to account/client/dist in dev and prod alike.
  spaDist: process.env.SPA_DIST
    ? process.env.SPA_DIST
    : fileURLToPath(new URL('../../client/dist', import.meta.url)),
};

// Configured = we know the SSO, our own callback, and we hold a client key to sign
// assertions with. Anything less and the wizard runs.
export function isConfigured(): boolean {
  return (
    !!config.issuer && !!config.redirectUri && !!config.clientKeyFile && fs.existsSync(config.clientKeyFile)
  );
}

// Populate config in place from the /setup wizard (after it writes .env).
export function applyConfig(v: {
  issuer?: string;
  internal?: string;
  redirectUri?: string;
  postLogoutRedirect?: string;
  clientKeyFile?: string;
  publicUrl?: string;
  redisUrl?: string;
}): void {
  if (v.issuer !== undefined) {
    config.issuer = v.issuer;
    // `internal` tracks the issuer unless it was pinned explicitly.
    if (!process.env.SSO_INTERNAL) config.internal = v.issuer;
  }
  if (v.internal !== undefined) config.internal = v.internal;
  if (v.redirectUri !== undefined) config.redirectUri = v.redirectUri;
  if (v.postLogoutRedirect !== undefined) config.postLogoutRedirect = v.postLogoutRedirect;
  if (v.clientKeyFile !== undefined) config.clientKeyFile = v.clientKeyFile;
  if (v.publicUrl !== undefined) config.publicUrl = v.publicUrl.replace(/\/+$/, '');
  if (v.redisUrl !== undefined) config.redisUrl = v.redisUrl;
}
