import 'dotenv/config';

// Infra config as a MUTABLE singleton. Missing essentials (KEY_ENCRYPTION_KEY /
// DATABASE_URL) no longer throw at import — the process boots in "setup mode" and
// the first-run /setup wizard collects them, writes .env, and calls applyConfig()
// to populate this object in place (in-process, no restart). Every consumer reads
// these fields at request time, so late population is safe.

function splitOrigins(s: string): string[] {
  return s.split(',').map((x) => x.trim()).filter(Boolean);
}

export const config = {
  port: Number(process.env.PORT ?? 3000),
  issuer: process.env.ISSUER ?? 'https://sso-dev.dreamxwarden.ca',
  nodeEnv: process.env.NODE_ENV ?? 'development',
  databaseUrl: process.env.DATABASE_URL ?? '',
  redisUrl: process.env.REDIS_URL ?? 'redis://127.0.0.1:6379',
  keyEncryptionKey: process.env.KEY_ENCRYPTION_KEY ?? '',

  // The account console's own OIDC client. It's an RP (so it still receives
  // back-channel logout) but it's the portal itself, not a "service you accessed",
  // so it's hidden from the Devices pane's apps list.
  accountClientId: process.env.ACCOUNT_CLIENT_ID ?? 'account',
  // Where the bare SSO hostname (GET /) sends people — end users belong in the
  // account portal, not on the IdP.
  accountPortalUrl: process.env.ACCOUNT_PORTAL_URL ?? 'https://account-dev.dreamxwarden.ca',

  // WebAuthn / passkeys. RP ID = the registrable domain so passkeys work across
  // sso/account/stream subdomains; origins = the first-party app(s) that register.
  webauthnRpId: process.env.WEBAUTHN_RP_ID ?? 'dreamxwarden.ca',
  webauthnRpName: process.env.WEBAUTHN_RP_NAME ?? 'DreamSSO',
  // Ceremony origins: the account console (passkey management) AND the SSO's own
  // login page (first-factor passkey sign-in + the MFA challenge).
  webauthnOrigins: splitOrigins(
    process.env.WEBAUTHN_ORIGINS ?? 'https://account-dev.dreamxwarden.ca,https://sso-dev.dreamxwarden.ca',
  ),
};

export function isValidKek(v: string): boolean {
  return /^[0-9a-fA-F]{64}$/.test(v);
}

// The infra essentials are present + well-formed. When false, the app boots in
// setup mode (serves only /setup + the neutral unavailable page).
export function isConfigured(): boolean {
  return !!config.databaseUrl && isValidKek(config.keyEncryptionKey);
}

// Populate config in place from the /setup wizard (after it writes .env). Only
// the provided fields are overwritten. Callers must reconnect the DB/Redis and
// re-resolve setup state afterwards.
export function applyConfig(v: {
  databaseUrl?: string;
  redisUrl?: string;
  keyEncryptionKey?: string;
  issuer?: string;
  webauthnRpId?: string;
  webauthnRpName?: string;
  webauthnOrigins?: string[];
}): void {
  if (v.databaseUrl !== undefined) config.databaseUrl = v.databaseUrl;
  if (v.redisUrl !== undefined) config.redisUrl = v.redisUrl;
  if (v.keyEncryptionKey !== undefined) config.keyEncryptionKey = v.keyEncryptionKey;
  if (v.issuer !== undefined) config.issuer = v.issuer;
  if (v.webauthnRpId !== undefined) config.webauthnRpId = v.webauthnRpId;
  if (v.webauthnRpName !== undefined) config.webauthnRpName = v.webauthnRpName;
  if (v.webauthnOrigins !== undefined) config.webauthnOrigins = v.webauthnOrigins;
}
