// Registers the `account` OIDC client (the account console / BFF) and mints its
// private_key_jwt keypair — the account-console analogue of seed-dev.mjs +
// setup-client-key.mjs for `videosite`.
//   - upserts the oauth_clients row (redirect/post-logout URIs, scopes)
//   - generates an Ed25519 keypair; public JWK -> oauth_clients.jwks,
//     private JWK -> account/server/.account-client-key.json (gitignored; the BFF reads it)
// Run with PG* env set (same as the migration / seed):
//   set -a; source .env; set +a
//   node scripts/seed-account-client.mjs
import { generateKeyPair, exportJWK, calculateJwkThumbprint } from 'jose';
import pg from 'pg';
import fs from 'node:fs';

const OUT = new URL('../account/server/.account-client-key.json', import.meta.url);

// Canonical local origin is account-dev (through Caddy → the host BFF). The
// localhost:5173 pair is for running the SPA under Vite's dev server with HMR
// (it proxies /auth + /api to the BFF); harmless to register even if unused.
const REDIRECT_URIS = [
  'https://account-dev.dreamxwarden.ca/auth/callback',
  'http://localhost:5173/auth/callback',
];
const POST_LOGOUT = [
  'https://account-dev.dreamxwarden.ca/',
  'http://localhost:5173/',
];

const pool = new pg.Pool();
const client = await pool.connect();
try {
  await client.query('BEGIN');

  const BACKCHANNEL_LOGOUT_URI = 'https://account-dev.dreamxwarden.ca/backchannel-logout';

  await client.query(
    `INSERT INTO oauth_clients
       (client_id, name, is_first_party, entry_policy, redirect_uris,
        post_logout_redirect_uris, backchannel_logout_uri, token_endpoint_auth_method, allowed_scopes)
     VALUES ('account', 'DreamSSO Account', true, 'opt_in',
        $1, $2, $3, 'private_key_jwt', ARRAY['openid','profile','email'])
     ON CONFLICT (client_id) DO UPDATE SET
        redirect_uris = EXCLUDED.redirect_uris,
        post_logout_redirect_uris = EXCLUDED.post_logout_redirect_uris,
        backchannel_logout_uri = EXCLUDED.backchannel_logout_uri,
        allowed_scopes = EXCLUDED.allowed_scopes`,
    [REDIRECT_URIS, POST_LOGOUT, BACKCHANNEL_LOGOUT_URI],
  );

  // Ed25519 keypair for private_key_jwt (RFC 7523), thumbprint kid — same recipe
  // as setup-client-key.mjs.
  const { publicKey, privateKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });
  const pub = await exportJWK(publicKey);
  const priv = await exportJWK(privateKey);
  const kid = await calculateJwkThumbprint(pub);
  pub.kid = kid; pub.alg = 'EdDSA'; pub.use = 'sig';
  priv.kid = kid; priv.alg = 'EdDSA';

  fs.mkdirSync(new URL('.', OUT), { recursive: true });
  fs.writeFileSync(OUT, JSON.stringify(priv, null, 2));
  await client.query("UPDATE oauth_clients SET jwks = $1 WHERE client_id = 'account'", [{ keys: [pub] }]);

  await client.query('COMMIT');
  console.log(`seeded: client=account (kid ${kid}); public JWK registered, private -> ${OUT.pathname}`);
} catch (err) {
  await client.query('ROLLBACK');
  console.error('seed failed:', err);
  process.exitCode = 1;
} finally {
  client.release();
  await pool.end();
}
