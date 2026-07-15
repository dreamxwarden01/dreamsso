// Dev seed: the `videosite` OAuth client + a throwaway test identity.
// Run with PG* env set (same as the migration):
//   set -a; source ../.env; set +a   (or pass PGHOST/PGUSER/... inline)
//   node scripts/seed-dev.mjs
import pg from 'pg';
import argon2 from 'argon2';
import { uuidv7 } from 'uuidv7';

const TEST_USER = 'tester';
const TEST_PASS = 'Test1234!';

const pool = new pg.Pool();
const client = await pool.connect();
try {
  await client.query('BEGIN');

  await client.query(
    `INSERT INTO oauth_clients
       (client_id, name, is_first_party, entry_policy, redirect_uris,
        post_logout_redirect_uris, backchannel_logout_uri, token_endpoint_auth_method, allowed_scopes)
     VALUES ('videosite', 'VideoSite', true, 'opt_in',
        ARRAY['https://stream-dev.dreamxwarden.ca/callback','https://stream-dev.dreamxwarden.ca/auth/callback'],
        ARRAY['https://stream-dev.dreamxwarden.ca/'],
        'https://stream-dev.dreamxwarden.ca/api/backchannel-logout',
        'private_key_jwt', ARRAY['openid','profile','email'])
     ON CONFLICT (client_id) DO UPDATE SET
        redirect_uris = EXCLUDED.redirect_uris,
        backchannel_logout_uri = EXCLUDED.backchannel_logout_uri`,
  );

  const hash = await argon2.hash(TEST_PASS, { type: argon2.argon2id });
  await client.query(
    `INSERT INTO identities (sub, username, display_name, email, email_verified, password_hash, status)
     VALUES ($1, $2, 'Test User', 'tester@example.com', true, $3, 'active')
     ON CONFLICT (username) WHERE deleted_at IS NULL DO UPDATE SET password_hash = EXCLUDED.password_hash`,
    [uuidv7(), TEST_USER, hash],
  );

  await client.query('COMMIT');
  console.log(`seeded: client=videosite, identity=${TEST_USER} / ${TEST_PASS}`);
} catch (err) {
  await client.query('ROLLBACK');
  console.error('seed failed:', err);
  process.exitCode = 1;
} finally {
  client.release();
  await pool.end();
}
