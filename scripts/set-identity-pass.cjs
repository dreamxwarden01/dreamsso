// Dev-only: set a known password on an SSO identity so we can drive login tests
// for migrated users (whose original passwords we don't have).
//   node scripts/set-identity-pass.cjs <username> <password>
const argon2 = require('argon2');
const { Client } = require('pg');
(async () => {
  const [user, pass] = [process.argv[2], process.argv[3]];
  if (!user || !pass) { console.error('usage: set-identity-pass.cjs <username> <password>'); process.exit(1); }
  const hash = await argon2.hash(pass, { type: argon2.argon2id });
  const c = new Client({ host: '127.0.0.1', port: 5432, user: 'dreamsso', password: 'dreamsso', database: 'dreamsso' });
  await c.connect();
  const r = await c.query('UPDATE identities SET password_hash = $1 WHERE username = $2', [hash, user]);
  console.log(`updated ${user}: ${r.rowCount} row(s)`);
  await c.end();
})().catch((e) => { console.error('ERR', e.message); process.exit(1); });
