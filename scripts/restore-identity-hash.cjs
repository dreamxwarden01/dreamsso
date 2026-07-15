// Dev-only: copy a migrated user's ORIGINAL password_hash from videosite-db back
// onto the SSO identity (undo a set-identity-pass override). Reads the hash from
// a file (arg 2) to avoid shell-escaping the $-laden argon2 PHC string.
//   node scripts/restore-identity-hash.cjs <username> <hashfile>
const fs = require('fs');
const { Client } = require('pg');
(async () => {
  const [user, file] = [process.argv[2], process.argv[3]];
  if (!user || !file) { console.error('usage: restore-identity-hash.cjs <username> <hashfile>'); process.exit(1); }
  const hash = fs.readFileSync(file, 'utf8').trim();
  if (!hash.startsWith('$argon2')) { console.error('not an argon2 hash:', hash.slice(0, 20)); process.exit(1); }
  const c = new Client({ host: '127.0.0.1', port: 5432, user: 'dreamsso', password: 'dreamsso', database: 'dreamsso' });
  await c.connect();
  const r = await c.query('UPDATE identities SET password_hash = $1 WHERE username = $2', [hash, user]);
  console.log(`restored ${user}: ${r.rowCount} row(s)`);
  await c.end();
})().catch((e) => { console.error('ERR', e.message); process.exit(1); });
