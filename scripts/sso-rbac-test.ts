// Unit test for the RBAC engine — resolution, defaults from the matrix, per-user
// overrides, and the level/delegation guard. Hits the DB directly (run via tsx).
//   npx tsx scripts/sso-rbac-test.ts
import { pool } from '../src/db.js';
import { resolveAuthz, canAdminister } from '../src/rbac/index.js';

let fail = 0;
const ok = (c: boolean, label: string, extra = '') => {
  console.log(`${c ? '✓' : '✗ FAIL'}  ${label}${extra ? '  ' + extra : ''}`);
  if (!c) fail++;
};
async function subOf(username: string): Promise<string> {
  const { rows } = await pool.query<{ sub: string }>('SELECT sub FROM identities WHERE username = $1', [username]);
  return rows[0]?.sub;
}

const superA = await subOf('dreamxwarden01');
const stdU = await subOf('tester');

const sa = await resolveAuthz(superA);
const su = await resolveAuthz(stdU);

ok(sa.role === 'superadmin' && sa.level === 0, '1. dreamxwarden01 = superadmin (level 0)', sa.role ?? 'null');
ok(su.role === 'standard_user' && su.level === 10, '2. tester = standard_user (level 10)', su.role ?? 'null');

ok(sa.granted.has('org.siteSettings.sso'), '3. superadmin can access /admin');
ok(sa.granted.has('org.users.remove'), '4. superadmin can remove users');
ok(!sa.granted.has('profile.security.mfa.disable'), '5. superadmin CANNOT disable own MFA');

ok(su.granted.has('profile.security.password.change'), '6. standard_user can change own password');
ok(su.granted.has('profile.security.mfa.disable'), '7. standard_user CAN disable own MFA');
ok(!su.granted.has('org.users.create'), '8. standard_user cannot create users');
ok(!su.granted.has('org.siteSettings.sso'), '9. standard_user cannot access /admin');
ok(!su.granted.has('profile.username.change'), '10. standard_user cannot change own username');

// per-user override grant, then remove
await pool.query(
  `INSERT INTO user_permission_overrides (user_sub, perm_key, effect) VALUES ($1, 'org.users.view', 'grant')
     ON CONFLICT (user_sub, perm_key) DO UPDATE SET effect = 'grant'`,
  [stdU],
);
ok((await resolveAuthz(stdU)).granted.has('org.users.view'), '11. override grants org.users.view to tester');
await pool.query(`DELETE FROM user_permission_overrides WHERE user_sub = $1 AND perm_key = 'org.users.view'`, [stdU]);
ok(!(await resolveAuthz(stdU)).granted.has('org.users.view'), '12. override removed -> back to deny');

// per-user override can also DENY a role-granted perm
await pool.query(
  `INSERT INTO user_permission_overrides (user_sub, perm_key, effect) VALUES ($1, 'profile.displayname.change', 'deny')
     ON CONFLICT (user_sub, perm_key) DO UPDATE SET effect = 'deny'`,
  [stdU],
);
ok(!(await resolveAuthz(stdU)).granted.has('profile.displayname.change'), '13. override can deny a normally-granted perm');
await pool.query(`DELETE FROM user_permission_overrides WHERE user_sub = $1 AND perm_key = 'profile.displayname.change'`, [stdU]);

// delegation level guard
ok(await canAdminister(superA, stdU), '14. superadmin can administer standard_user');
ok(!(await canAdminister(stdU, superA)), '15. standard_user cannot administer superadmin');
ok(!(await canAdminister(superA, superA)), '16. cannot administer self via org page');

console.log(fail ? `\n${fail} FAILED ✗` : '\nALL CHECKS PASSED ✓');
await pool.end();
process.exit(fail ? 1 : 0);
