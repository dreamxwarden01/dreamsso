// Seed RBAC Phase A from the code catalog: org_roles, role_permissions (per-role
// defaults), and the initial user_org_role assignments — every active identity ->
// standard_user, with one designated superadmin. Idempotent (run via tsx).
//   npx tsx scripts/seed-rbac.ts            (superadmin = dreamxwarden01)
//   SUPERADMIN_USERNAME=foo npx tsx scripts/seed-rbac.ts
import { pool } from '../src/db.js';
import { SYSTEM_ROLES, PERMISSIONS } from '../src/rbac/catalog.js';

const SUPERADMIN = process.env.SUPERADMIN_USERNAME ?? 'dreamxwarden01';

const client = await pool.connect();
try {
  await client.query('BEGIN');

  for (const r of SYSTEM_ROLES) {
    await client.query(
      `INSERT INTO org_roles (slug, label, level) VALUES ($1, $2, $3)
         ON CONFLICT (slug) DO UPDATE SET label = EXCLUDED.label, level = EXCLUDED.level`,
      [r.slug, r.label, r.level],
    );
  }

  for (const def of PERMISSIONS) {
    for (const r of SYSTEM_ROLES) {
      await client.query(
        `INSERT INTO role_permissions (role_slug, perm_key, effect) VALUES ($1, $2, $3)
           ON CONFLICT (role_slug, perm_key) DO UPDATE SET effect = EXCLUDED.effect`,
        [r.slug, def.key, def.defaults[r.slug]],
      );
    }
  }

  // Everyone defaults to standard_user; then promote the designated superadmin.
  const { rowCount: assigned } = await client.query(
    `INSERT INTO user_org_roles (user_sub, org_role_slug)
       SELECT sub, 'standard_user' FROM identities WHERE deleted_at IS NULL
     ON CONFLICT (user_sub) DO NOTHING`,
  );
  const { rows: promoted } = await client.query(
    `INSERT INTO user_org_roles (user_sub, org_role_slug)
       SELECT sub, 'superadmin' FROM identities WHERE username = $1 AND deleted_at IS NULL
     ON CONFLICT (user_sub) DO UPDATE SET org_role_slug = 'superadmin'
     RETURNING user_sub`,
    [SUPERADMIN],
  );

  await client.query('COMMIT');
  console.log(
    `RBAC seeded: ${SYSTEM_ROLES.length} roles, ${PERMISSIONS.length} perms x role; ` +
      `${assigned} users -> standard_user; superadmin '${SUPERADMIN}' ${promoted.length ? 'set' : 'NOT FOUND'}.`,
  );
  if (!promoted.length) process.exitCode = 1;
} catch (e) {
  await client.query('ROLLBACK');
  console.error('seed-rbac FAILED — rolled back:', (e as Error).message);
  process.exitCode = 1;
} finally {
  client.release();
  await pool.end();
}
