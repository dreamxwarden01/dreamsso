// Apply pending schema migrations by hand.
//
// The SSO also runs these at boot (lenient) and during install (strict); this is
// for applying them deliberately — e.g. on a prod database before rolling the new
// image, so the schema is ready when the app starts rather than racing it.
//
// Run: npx tsx scripts/migrate.ts
import { runMigrations } from '../src/db/migrations.js';
import { pool } from '../src/db.js';

const { applied, baselined } = await runMigrations({ strict: true });

if (baselined.length) {
  console.log(`baselined (recorded, NOT executed — applied before this runner existed): ${baselined.length}`);
  for (const f of baselined) console.log(`  · ${f}`);
}
if (applied.length) {
  console.log(`applied: ${applied.length}`);
  for (const f of applied) console.log(`  ✓ ${f}`);
} else {
  console.log('applied: none — schema already up to date');
}

await pool.end();
