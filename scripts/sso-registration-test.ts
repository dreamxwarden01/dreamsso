// Run registration and invitation regressions in disposable local PostgreSQL/Redis fixtures.
// This entry point does not send mail or change a running SSO installation.
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
const result = spawnSync(process.execPath, [fileURLToPath(new URL('../tests/run-role-events-db.mjs', import.meta.url))], {
  cwd: fileURLToPath(new URL('..', import.meta.url)), stdio: 'inherit', env: process.env,
});
if (result.error) console.error('Could not start the isolated registration tests.');
process.exitCode = result.status ?? 1;
