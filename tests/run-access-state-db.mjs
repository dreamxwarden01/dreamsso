import { randomBytes, randomUUID } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
const exec = promisify(execFile), context = process.env.DREAMSSO_TEST_DOCKER_CONTEXT || 'orbstack';
const name = 'dreamsso-query-test-' + randomUUID(), directory = await mkdtemp(join(tmpdir(), 'dreamsso-query-db-'));
const password = randomBytes(24).toString('hex');let created = false;
const docker = (...args) => exec('docker', ['--context', context, ...args]);
try {
  const environmentFile = join(directory, 'postgres.env');
  await writeFile(environmentFile, `POSTGRES_DB=dreamsso_access_state_test\nPOSTGRES_USER=dreamsso_access_state_test\nPOSTGRES_PASSWORD=${password}\n`, { mode: 0o600 });
  console.info('Starting an isolated PostgreSQL test container.');
  await docker('run', '--detach', '--name', name, '--label', 'dreamsso.scope=access-state-local-test', '--env-file', environmentFile,
    '--publish', '127.0.0.1::5432', '--tmpfs', '/var/lib/postgresql:rw,size=256m', 'postgres:18');created = true;
  let ready = false;
  for (let attempt = 0; attempt < 80; attempt++) {
    try { await docker('exec', name, 'pg_isready', '-U', 'dreamsso_access_state_test', '-d', 'dreamsso_access_state_test');ready = true;break; }
    catch { await new Promise(resolve => setTimeout(resolve, 250)); }
  }
  if (!ready) throw new Error('Test database did not become ready.');
  const { stdout } = await docker('port', name, '5432/tcp'), match = /^127\.0\.0\.1:(\d+)\s*$/.exec(stdout);
  if (!match) throw new Error('Unexpected test database network binding.');
  const env = { ...process.env, DREAMSSO_LOCAL_TEST_DATABASE_URL: `postgresql://dreamsso_access_state_test:${password}@127.0.0.1:${match[1]}/dreamsso_access_state_test` };
  const result = await exec(process.execPath, ['--import', 'tsx', '--test', 'tests/access-state.database.test.ts'], { env });
  process.stdout.write(result.stdout);process.stderr.write(result.stderr);
} catch (error) {
  // The subprocess environment contains an ephemeral password; do not dump the error object.
  console.error('Isolated database tests failed.');if (error.stdout) process.stdout.write(error.stdout);
  if (error.stderr) process.stderr.write(error.stderr);process.exitCode = 1;
} finally {
  if (created) { try { await docker('rm', '--force', name);console.info('Test container removed.'); } catch { console.error('Test container cleanup failed: ' + name);process.exitCode = 1; } }
  await rm(directory, { recursive: true, force: true });
}
