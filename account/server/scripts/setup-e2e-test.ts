// End-to-end test for the account portal's first-run setup.
//
// Boots a REAL, unconfigured BFF in a throwaway working directory (so its .env,
// client key, mTLS state and setup token are all temp files — the dev install is
// never touched), then drives the wizard's API the way the browser will:
//   gate/lock -> config (mints the client key, writes .env) -> mTLS CSR + install
//   -> finish -> the portal is live and /setup is gone.
//
// Requires: Redis on 127.0.0.1:6379 and the dev SSO reachable at SSO_ISSUER.
// Run: npx tsx scripts/setup-e2e-test.ts        (from account/server)
import 'reflect-metadata';
import * as x509 from '@peculiar/x509';
import { spawn, type ChildProcess } from 'node:child_process';
import { webcrypto } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const SERVER_ROOT = path.resolve(fileURLToPath(new URL('..', import.meta.url)));
const PORT = 3992;
const BASE = `http://127.0.0.1:${PORT}`;
const SSO_ISSUER = 'https://sso-dev.dreamxwarden.ca';
const PORTAL_URL = 'https://account-e2e.example.com';
const REDIS_URL = 'redis://127.0.0.1:6379';

x509.cryptoProvider.set(webcrypto as unknown as Crypto);
const EC = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' };

let pass = 0;
let fail = 0;
const check = (n: string, ok: boolean, detail?: unknown) => {
  if (ok) {
    pass++;
    console.log('  ✓ ' + n);
  } else {
    fail++;
    console.error('  ✗ ' + n, detail !== undefined ? JSON.stringify(detail) : '');
  }
};

// The wizard's browser session: a cookie jar for setup_token.
let cookie = '';
async function req(
  method: string,
  p: string,
  body?: unknown,
): Promise<{ status: number; json: any; text: string }> {
  const r = await fetch(BASE + p, {
    method,
    headers: {
      ...(body !== undefined ? { 'content-type': 'application/json' } : {}),
      ...(cookie ? { cookie } : {}),
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
    redirect: 'manual',
    signal: AbortSignal.timeout(15_000),
  });
  const setCookie = r.headers.get('set-cookie');
  if (setCookie) cookie = setCookie.split(';')[0];
  const text = await r.text();
  let json: any = null;
  try {
    json = JSON.parse(text);
  } catch {
    /* html */
  }
  return { status: r.status, json, text };
}

// A throwaway CA that issues certs for a CSR's public key — stands in for Cloudflare.
const caKeys = (await webcrypto.subtle.generateKey(EC, true, ['sign', 'verify'])) as CryptoKeyPair;
async function issue(csrPem: string): Promise<string> {
  const csr = new x509.Pkcs10CertificateRequest(csrPem);
  const now = Date.now();
  const cert = await x509.X509CertificateGenerator.create({
    serialNumber: '02',
    subject: csr.subject,
    issuer: 'CN=Test CA',
    notBefore: new Date(now - 3600e3),
    notAfter: new Date(now + 365 * 864e5),
    signingAlgorithm: EC,
    publicKey: csr.publicKey,
    signingKey: caKeys.privateKey,
  });
  return cert.toString('pem');
}

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'dxw-bff-setup-'));
let child: ChildProcess | null = null;

// Boot the server with cwd = tmp: every file it touches (.env, .setup-token,
// .mtls.json, .account-client-key.json) defaults to a path under cwd, and dotenv
// finds no .env there — so this really is a fresh install.
function boot(): Promise<string> {
  return new Promise((resolve, reject) => {
    // detached: the tsx shim re-execs node, so killing the shim would orphan the
    // real server. Own process group -> kill(-pid) takes the whole tree down.
    child = spawn(path.join(SERVER_ROOT, 'node_modules/.bin/tsx'), [path.join(SERVER_ROOT, 'src/server.ts')], {
      cwd: tmp,
      env: { ...process.env, PORT: String(PORT), NODE_ENV: 'development', SPA_DIST: path.join(tmp, 'no-spa') },
      stdio: ['ignore', 'pipe', 'pipe'],
      detached: true,
    });
    let out = '';
    const t = setTimeout(() => reject(new Error('boot timeout: ' + out)), 20_000);
    child.stdout!.on('data', (d) => {
      out += d;
      const m = out.match(/\/setup\?token=(\S+)/);
      if (m) {
        clearTimeout(t);
        resolve(m[1]);
      }
    });
    child.stderr!.on('data', (d) => {
      out += d;
    });
    child.on('exit', (c) => {
      clearTimeout(t);
      reject(new Error(`server exited (${c}): ` + out));
    });
  });
}

try {
  console.log('portal setup e2e — workdir ' + tmp + '\n');

  // ---- boot in setup mode ----
  const token = await boot();
  check('boots unconfigured, logs a setup token', !!token);
  check('.setup-token written 0600', (fs.statSync(path.join(tmp, '.setup-token')).mode & 0o777) === 0o600);

  // ---- the gate ----
  check('GET / -> neutral 503', (await req('GET', '/')).status === 503);
  check('GET /api/me -> neutral 503', (await req('GET', '/api/me')).status === 503);
  check('GET /healthz -> 200 (open)', (await req('GET', '/healthz')).status === 200);
  check('GET /setup without a token -> the SAME 503', (await req('GET', '/setup')).status === 503);
  check('GET /setup?token=wrong -> 503', (await req('GET', '/setup?token=nope')).status === 503);

  const wiz = await req('GET', `/setup?token=${token}`);
  check('GET /setup?token=REAL -> the wizard', wiz.status === 200 && wiz.text.includes('Connect to your SSO') && wiz.text.includes('Client certificate'));
  check('  and drops the setup_token cookie', cookie.startsWith('setup_token='));

  // ---- step 1 state ----
  const env0 = (await req('GET', '/setup/env')).json;
  check('/setup/env: nothing configured yet', env0.configured === false && env0.hasClientKey === false);
  check('/setup/env: all three fields absent', !env0.fields.publicUrl.present && !env0.fields.issuer.present && !env0.fields.redis.present);

  // ---- validation (server-side, mirroring the client's red-on-blur) ----
  const bad = await req('POST', '/setup/config', { publicUrl: 'account.example.com', issuer: 'http://sso.x', redisUrl: 'nope' });
  check('bad input -> 422 with a field error each', bad.status === 422 && !!bad.json.errors.publicUrl && !!bad.json.errors.issuer && !!bad.json.errors.redis, bad.json);
  const badRedis = await req('POST', '/setup/config', { publicUrl: PORTAL_URL, issuer: SSO_ISSUER, redisUrl: 'redis://127.0.0.1:6399' });
  check('unreachable Redis -> 422 on the redis field', badRedis.status === 422 && /Could not connect/.test(badRedis.json.errors.redis ?? ''), badRedis.json);
  check('  nothing was written', !fs.existsSync(path.join(tmp, '.env')));

  // ---- SSO probe ----
  const pBad = (await req('GET', '/setup/probe-sso?url=' + encodeURIComponent('sso.example.com'))).json;
  check('probe: not a URL -> bad_url', pBad.ok === false && pBad.reason === 'bad_url');
  const pDown = (await req('GET', '/setup/probe-sso?url=' + encodeURIComponent('https://127.0.0.1:9'))).json;
  check('probe: nothing listening -> unreachable', pDown.ok === false && pDown.reachable === false);
  const pMis = (await req('GET', '/setup/probe-sso?url=' + encodeURIComponent('https://account-dev.dreamxwarden.ca'))).json;
  check('probe: an https host that is not an OP -> not ok', pMis.ok === false, pMis);
  const pOk = (await req('GET', '/setup/probe-sso?url=' + encodeURIComponent(SSO_ISSUER))).json;
  check('probe: the live SSO -> ok + matching issuer', pOk.ok === true && pOk.issuer === SSO_ISSUER, pOk);

  // ---- step 1 save ----
  const saved = await req('POST', '/setup/config', { publicUrl: PORTAL_URL + '/', issuer: SSO_ISSUER, redisUrl: REDIS_URL });
  check('valid config -> 200', saved.status === 200, saved.json);
  check('  mints an OIDC client key (created)', saved.json?.created === true && typeof saved.json.kid === 'string');
  check('  derives redirect_uri from the portal URL', saved.json?.redirectUri === PORTAL_URL + '/auth/callback');
  check('  derives jwks_uri + events_uri', saved.json?.jwksUri === PORTAL_URL + '/.well-known/jwks.json' && saved.json?.eventsUri === PORTAL_URL + '/backchannel/events');
  check('  trailing slash on the portal URL is normalized away', !saved.json?.redirectUri?.includes('//auth'));

  const envFile = fs.readFileSync(path.join(tmp, '.env'), 'utf8');
  check('.env written 0600', (fs.statSync(path.join(tmp, '.env')).mode & 0o777) === 0o600);
  check('.env carries the resolved + derived values', envFile.includes(`PUBLIC_URL=${PORTAL_URL}`) && envFile.includes(`SSO_ISSUER=${SSO_ISSUER}`) && envFile.includes(`OIDC_REDIRECT_URI=${PORTAL_URL}/auth/callback`) && envFile.includes('OIDC_CLIENT_ID=account'), envFile);

  const keyPath = path.join(tmp, '.account-client-key.json');
  const keyFile = JSON.parse(fs.readFileSync(keyPath, 'utf8')) as { keys: { kid: string; kty: string; crv: string; d?: string }[] };
  check('client key file 0600', (fs.statSync(keyPath).mode & 0o777) === 0o600);
  check('client key is a private Ed25519 JWK with the reported kid', keyFile.keys[0].kty === 'OKP' && keyFile.keys[0].crv === 'Ed25519' && !!keyFile.keys[0].d && keyFile.keys[0].kid === saved.json.kid);

  const env1 = (await req('GET', '/setup/env')).json;
  check('/setup/env now reports configured + a client key', env1.configured === true && env1.hasClientKey === true);
  check('  and the fields read back as present', env1.fields.publicUrl.value === PORTAL_URL && env1.fields.issuer.value === SSO_ISSUER);
  check('the gate is still shut (setup is not finished)', (await req('GET', '/api/me')).status === 503);

  // ---- re-running the config step is idempotent (does not re-mint the key) ----
  const again = await req('POST', '/setup/config', { publicUrl: PORTAL_URL, issuer: SSO_ISSUER, redisUrl: REDIS_URL });
  check('re-save keeps the existing key (created=false, same kid)', again.json?.created === false && again.json?.kid === saved.json.kid);

  // ---- mTLS (optional step) ----
  const m0 = (await req('GET', '/setup/mtls')).json;
  check('mTLS starts not_configured', m0.state === 'not_configured' && m0.pending === false);

  const csrRes = await req('POST', '/setup/mtls/start', { cn: 'portal-e2e' });
  check('CSR generated, CN preserved', csrRes.status === 200 && csrRes.json.cn === 'portal-e2e' && csrRes.json.csr.includes('BEGIN CERTIFICATE REQUEST'));
  const csrKey = new x509.Pkcs10CertificateRequest(csrRes.json.csr).publicKey.algorithm;
  check('  key is ECDSA P-256 (ECC, as Cloudflare issues)', JSON.stringify(csrKey).includes('P-256'));
  check('  status now shows a pending key', (await req('GET', '/setup/mtls')).json.pending === true);
  check('  the private key never left the server', !JSON.stringify(csrRes.json).includes('PRIVATE KEY'));

  const junk = await req('POST', '/setup/mtls/install', { cert: 'not a certificate' });
  check('garbage cert -> 422 parse_failed', junk.status === 422 && junk.json.reason === 'parse_failed');

  const cert = await issue(csrRes.json.csr);
  const inst = await req('POST', '/setup/mtls/install', { cert });
  check('issued cert installs', inst.status === 200 && inst.json.ok === true, inst.json);
  check('  status: configured + enforcing + right CN', inst.json.state === 'configured' && inst.json.enforce === true && inst.json.cn === 'portal-e2e');
  const mtlsState = JSON.parse(fs.readFileSync(path.join(tmp, '.mtls.json'), 'utf8')) as { key: string; cert: string; enforce: boolean };
  check('.mtls.json written 0600', (fs.statSync(path.join(tmp, '.mtls.json')).mode & 0o777) === 0o600);
  check('  holds the private key + cert, enforcement on', mtlsState.key.includes('BEGIN PRIVATE KEY') && mtlsState.cert.includes('BEGIN CERTIFICATE') && mtlsState.enforce === true);

  // ---- finish ----
  check('finish -> 204', (await req('POST', '/setup/finish')).status === 204);
  check('the setup token is burned', !fs.existsSync(path.join(tmp, '.setup-token')));
  check('/setup is gone (404, not 503)', (await req('GET', `/setup?token=${token}`)).status === 404);
  check('/setup/config is gone too', (await req('POST', '/setup/config', {})).status === 404);

  // ---- the portal is live ----
  check('GET /api/me -> 401 (route reached, no session)', (await req('GET', '/api/me')).status === 401);
  const jwks = await req('GET', '/.well-known/jwks.json');
  check('jwks_uri serves the PUBLIC key (the SSO reads it from here)', jwks.status === 200 && jwks.json.keys[0].kid === saved.json.kid && jwks.json.keys[0].d === undefined, jwks.json);
  const health = (await req('GET', '/healthz')).json;
  check('healthz reports the adopted issuer (in-process, no restart)', health.issuer === SSO_ISSUER && health.client === 'account');
} catch (e) {
  fail++;
  console.error('EXCEPTION:', e);
} finally {
  if (child?.pid) {
    try {
      process.kill(-child.pid, 'SIGKILL'); // the whole group, not just the shim
    } catch {
      child.kill('SIGKILL');
    }
  }
  fs.rmSync(tmp, { recursive: true, force: true });
}

console.log(`\nportal setup e2e: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
