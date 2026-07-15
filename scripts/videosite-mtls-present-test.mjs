// Videosite outbound mTLS presentation check:
//   - host runs an mTLS-requesting TLS server on 0.0.0.0:8895
//   - a script EXEC'D INSIDE the videosite container drives the real modules
//     (mtlsService + s2sFetch): setup -> in-container throwaway CA signs the
//     CSR -> install -> enforce on -> s2sFetch to host.docker.internal ->
//     enforce off -> second call; site_settings mtls rows snapshot/restored.
//   - the host asserts what the TLS server actually saw: CN, then nothing.
// Run: node scripts/videosite-mtls-present-test.mjs
import 'reflect-metadata';
import https from 'node:https';
import { webcrypto } from 'node:crypto';
import { spawn } from 'node:child_process';
import * as x509 from '@peculiar/x509';

x509.cryptoProvider.set(webcrypto);
const EC = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' };

let fail = 0;
const ok = (c, label, extra = '') => {
  console.log(`${c ? '✓' : '✗ FAIL'}  ${label}${extra ? '  ' + extra : ''}`);
  if (!c) fail++;
};

// --- host TLS server (self-signed EC) that records presented client certs ---
const srvKeys = await webcrypto.subtle.generateKey(EC, true, ['sign', 'verify']);
const srvCert = await x509.X509CertificateGenerator.createSelfSigned({
  serialNumber: '01',
  name: 'CN=host-mtls-probe',
  notBefore: new Date(Date.now() - 86400000),
  notAfter: new Date(Date.now() + 7 * 86400000),
  keys: srvKeys,
  signingAlgorithm: EC,
});
const pkcs8 = Buffer.from(await webcrypto.subtle.exportKey('pkcs8', srvKeys.privateKey));
const srvKeyPem =
  '-----BEGIN PRIVATE KEY-----\n' + pkcs8.toString('base64').match(/.{1,64}/g).join('\n') + '\n-----END PRIVATE KEY-----\n';

const seen = [];
const server = https.createServer(
  { key: srvKeyPem, cert: srvCert.toString('pem'), requestCert: true, rejectUnauthorized: false },
  (req, res) => {
    const peer = req.socket.getPeerCertificate();
    seen.push(peer && Object.keys(peer).length ? (peer.subject?.CN ?? null) : null);
    res.end('{}');
  },
);
await new Promise((resolve) => server.listen(8895, '0.0.0.0', resolve));

// --- script exec'd inside the container (real modules, real settings table) ---
const inner = `
require('reflect-metadata');
(async () => {
  await require('/app/services/redis').connect(); // settings cache lives on Redis
  const { getPool } = require('/app/config/database');
  const pool = getPool();
  const [snap] = await pool.execute("SELECT setting_key, setting_value FROM site_settings WHERE setting_key LIKE 'mtls\\\\_%'");
  const mtls = require('/app/services/mtlsService');
  const { s2sFetch } = require('/app/services/s2sFetch');
  const cache = require('/app/services/cache/settingsCache');
  let code = 0;
  try {
    const { csr } = await mtls.startSetup('vs-mtls-e2e');
    const x509 = require('@peculiar/x509');
    const { webcrypto } = require('crypto');
    x509.cryptoProvider.set(webcrypto);
    const EC = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' };
    const caKeys = await webcrypto.subtle.generateKey(EC, true, ['sign', 'verify']);
    const ca = await x509.X509CertificateGenerator.createSelfSigned({
      serialNumber: '01', name: 'CN=vs-e2e-ca',
      notBefore: new Date(Date.now() - 864e5), notAfter: new Date(Date.now() + 30 * 864e5),
      keys: caKeys, signingAlgorithm: EC,
      extensions: [new x509.BasicConstraintsExtension(true, undefined, true)],
    });
    // intermediate -> leaf, then paste the chain in the WRONG order (intermediate
    // first) — exercises videosite's leaf detection + leaf-first normalization.
    const intKeys = await webcrypto.subtle.generateKey(EC, true, ['sign', 'verify']);
    const intCert = await x509.X509CertificateGenerator.create({
      serialNumber: '02', subject: 'CN=vs-e2e-int', issuer: ca.subject,
      notBefore: new Date(Date.now() - 864e5), notAfter: new Date(Date.now() + 30 * 864e5),
      publicKey: intKeys.publicKey, signingKey: caKeys.privateKey, signingAlgorithm: EC,
      extensions: [new x509.BasicConstraintsExtension(true, undefined, true)],
    });
    const req = new x509.Pkcs10CertificateRequest(csr);
    const cert = await x509.X509CertificateGenerator.create({
      serialNumber: '03', subject: 'CN=vs-mtls-e2e', issuer: intCert.subject,
      notBefore: new Date(Date.now() - 864e5), notAfter: new Date(Date.now() + 30 * 864e5),
      publicKey: req.publicKey, signingKey: intKeys.privateKey, signingAlgorithm: EC,
    });
    const inst = await mtls.installCert(intCert.toString('pem') + '\\n' + cert.toString('pem'));
    console.log('inner install:', inst.ok === true, '| issuer:', inst.issuer);
    console.log('inner enforce-on:', (await mtls.setEnforce(true)).ok === true);
    let r = await s2sFetch('https://host.docker.internal:8895/', { method: 'POST', body: new URLSearchParams({ p: '1' }) });
    console.log('inner call1:', r.ok);
    await mtls.setEnforce(false);
    r = await s2sFetch('https://host.docker.internal:8895/', { method: 'POST', body: new URLSearchParams({ p: '2' }) });
    console.log('inner call2:', r.ok);
  } catch (e) {
    console.error('inner ERR:', e.message, '| cause:', e.cause && (e.cause.message || e.cause.code));
    code = 1;
  } finally {
    await pool.execute("DELETE FROM site_settings WHERE setting_key LIKE 'mtls\\\\_%'");
    for (const row of snap) {
      await pool.execute('INSERT INTO site_settings (setting_key, setting_value) VALUES (?, ?)', [row.setting_key, row.setting_value]);
    }
    await cache.invalidate();
    await require('/app/services/redis').quit().catch(() => {});
    process.exit(code);
  }
})();
`;

// async spawn — spawnSync would freeze this process's event loop and the TLS
// server above could never answer the container's requests.
const run = await new Promise((resolve) => {
  const child = spawn(
    'docker',
    ['compose', 'exec', '-T', '-e', 'NODE_TLS_REJECT_UNAUTHORIZED=0', 'videosite-web', 'node', '-e', inner],
    { cwd: new URL('..', import.meta.url).pathname },
  );
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', (d) => { stdout += d; });
  child.stderr.on('data', (d) => { stderr += d; });
  const t = setTimeout(() => child.kill('SIGKILL'), 120000);
  child.on('close', (status) => { clearTimeout(t); resolve({ status, stdout, stderr }); });
});
process.stdout.write(run.stdout || '');
if (run.status !== 0) process.stderr.write(run.stderr || '');

ok(run.status === 0 && /inner install: true \| issuer: vs-e2e-int/.test(run.stdout) && /inner call1: true/.test(run.stdout),
   '1. in-container ceremony (wrong-order fullchain -> leaf found) + calls completed');
ok(seen[0] === 'vs-mtls-e2e', '2. enforce ON -> videosite presented its client cert', `(peer CN: ${seen[0]})`);
ok(seen[1] === null, '3. enforce OFF -> no cert presented', `(peer: ${seen[1]})`);

server.close();
console.log(fail ? `\n${fail} FAILED ✗` : '\nALL CHECKS PASSED ✓');
process.exit(fail ? 1 : 0);
