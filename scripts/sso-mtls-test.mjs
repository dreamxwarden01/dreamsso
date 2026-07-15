// E2E for videosite's SSO connection + mTLS admin endpoints. Logs in as the
// admin, then drives the mTLS lifecycle. Certs are issued from the server's CSR
// with node-forge (mtlsService only checks expiry + public-key match, not CA
// trust, so a throwaway CA signature is fine). Usage: node scripts/sso-mtls-test.mjs
import forge from 'node-forge';
import { answerKmsi } from './lib/kmsi.mjs';
import { generateKeyPairSync } from 'node:crypto';

const STREAM = 'https://stream-dev.dreamxwarden.ca';
const SSO = 'https://sso-dev.dreamxwarden.ca';
const USER = process.argv[2] || 'tester';
const PASS = process.argv[3] || 'Test1234!';

let fail = 0, sid = '';
const ok = (c, label, extra = '') => { console.log(`${c ? '✓' : '✗ FAIL'}  ${label}${extra ? '  ' + extra : ''}`); if (!c) fail++; };
const gsc = (res, name) => { for (const c of res.headers.getSetCookie?.() ?? []) { const nv = c.split(';')[0], i = nv.indexOf('='); if (i > 0 && nv.slice(0, i) === name) return nv.slice(i + 1); } return null; };
const api = (path, opts = {}) => fetch(STREAM + path, { ...opts, headers: { cookie: 'sid=' + sid, 'content-type': 'application/json', ...(opts.headers || {}) } });

const caKey = forge.pki.privateKeyFromPem(generateKeyPairSync('rsa', { modulusLength: 2048, privateKeyEncoding: { type: 'pkcs8', format: 'pem' }, publicKeyEncoding: { type: 'spki', format: 'pem' } }).privateKey);
function issueFromCsr(csrPem, days) {
  const csr = forge.pki.certificationRequestFromPem(csrPem);
  return issue(csr.publicKey, csr.subject.attributes, days);
}
function issueRandom(days) {
  const kp = forge.pki.publicKeyFromPem(generateKeyPairSync('rsa', { modulusLength: 2048, publicKeyEncoding: { type: 'spki', format: 'pem' }, privateKeyEncoding: { type: 'pkcs8', format: 'pem' } }).publicKey);
  return issue(kp, [{ name: 'commonName', value: 'someone-else' }], days);
}
function issue(pubKey, subject, days) {
  const cert = forge.pki.createCertificate();
  cert.publicKey = pubKey; cert.serialNumber = '01';
  cert.validity.notBefore = new Date(Date.now() - 86400000);
  cert.validity.notAfter = new Date(Date.now() + days * 86400000);
  cert.setSubject(subject); cert.setIssuer([{ name: 'commonName', value: 'Test CA' }]);
  cert.sign(caKey, forge.md.sha256.create());
  return forge.pki.certificateToPem(cert);
}

// --- login (videosite admin) ---
let r = await fetch(STREAM + '/auth/login', { redirect: 'manual' });
const flow = gsc(r, 'oidc_flow');
r = await fetch(r.headers.get('location'), { redirect: 'manual' });
const txn = new URL(r.headers.get('location'), SSO).searchParams.get('txn');
r = await fetch(SSO + '/login?txn=' + encodeURIComponent(txn));
const csrf = ((await r.text()).match(/name="csrf" value="([^"]+)"/) || [])[1];
r = await fetch(SSO + '/login', { method: 'POST', redirect: 'manual', headers: { 'content-type': 'application/x-www-form-urlencoded', origin: 'null', 'sec-fetch-site': 'same-origin' }, body: new URLSearchParams({ txn, csrf, username: USER, password: PASS }) });
r = await answerKmsi(SSO, r, txn, csrf); // KMSI precedes every code mint
const cb = new URL(r.headers.get('location'));
r = await fetch(`${STREAM}/auth/callback?code=${cb.searchParams.get('code')}&state=${cb.searchParams.get('state')}`, { redirect: 'manual', headers: { cookie: 'oidc_flow=' + flow } });
sid = gsc(r, 'sid');
ok(!!sid, '0. admin login -> sid');

// --- connection config ---
r = await api('/api/sso/config'); const cfg = await r.json();
ok(r.status === 200 && cfg.issuer && cfg.client_id === 'videosite', '1. GET config', `(issuer=${cfg.issuer})`);
r = await api('/api/sso/config', { method: 'PUT', body: JSON.stringify({ ...cfg, issuer: 'notaurl' }) });
ok(r.status === 422 && (await r.json()).errors?.issuer, '2. PUT invalid issuer -> 422');
r = await api('/api/sso/config', { method: 'PUT', body: JSON.stringify(cfg) });
ok(r.status === 204, '3. PUT valid config -> 204');

// --- mTLS lifecycle ---
r = await api('/api/sso/mtls'); ok((await r.json()).state === 'not_configured', '4. mTLS not_configured');

r = await api('/api/sso/mtls/csr', { method: 'POST', body: JSON.stringify({ cn: '' }) });
const s1 = await r.json();
ok(r.status === 200 && /BEGIN CERTIFICATE REQUEST/.test(s1.csr) && /^videosite-/.test(s1.cn), '5. CSR generated, CN auto', `(${s1.cn})`);

r = await api('/api/sso/mtls/cert', { method: 'POST', body: JSON.stringify({ cert: issueFromCsr(s1.csr, 3650) }) });
const inst = await r.json();
ok(r.status === 200 && inst.cn === s1.cn && !inst.expired, '6. install valid cert -> ok', `(expires ${inst.expires})`);

r = await api('/api/sso/mtls'); const st = await r.json();
ok(st.state === 'configured' && st.enforce === false, '7. status configured, enforce off');

r = await api('/api/sso/mtls/enforce', { method: 'PUT', body: JSON.stringify({ enabled: true }) });
ok(r.status === 204, '8. enable enforce -> 204');
r = await api('/api/sso/mtls'); ok((await r.json()).enforce === true, '9. enforce now on');

// new pending key, then reject expired + mismatch
r = await api('/api/sso/mtls/csr', { method: 'POST', body: JSON.stringify({ cn: 'videosite-renew' }) });
const s2 = await r.json();
r = await api('/api/sso/mtls/cert', { method: 'POST', body: JSON.stringify({ cert: issueFromCsr(s2.csr, -1) }) });
ok(r.status === 422 && (await r.json()).error === 'expired', '10. expired cert -> 422 expired');
r = await api('/api/sso/mtls/cert', { method: 'POST', body: JSON.stringify({ cert: issueRandom(3650) }) });
ok(r.status === 422 && (await r.json()).error === 'key_mismatch', '11. wrong-key cert -> 422 key_mismatch');
r = await api('/api/sso/mtls/cert', { method: 'POST', body: JSON.stringify({ cert: issueFromCsr(s2.csr, 3650) }) });
ok(r.status === 200 && (await r.json()).cn === 'videosite-renew', '12. valid cert for pending key -> installed');

// reset
r = await api('/api/sso/mtls', { method: 'DELETE' }); ok(r.status === 204, '13. reset -> 204');
r = await api('/api/sso/mtls'); ok((await r.json()).state === 'not_configured', '14. back to not_configured');

console.log(fail ? `\n${fail} check(s) FAILED ✗` : '\nALL CHECKS PASSED ✓');
process.exit(fail ? 1 : 0);
