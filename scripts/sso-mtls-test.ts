// E2E for the SSO's service-mTLS card backend + outbound presentation:
//   ECDSA P-256 key + PKCS#10 CSR (@peculiar/x509), full ceremony with a
//   throwaway LOCAL CA (no Cloudflare): csr -> sign -> install
//   validation reasons: no_cert / parse_failed / key_mismatch / expired / not_configured
//   renew path (no pending key -> cert swaps, key kept)
//   fullchain paste (any order) -> leaf detected, chain normalized + presented
//   status carries issuer + not_before/not_after as ISO UTC (client renders local)
//   enforce toggle; s2sFetch PRESENTS the client cert to an mTLS-requiring
//   local TLS server when enforcement is on, and does not when off
// State: snapshots all mtls_* settings rows and restores them verbatim.
// Run: npx tsx scripts/sso-mtls-test.ts
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'; // test TLS server is self-signed

import 'reflect-metadata'; // must load before @peculiar/x509 (tsyringe polyfill)
import https from 'node:https';
import { webcrypto } from 'node:crypto';
import type { TLSSocket } from 'node:tls';
import * as x509 from '@peculiar/x509';
import { answerKmsi } from './lib/kmsi.mjs';
import { pool } from '../src/db.js';
import { s2sFetch } from '../src/s2sFetch.js';

x509.cryptoProvider.set(webcrypto as Crypto);

const SSO = 'https://sso-dev.dreamxwarden.ca';
const USER = 'tester';
const PASS = 'Test1234!';
const EC = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' } as const;

let fail = 0;
const ok = (c: boolean, label: string, extra = '') => {
  console.log(`${c ? '✓' : '✗ FAIL'}  ${label}${extra ? '  ' + extra : ''}`);
  if (!c) fail++;
};
const setCookie = (r: Response, n: string) => {
  for (const c of r.headers.getSetCookie?.() ?? []) {
    const nv = c.split(';')[0];
    const i = nv.indexOf('=');
    if (i > 0 && nv.slice(0, i) === n) return nv.slice(i + 1);
  }
  return null;
};
const pemKey = async (k: CryptoKey) =>
  '-----BEGIN PRIVATE KEY-----\n' +
  Buffer.from(await webcrypto.subtle.exportKey('pkcs8', k)).toString('base64').match(/.{1,64}/g)!.join('\n') +
  '\n-----END PRIVATE KEY-----\n';

// --- throwaway CA + cert factory (what Cloudflare does for us in prod) ---
const caKeys = (await webcrypto.subtle.generateKey(EC, true, ['sign', 'verify'])) as CryptoKeyPair;
const caCert = await x509.X509CertificateGenerator.createSelfSigned({
  serialNumber: '01',
  name: 'CN=mtls-e2e-ca',
  notBefore: new Date(Date.now() - 86400000),
  notAfter: new Date(Date.now() + 30 * 86400000),
  keys: caKeys,
  signingAlgorithm: EC,
  extensions: [new x509.BasicConstraintsExtension(true, undefined, true)],
});

let serial = 2;
async function signCert(
  publicKey: x509.PublicKey | CryptoKey, cn: string, days: number, from = new Date(),
  opts: { issuer?: x509.X509Certificate; signingKey?: CryptoKey; isCa?: boolean } = {},
): Promise<string> {
  const cert = await x509.X509CertificateGenerator.create({
    serialNumber: '0' + (serial++).toString(16),
    subject: `CN=${cn}`,
    issuer: (opts.issuer ?? caCert).subject,
    notBefore: from,
    notAfter: new Date(from.getTime() + days * 86400000),
    publicKey,
    signingKey: opts.signingKey ?? caKeys.privateKey,
    signingAlgorithm: EC,
    extensions: opts.isCa ? [new x509.BasicConstraintsExtension(true, undefined, true)] : [],
  });
  return cert.toString('pem');
}

// --- snapshot mtls settings for verbatim restore ---
const { rows: snapshot } = await pool.query<{ key: string; value: string }>(
  "SELECT key, value FROM settings WHERE key LIKE 'mtls_%'",
);

// --- park step-up, grant admin perm, local login (standard preamble) ---
const { rows: suOrig } = await pool.query<{ value: string }>(
  `SELECT value FROM settings WHERE key = 'stepup_admin_required'`);
await pool.query(`INSERT INTO settings (key, value) VALUES ('stepup_admin_required', 'false')
  ON CONFLICT (key) DO UPDATE SET value = 'false'`);
await new Promise((r) => setTimeout(r, 5500)); // outwait the settings cache
const { rows: [{ sub }] } = await pool.query('SELECT sub FROM identities WHERE username = $1', [USER]);
await pool.query(
  `INSERT INTO user_permission_overrides (user_sub, perm_key, effect) VALUES ($1, 'org.siteSettings.sso', 'grant')
     ON CONFLICT (user_sub, perm_key) DO UPDATE SET effect = 'grant'`, [sub]);

let r = await fetch(SSO + '/admin/start-login', { redirect: 'manual' });
const txn = new URL(r.headers.get('location')!, SSO).searchParams.get('txn')!;
r = await fetch(SSO + '/login?txn=' + encodeURIComponent(txn));
const csrfForm = ((await r.text()).match(/name="csrf" value="([^"]+)"/) || [])[1];
r = await fetch(SSO + '/login', {
  method: 'POST', redirect: 'manual',
  headers: { 'content-type': 'application/x-www-form-urlencoded', origin: 'null', 'sec-fetch-site': 'same-origin' },
  body: new URLSearchParams({ txn, csrf: csrfForm, username: USER, password: PASS }),
});
const cookie = 'sso_session=' + setCookie(r, 'sso_session');
r = await answerKmsi(SSO, r, txn, csrfForm, { cookie });
const api = (method: string, path: string, csrf?: string, body?: unknown) =>
  fetch(SSO + path, {
    method,
    headers: {
      cookie,
      ...(csrf ? { 'x-csrf-token': csrf } : {}),
      ...(body ? { 'content-type': 'application/json' } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
const csrf = ((await (await api('GET', '/admin/api/me')).json()) as { csrf: string }).csrf;

// 1. clean slate
r = await api('DELETE', '/admin/api/mtls', csrf);
ok(r.status === 204, '1. reset -> 204', `(${r.status})`);
r = await api('GET', '/admin/api/mtls');
let st = (await r.json()) as Record<string, unknown>;
ok(st.state === 'not_configured' && st.pending === false, '1a. status not_configured, no pending');

// 2. enforce before setup -> refused
r = await api('PUT', '/admin/api/mtls/enforce', csrf, { enabled: true });
ok(r.status === 422 && (await r.json()).error === 'not_configured', '2. enforce unconfigured -> 422');

// 3. CSR generation — ECDSA P-256
r = await api('POST', '/admin/api/mtls/csr', csrf, { cn: 'sso-mtls-e2e' });
const { cn, csr } = (await r.json()) as { cn: string; csr: string };
const csrObj = new x509.Pkcs10CertificateRequest(csr);
const csrAlg = csrObj.publicKey.algorithm as { name: string; namedCurve?: string };
ok(r.status === 200 && cn === 'sso-mtls-e2e' && (await csrObj.verify()) &&
   csrObj.subject === 'CN=sso-mtls-e2e' && csrAlg.name === 'ECDSA' && csrAlg.namedCurve === 'P-256',
   '3. CSR: valid PKCS#10, ECDSA P-256, CN as requested');
st = await (await api('GET', '/admin/api/mtls')).json();
ok(st.state === 'not_configured' && st.pending === true, '3a. pending key recorded, still not configured');

// 4. paste rejections
r = await api('POST', '/admin/api/mtls/cert', csrf, { cert: 'garbage' });
ok(r.status === 422 && (await r.json()).error === 'parse_failed', '4. garbage -> 422 parse_failed');
const stranger = (await webcrypto.subtle.generateKey(EC, true, ['sign', 'verify'])) as CryptoKeyPair;
r = await api('POST', '/admin/api/mtls/cert', csrf, { cert: await signCert(stranger.publicKey, 'stranger', 30) });
ok(r.status === 422 && (await r.json()).error === 'key_mismatch', '4a. cert for another key -> 422 key_mismatch');
r = await api('POST', '/admin/api/mtls/cert', csrf,
  { cert: await signCert(csrObj.publicKey, cn, 1, new Date(Date.now() - 10 * 86400000)) });
ok(r.status === 422 && (await r.json()).error === 'expired', '4b. expired cert -> 422 expired');

// 5. install the properly signed cert (throwaway local CA — CF's role in prod)
r = await api('POST', '/admin/api/mtls/cert', csrf, { cert: await signCert(csrObj.publicKey, cn, 30) });
const inst = (await r.json()) as Record<string, unknown>;
ok(r.status === 200 && inst.ok === true && inst.cn === cn, '5. install -> configured', `(${inst.cn})`);
st = await (await api('GET', '/admin/api/mtls')).json();
const isoUtc = (v: unknown) => typeof v === 'string' && /Z$/.test(v) && !Number.isNaN(Date.parse(v));
ok(st.state === 'configured' && st.enforce === false && st.cn === cn && st.expired === false,
   '5a. status configured, enforce off');
ok(st.issuer === 'mtls-e2e-ca' && isoUtc(st.not_before) && isoUtc(st.not_after),
   '5b. issuer + ISO-UTC validity bounds', `(${st.issuer}, ${st.not_after})`);
const na1 = st.not_after as string;

// 6. renew: new cert for the SAME key (no fresh CSR), enforce state untouched
r = await api('PUT', '/admin/api/mtls/enforce', csrf, { enabled: true });
ok(r.status === 204, '6. enforce on -> 204');
r = await api('POST', '/admin/api/mtls/cert', csrf, { cert: await signCert(csrObj.publicKey, cn, 60) });
ok(r.status === 200, '6a. renew (same key) accepted');
st = await (await api('GET', '/admin/api/mtls')).json();
ok(st.state === 'configured' && st.enforce === true && st.not_after !== na1,
   '6b. cert swapped, enforcement stayed on');

// 7. outbound presentation: local TLS server that REQUESTS a client cert
const srvKeys = (await webcrypto.subtle.generateKey(EC, true, ['sign', 'verify'])) as CryptoKeyPair;
const srvCert = await signCert(srvKeys.publicKey, '127.0.0.1', 7);
const seen: (string | null)[] = [];
const server = https.createServer(
  {
    key: await pemKey(srvKeys.privateKey),
    cert: srvCert,
    requestCert: true,
    rejectUnauthorized: false, // record what was presented; trust checks are CF's job
  },
  (req, res) => {
    const peer = (req.socket as TLSSocket).getPeerCertificate();
    seen.push(peer && Object.keys(peer).length ? (peer.subject?.CN ?? null) : null);
    res.setHeader('content-type', 'application/json');
    res.end('{}');
  },
);
await new Promise<void>((resolve) => server.listen(8896, '127.0.0.1', resolve));

r = await s2sFetch('https://127.0.0.1:8896/', { method: 'POST', body: new URLSearchParams({ ping: '1' }) });
ok(r.ok && seen[0] === cn, '7. enforce ON -> client cert presented', `(peer CN: ${seen[0]})`);

r = await api('PUT', '/admin/api/mtls/enforce', csrf, { enabled: false });
ok(r.status === 204, '7a. enforce off -> 204');
await new Promise((res) => setTimeout(res, 5500)); // outwait this process's settings cache
r = await s2sFetch('https://127.0.0.1:8896/', { method: 'POST', body: new URLSearchParams({ ping: '2' }) });
ok(r.ok && seen[1] === null, '7b. enforce OFF -> no cert presented', `(peer: ${seen[1]})`);
server.close();

// 8. full chain (leaf + intermediate), pasted in the WRONG order (intermediate
// first): the leaf is found by key match, expiry checked on it, and the stored
// chain is normalized leaf-first.
const intKeys = (await webcrypto.subtle.generateKey(EC, true, ['sign', 'verify'])) as CryptoKeyPair;
const intPem = await signCert(intKeys.publicKey, 'mtls-e2e-int', 30, new Date(), { isCa: true });
const intCert = new x509.X509Certificate(intPem);
const chainLeaf = await signCert(csrObj.publicKey, cn, 30, new Date(), { issuer: intCert, signingKey: intKeys.privateKey });
r = await api('POST', '/admin/api/mtls/cert', csrf, { cert: intPem + '\n' + chainLeaf });
ok(r.status === 200, '8. wrong-order fullchain accepted (leaf found by key)');
st = await (await api('GET', '/admin/api/mtls')).json();
ok(st.cn === cn && st.issuer === 'mtls-e2e-int', '8a. status describes the LEAF (issuer = intermediate CN)');

// 8b. the whole chain is presented: this probe TRUSTS ONLY THE ROOT, so
// socket.authorized === true is only possible if the intermediate traveled.
r = await api('PUT', '/admin/api/mtls/enforce', csrf, { enabled: true });
ok(r.status === 204, '8b. enforce back on -> 204');
await new Promise((res) => setTimeout(res, 5500)); // outwait this process's settings cache
const seen2: { cn: string | null; authorized: boolean }[] = [];
const server2 = https.createServer(
  {
    key: await pemKey(srvKeys.privateKey),
    cert: srvCert,
    requestCert: true,
    rejectUnauthorized: false,
    ca: [caCert.toString('pem')], // root only — NOT the intermediate
  },
  (req, res) => {
    const sock = req.socket as TLSSocket;
    const peer = sock.getPeerCertificate();
    seen2.push({ cn: peer && Object.keys(peer).length ? (peer.subject?.CN ?? null) : null, authorized: sock.authorized });
    res.end('{}');
  },
);
await new Promise<void>((resolve) => server2.listen(8894, '127.0.0.1', resolve));
r = await s2sFetch('https://127.0.0.1:8894/', { method: 'POST', body: new URLSearchParams({ ping: '3' }) });
ok(r.ok && seen2[0]?.cn === cn && seen2[0]?.authorized === true,
   '8c. chain verified to the root at the probe -> intermediate was presented',
   `(CN: ${seen2[0]?.cn}, authorized: ${seen2[0]?.authorized})`);
server2.close();

// 9. reset clears everything
r = await api('DELETE', '/admin/api/mtls', csrf);
st = await (await api('GET', '/admin/api/mtls')).json();
ok(r.status === 204 && st.state === 'not_configured' && st.pending === false, '9. reset -> not_configured');

// --- restore: mtls settings verbatim, perm, step-up flag ---
await pool.query("DELETE FROM settings WHERE key LIKE 'mtls_%'");
for (const row of snapshot) {
  await pool.query('INSERT INTO settings (key, value) VALUES ($1, $2)', [row.key, row.value]);
}
await pool.query(`DELETE FROM user_permission_overrides WHERE user_sub = $1 AND perm_key = 'org.siteSettings.sso'`, [sub]);
if (suOrig[0]) {
  await pool.query(`UPDATE settings SET value = $1 WHERE key = 'stepup_admin_required'`, [suOrig[0].value]);
} else {
  await pool.query(`DELETE FROM settings WHERE key = 'stepup_admin_required'`);
}

console.log(fail ? `\n${fail} FAILED ✗` : '\nALL CHECKS PASSED ✓');
await pool.end();
process.exit(fail ? 1 : 0);
