// Unit test for the portal's mTLS client-certificate lifecycle:
//   ECDSA P-256 key + PKCS#10 CSR -> cert issued by a CA (stands in for Cloudflare)
//   -> install (validates key-match + expiry, normalizes the chain LEAF-FIRST,
//   auto-enables) -> outboundIdentity feeds the undici agent.
// Also covers the rejection paths: garbage, wrong key, expired.
// Run: npx tsx scripts/mtls-test.ts
import 'reflect-metadata';
import * as x509 from '@peculiar/x509';
import { webcrypto, X509Certificate } from 'node:crypto';
import fs from 'node:fs';

const STATE = '/tmp/dxw-mtls-test.json';
process.env.MTLS_STATE_FILE = STATE;
fs.rmSync(STATE, { force: true });

const mtls = await import('../src/mtls.js');
x509.cryptoProvider.set(webcrypto as unknown as Crypto);
const EC = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' };

let pass = 0;
let fail = 0;
const check = (n: string, c: boolean) => {
  if (c) { pass++; console.log('  ✓ ' + n); } else { fail++; console.error('  ✗ ' + n); }
};

// A throwaway CA that issues certs for a CSR's public key — stands in for Cloudflare.
const caKeys = (await webcrypto.subtle.generateKey(EC, true, ['sign', 'verify'])) as CryptoKeyPair;
let caCertPem = '';
async function makeCa() {
  const c = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: '01', name: 'CN=Test CA',
    notBefore: new Date(Date.now() - 3600e3), notAfter: new Date(Date.now() + 3650 * 864e5),
    signingAlgorithm: EC, keys: caKeys,
  });
  caCertPem = c.toString('pem');
}
async function issue(csrPem: string, opts: { expired?: boolean } = {}) {
  const csr = new x509.Pkcs10CertificateRequest(csrPem);
  const now = Date.now();
  const cert = await x509.X509CertificateGenerator.create({
    serialNumber: '02',
    subject: csr.subject,
    issuer: 'CN=Test CA',
    notBefore: opts.expired ? new Date(now - 20 * 864e5) : new Date(now - 3600e3),
    notAfter: opts.expired ? new Date(now - 10 * 864e5) : new Date(now + 365 * 864e5),
    signingAlgorithm: EC,
    publicKey: csr.publicKey,
    signingKey: caKeys.privateKey,
  });
  return cert.toString('pem');
}

try {
  await makeCa();

  // --- step 1: key + CSR ---
  const { cn, csr } = await mtls.startSetup('portal-test');
  check('CSR generated, CN preserved', cn === 'portal-test' && csr.includes('BEGIN CERTIFICATE REQUEST'));
  const parsedCsr = new x509.Pkcs10CertificateRequest(csr);
  check('CSR key is ECDSA P-256 (ECC)', JSON.stringify(parsedCsr.publicKey.algorithm).includes('P-256'));
  check('status: not_configured + pending key', (() => {
    const s = mtls.getStatus(); return s.state === 'not_configured' && s.pending === true;
  })());
  check('no outbound identity before a cert', mtls.outboundIdentity() === null);

  // --- rejection paths ---
  check('garbage cert -> parse_failed', (mtls.installCert('not a cert') as { reason?: string }).reason === 'parse_failed');

  const otherCsr = (await (async () => {
    const k = (await webcrypto.subtle.generateKey(EC, true, ['sign', 'verify'])) as CryptoKeyPair;
    const c = await x509.Pkcs10CertificateRequestGenerator.create({ name: [{ CN: ['someone-else'] }], keys: k, signingAlgorithm: EC });
    return c.toString('pem');
  })());
  const wrongCert = await issue(otherCsr);
  check('cert for a DIFFERENT key -> key_mismatch', (mtls.installCert(wrongCert) as { reason?: string }).reason === 'key_mismatch');

  const expiredCert = await issue(csr, { expired: true });
  check('expired cert -> expired', (mtls.installCert(expiredCert) as { reason?: string }).reason === 'expired');

  // --- happy path: install a CHAIN, intermediate-first (must normalize leaf-first) ---
  const leaf = await issue(csr);
  const chainInput = caCertPem + '\n' + leaf; // deliberately CA first
  const res = mtls.installCert(chainInput) as { ok: boolean; cn?: string | null; expired?: boolean };
  check('valid cert installs', res.ok === true && res.cn === 'portal-test' && res.expired === false);

  const state = JSON.parse(fs.readFileSync(STATE, 'utf8')) as { cert: string; key: string; enforce: boolean; pendingKey?: string };
  const firstBlock = (state.cert.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) || [])[0];
  check('chain normalized LEAF-FIRST', new X509Certificate(firstBlock).subject.includes('portal-test'));
  check('chain kept both certs', (state.cert.match(/BEGIN CERTIFICATE/g) || []).length === 2);
  check('pending key promoted to active', !!state.key && !state.pendingKey);
  check('enforcement auto-enabled on valid install', state.enforce === true);

  // --- status + outbound identity ---
  const st = mtls.getStatus() as { state: string; enforce: boolean; cn?: string | null };
  check('status: configured + enforcing', st.state === 'configured' && st.enforce === true && st.cn === 'portal-test');
  const id = mtls.outboundIdentity();
  check('outboundIdentity returns cert + key (agent material)', !!id && id.cert.includes('BEGIN CERTIFICATE') && id.key.includes('BEGIN PRIVATE KEY'));

  // --- enforce toggle + reset ---
  mtls.setEnforce(false);
  check('enforce off -> no outbound identity (plain fetch)', mtls.outboundIdentity() === null);
  mtls.setEnforce(true);
  check('enforce back on -> identity returns', mtls.outboundIdentity() !== null);
  mtls.reset();
  check('reset -> not_configured', mtls.getStatus().state === 'not_configured');
} catch (e) {
  fail++; console.error('EXCEPTION:', e);
} finally {
  fs.rmSync(STATE, { force: true });
}

console.log(`\nportal mtls: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
