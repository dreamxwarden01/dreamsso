// Service-to-service mTLS client certificate management for the account portal.
//
// Mirrors videosite's mtlsService, with one difference: the BFF has NO database and
// NO key-encryption key, so state lives in a 0600 JSON file instead of encrypted
// settings. The private key is therefore plaintext-at-rest (same as the portal's
// existing OIDC client key file) — host access is the trust boundary.
//
// The private key is generated here (ECDSA P-256 — faster and smaller than RSA, and
// Cloudflare issues ECC client certs) and never leaves. @peculiar/x509 builds the
// PKCS#10 CSR (Node has no native CSR API, and node-forge can't do EC). The issued
// certificate is validated with Node's X509Certificate: it must not be expired and
// its public key must match the key the CSR was made from.
import 'reflect-metadata'; // @peculiar/x509's CJS build needs the polyfill loaded first
import * as x509 from '@peculiar/x509';
import fs from 'node:fs';
import path from 'node:path';
import { webcrypto, X509Certificate, createPublicKey, randomBytes } from 'node:crypto';

x509.cryptoProvider.set(webcrypto as unknown as Crypto);

const STATE_FILE = process.env.MTLS_STATE_FILE || path.resolve(process.cwd(), '.mtls.json');

const EC_ALG = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' };

interface MtlsState {
  cn?: string;
  cert?: string; // PEM chain, normalized LEAF-FIRST
  key?: string; // PEM PKCS#8 private key (plaintext — no KEK on the BFF)
  pendingKey?: string; // written at CSR time, promoted when the cert lands
  pendingCn?: string;
  enforce?: boolean;
}

// Cached in memory: outboundIdentity() runs on every S2S call, so we never hit the
// disk per request. Writes update both.
let cache: MtlsState | null = null;
function read(): MtlsState {
  if (cache) return cache;
  try {
    cache = JSON.parse(fs.readFileSync(STATE_FILE, 'utf8')) as MtlsState;
  } catch {
    cache = {};
  }
  return cache;
}
function write(s: MtlsState): void {
  cache = s;
  fs.writeFileSync(STATE_FILE, JSON.stringify(s, null, 2) + '\n', { mode: 0o600 });
}

const randomCn = () =>
  'account-' + randomBytes(9).toString('base64url').replace(/[^a-zA-Z0-9]/g, '').slice(0, 12);

async function genKeyAndCsr(cn: string): Promise<{ privateKeyPem: string; csrPem: string }> {
  const keys = (await webcrypto.subtle.generateKey(EC_ALG, true, ['sign', 'verify'])) as CryptoKeyPair;
  const csr = await x509.Pkcs10CertificateRequestGenerator.create({
    name: [{ CN: [cn] }], // JSON name form — no DN-string parsing of operator input
    keys,
    signingAlgorithm: EC_ALG,
  });
  const pkcs8 = Buffer.from(await webcrypto.subtle.exportKey('pkcs8', keys.privateKey));
  const privateKeyPem =
    '-----BEGIN PRIVATE KEY-----\n' +
    pkcs8.toString('base64').match(/.{1,64}/g)!.join('\n') +
    '\n-----END PRIVATE KEY-----\n';
  return { privateKeyPem, csrPem: csr.toString('pem') };
}

const PEM_CERT_RE = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;

export interface CertInfo {
  cn: string | null;
  issuer: string | null;
  not_before: string;
  not_after: string;
  expired: boolean;
}

function certInfo(certPem: string): CertInfo {
  // The stored value may be a chain (leaf-first) — describe the leaf.
  const c = new X509Certificate((certPem.match(PEM_CERT_RE) || [certPem])[0]);
  return {
    cn: (c.subject.match(/CN=(.+)/) || [])[1]?.trim() || null,
    issuer: (c.issuer.match(/CN=(.+)/) || [])[1]?.trim() || c.issuer.replace(/\n/g, ', ') || null,
    not_before: new Date(c.validFrom).toISOString(), // ISO UTC — the client renders local time
    not_after: new Date(c.validTo).toISOString(),
    expired: new Date(c.validTo) < new Date(),
  };
}

// Accepts a single cert OR a full chain (leaf + intermediates, any order): the leaf
// is the block whose public key matches ours; expiry is checked on the leaf only;
// the returned chain is normalized LEAF-FIRST — the order Node's TLS `cert` option
// wants, so the whole chain is presented in the handshake.
function validateCertAgainstKey(
  certPem: string,
  keyPem: string,
): { ok: true; chain: string } | { ok: false; reason: string } {
  const blocks = certPem.match(PEM_CERT_RE);
  if (!blocks || blocks.length === 0) return { ok: false, reason: 'parse_failed' };
  let parsed: X509Certificate[];
  try {
    parsed = blocks.map((b) => new X509Certificate(b));
  } catch {
    return { ok: false, reason: 'parse_failed' };
  }
  let keySpki: Buffer;
  try {
    keySpki = createPublicKey(keyPem).export({ type: 'spki', format: 'der' }) as Buffer;
  } catch {
    return { ok: false, reason: 'key_mismatch' };
  }
  const idx = parsed.findIndex((c) => {
    try {
      return (c.publicKey.export({ type: 'spki', format: 'der' }) as Buffer).equals(keySpki);
    } catch {
      return false;
    }
  });
  if (idx === -1) return { ok: false, reason: 'key_mismatch' };
  if (new Date(parsed[idx].validTo) < new Date()) return { ok: false, reason: 'expired' };
  const chain = [blocks[idx], ...blocks.filter((_, i) => i !== idx)].join('\n');
  return { ok: true, chain };
}

export function getStatus() {
  const s = read();
  const pending = !!s.pendingKey;
  if (!s.cert) return { state: 'not_configured' as const, enforce: false, pending };
  const info = certInfo(s.cert);
  return { state: 'configured' as const, enforce: !!s.enforce && !info.expired, pending, ...info };
}

// Step 1: generate an ECC key (kept) + CSR (shown). Auto-names the CN if blank.
export async function startSetup(cnInput?: string): Promise<{ cn: string; csr: string }> {
  const cn = cnInput && cnInput.trim() ? cnInput.trim().slice(0, 64) : randomCn();
  const { privateKeyPem, csrPem } = await genKeyAndCsr(cn);
  write({ ...read(), pendingKey: privateKeyPem, pendingCn: cn });
  return { cn, csr: csrPem };
}

// Step 2 (setup) / renew: validate the issued cert against the matching key, then
// store it. Setup promotes the pending key; renew keeps the active key.
export function installCert(certPemIn: string) {
  const certPem = String(certPemIn || '').trim();
  if (!certPem) return { ok: false as const, reason: 'no_cert' };
  const s = read();
  const key = s.pendingKey || s.key;
  if (!key) return { ok: false as const, reason: 'no_key' };

  const v = validateCertAgainstKey(certPem, key);
  if (!v.ok) return v;
  const info = certInfo(v.chain);

  const next: MtlsState = { ...s, cert: v.chain, cn: info.cn ?? '', enforce: true };
  if (s.pendingKey) {
    next.key = s.pendingKey;
    delete next.pendingKey;
    delete next.pendingCn;
  }
  // Auto-enable enforcement on EVERY valid install — setup or renew (a
  // cryptographically valid cert should be immediately active). validateCertAgainstKey
  // already proved key-match + not-expired; getStatus/outboundIdentity still mask it
  // off if the cert later expires.
  write(next);
  return { ok: true as const, ...info };
}

export function setEnforce(enabled: boolean) {
  const s = read();
  if (enabled) {
    if (!s.cert) return { ok: false as const, reason: 'not_configured' };
    if (certInfo(s.cert).expired) return { ok: false as const, reason: 'expired' };
  }
  write({ ...s, enforce: enabled });
  return { ok: true as const };
}

export function reset() {
  write({});
  return { ok: true as const };
}

// Material for the outbound S2S dispatcher (s2sFetch): null unless enforcement is on
// and a live cert + key are present.
export function outboundIdentity(): { cert: string; key: string } | null {
  const s = read();
  if (!s.enforce || !s.cert || !s.key) return null;
  if (certInfo(s.cert).expired) return null;
  return { cert: s.cert, key: s.key };
}
