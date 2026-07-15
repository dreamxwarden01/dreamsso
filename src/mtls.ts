import 'reflect-metadata'; // @peculiar/x509's CJS build needs the polyfill loaded first
import * as x509 from '@peculiar/x509';
import { webcrypto, X509Certificate, createPublicKey, randomBytes } from 'node:crypto';
import { getSetting, setSetting, getSecretSetting, setSecretSetting } from './settings.js';

x509.cryptoProvider.set(webcrypto as Crypto);

// Service-to-service mTLS client-certificate management — the SSO twin of
// videosite's mtlsService. The certificate authenticates DreamSSO's OUTBOUND
// S2S calls at the Cloudflare edge (event delivery to apps); trust and
// enforcement live entirely at the edge (certs are stripped before origins),
// so there is no verification side here.
//
// The private key is generated locally (ECDSA P-256 — faster and smaller than
// RSA, and Cloudflare issues ECC client certs) and never leaves; @peculiar/x509
// builds the PKCS#10 CSR (Node has no native CSR API, and node-forge can't do
// EC). The issued certificate is validated with Node's X509Certificate: it must
// not be expired and its public key must match the key the CSR was made from.
// The key is stored sealed (settings secretbox); the cert is public (plain
// setting).

const K = {
  cert: 'mtls_cert',
  cn: 'mtls_cn',
  enforce: 'mtls_enforce',
  activeKey: 'mtls_private_key', // sealed
  pendingKey: 'mtls_pending_key', // sealed — set during setup, before the cert lands
  pendingCn: 'mtls_pending_cn',
};

const randomCn = () => 'dreamsso-' + randomBytes(9).toString('base64url').replace(/[^a-zA-Z0-9]/g, '').slice(0, 12);

const EC_ALG = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' } as const;

async function genKeyAndCsr(cn: string) {
  const keys = (await webcrypto.subtle.generateKey(EC_ALG, true, ['sign', 'verify'])) as CryptoKeyPair;
  const csr = await x509.Pkcs10CertificateRequestGenerator.create({
    name: [{ CN: [cn] }], // JSON name form — no DN-string parsing of user input
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

export interface CertInfo {
  cn: string | null;
  issuer: string | null;
  not_before: string; // ISO UTC — the client renders local time
  not_after: string;
  expired: boolean;
}

const PEM_CERT_RE = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;

function certInfo(certPem: string): CertInfo {
  // The stored value may be a chain (normalized leaf-first) — describe the leaf.
  const c = new X509Certificate((certPem.match(PEM_CERT_RE) || [certPem])[0]);
  return {
    cn: (c.subject.match(/CN=(.+)/) || [])[1]?.trim() || null,
    issuer: (c.issuer.match(/CN=(.+)/) || [])[1]?.trim() || c.issuer.replace(/\n/g, ', ') || null,
    not_before: new Date(c.validFrom).toISOString(),
    not_after: new Date(c.validTo).toISOString(),
    expired: new Date(c.validTo) < new Date(),
  };
}

type Validation = { ok: true; chain: string } | { ok: false; reason: 'parse_failed' | 'expired' | 'key_mismatch' };

// Accepts a single cert OR a full chain (leaf + intermediates, any order): the
// leaf is the block whose public key matches ours; expiry is checked on the
// leaf only; the returned chain is normalized LEAF-FIRST — the order Node's
// TLS `cert` option wants, so the whole chain is presented in the handshake.
function validateCertAgainstKey(certPem: string, keyPem: string): Validation {
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
    keySpki = createPublicKey(keyPem).export({ type: 'spki', format: 'der' });
  } catch {
    return { ok: false, reason: 'key_mismatch' };
  }
  const idx = parsed.findIndex((c) => {
    try {
      return c.publicKey.export({ type: 'spki', format: 'der' }).equals(keySpki);
    } catch {
      return false;
    }
  });
  if (idx === -1) return { ok: false, reason: 'key_mismatch' };
  if (new Date(parsed[idx].validTo) < new Date()) return { ok: false, reason: 'expired' };
  const chain = [blocks[idx], ...blocks.filter((_, i) => i !== idx)].join('\n');
  return { ok: true, chain };
}

export async function getStatus(): Promise<Record<string, unknown>> {
  const cert = await getSetting(K.cert);
  if (!cert) {
    return {
      state: 'not_configured',
      enforce: false,
      pending: !!(await getSecretSetting(K.pendingKey)),
    };
  }
  const info = certInfo(cert);
  const enforce = (await getSetting(K.enforce, 'false')) === 'true';
  return { state: 'configured', enforce: enforce && !info.expired, ...info };
}

// Generate a fresh key + CSR as PENDING — the active key/cert (if any) stay
// untouched until the issued cert is installed; repeat calls overwrite pending.
export async function startSetup(cnInput?: string): Promise<{ cn: string; csr: string }> {
  const cn = cnInput && cnInput.trim() ? cnInput.trim().slice(0, 64) : randomCn();
  const { privateKeyPem, csrPem } = await genKeyAndCsr(cn);
  await setSecretSetting(K.pendingKey, privateKeyPem);
  await setSetting(K.pendingCn, cn);
  return { cn, csr: csrPem };
}

export async function installCert(certPem: unknown): Promise<{ ok: false; reason: string } | ({ ok: true } & CertInfo)> {
  const pem = typeof certPem === 'string' ? certPem.trim() : '';
  if (!pem) return { ok: false, reason: 'no_cert' };
  const pendingKey = await getSecretSetting(K.pendingKey);
  const key = pendingKey || (await getSecretSetting(K.activeKey));
  if (!key) return { ok: false, reason: 'no_key' };
  const v = validateCertAgainstKey(pem, key);
  if (!v.ok) return { ok: false, reason: v.reason };

  // Setup path promotes the pending key; renew (no pending) keeps the active one.
  if (pendingKey) {
    await setSecretSetting(K.activeKey, pendingKey);
    await setSecretSetting(K.pendingKey, null);
    await setSetting(K.pendingCn, null);
  }
  const info = certInfo(v.chain);
  await setSetting(K.cert, v.chain);
  await setSetting(K.cn, info.cn ?? '');
  // Auto-enable enforcement on EVERY valid install — setup or renew (product
  // decision: a new cryptographically valid cert should be immediately active).
  // validateCertAgainstKey already proved key-match + not-expired; getStatus/
  // outboundIdentity still mask it off if the cert later expires.
  await setSetting(K.enforce, 'true');
  return { ok: true, ...info };
}

export async function setEnforce(enabled: boolean): Promise<{ ok: true } | { ok: false; reason: string }> {
  if (enabled) {
    const cert = await getSetting(K.cert);
    if (!cert) return { ok: false, reason: 'not_configured' };
    if (certInfo(cert).expired) return { ok: false, reason: 'expired' };
  }
  await setSetting(K.enforce, enabled ? 'true' : 'false');
  return { ok: true };
}

export async function reset(): Promise<void> {
  await setSetting(K.cert, null);
  await setSetting(K.cn, null);
  await setSecretSetting(K.activeKey, null);
  await setSecretSetting(K.pendingKey, null);
  await setSetting(K.pendingCn, null);
  await setSetting(K.enforce, 'false');
}

// Material for the outbound S2S dispatcher (s2sFetch): null unless enforcement
// is on and a live cert + key are present.
export async function outboundIdentity(): Promise<{ cert: string; key: string } | null> {
  if ((await getSetting(K.enforce, 'false')) !== 'true') return null;
  const cert = await getSetting(K.cert);
  const key = await getSecretSetting(K.activeKey);
  if (!cert || !key || certInfo(cert).expired) return null;
  return { cert, key };
}
