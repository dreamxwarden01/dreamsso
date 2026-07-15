import crypto from 'node:crypto';
import {
  generateKeyPair, exportJWK, exportPKCS8, importPKCS8, calculateJwkThumbprint,
  type JWK, type JSONWebKeySet,
} from 'jose';
import { pool } from './db.js';
import { config } from './config.js';

const ALG = 'EdDSA';

// AES-256-GCM at rest: [ iv(12) | tag(16) | ciphertext ]
function encrypt(plaintext: string): Buffer {
  const key = Buffer.from(config.keyEncryptionKey, 'hex');
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), ct]);
}
function decrypt(buf: Buffer): string {
  const key = Buffer.from(config.keyEncryptionKey, 'hex');
  const d = crypto.createDecipheriv('aes-256-gcm', key, buf.subarray(0, 12));
  d.setAuthTag(buf.subarray(12, 28));
  return Buffer.concat([d.update(buf.subarray(28)), d.final()]).toString('utf8');
}

let cached: { kid: string; privateKey: CryptoKey; publicJwk: Record<string, unknown> } | null = null;

// Load the current signing key, generating + persisting one on first boot.
export async function getSigningKey() {
  if (cached) return cached;

  const existing = await pool.query(
    "SELECT kid, public_jwk, private_key_enc FROM signing_keys WHERE status = 'current' ORDER BY created_at DESC LIMIT 1",
  );
  if (existing.rows[0]) {
    const row = existing.rows[0];
    const privateKey = (await importPKCS8(decrypt(row.private_key_enc), ALG)) as CryptoKey;
    cached = { kid: row.kid, privateKey, publicJwk: row.public_jwk };
    return cached;
  }

  const { publicKey, privateKey } = await generateKeyPair(ALG, { crv: 'Ed25519', extractable: true });
  const publicJwk = (await exportJWK(publicKey)) as unknown as Record<string, unknown>;
  const kid = await calculateJwkThumbprint(publicJwk as any);
  publicJwk.kid = kid;
  publicJwk.alg = ALG;
  publicJwk.use = 'sig';

  await pool.query(
    `INSERT INTO signing_keys (kid, alg, public_jwk, private_key_enc, status, activated_at)
     VALUES ($1, $2, $3, $4, 'current', now())`,
    [kid, ALG, publicJwk, encrypt(await exportPKCS8(privateKey))],
  );
  cached = { kid, privateKey: privateKey as CryptoKey, publicJwk };
  return cached;
}

// Public JWKS — current + next + still-trusted retired keys (for verification).
// Called on every token/userinfo/resource-auth verification, so cached briefly
// in-process; rotation invalidates via invalidateJwksCache().
//
// Retired keys stay published for 24h after retirement — the longest-lived
// artifact signed with the SSO key is a 15-minute access token, so this is a
// generous window for in-flight tokens + RP JWKS caches. Rows are kept forever
// (audit trail); they just drop out of the published set.
const RETIRED_JWKS_WINDOW = "interval '24 hours'";
let jwksCache: { value: JSONWebKeySet; at: number } | null = null;
const JWKS_CACHE_MS = 60_000;

export async function getJwks(): Promise<JSONWebKeySet> {
  if (jwksCache && Date.now() - jwksCache.at < JWKS_CACHE_MS) return jwksCache.value;
  const { rows } = await pool.query(
    `SELECT public_jwk FROM signing_keys
      WHERE status IN ('current','next')
         OR (status = 'retired' AND retired_at > now() - ${RETIRED_JWKS_WINDOW})
      ORDER BY created_at DESC`,
  );
  jwksCache = { value: { keys: rows.map((r) => r.public_jwk as JWK) }, at: Date.now() };
  return jwksCache.value;
}

export function invalidateJwksCache(): void {
  jwksCache = null;
}

// Rotate the signing key: mint a fresh Ed25519 pair, retire the current key,
// and activate the new one in a single transaction. The retired key keeps
// verifying (it stays in the JWKS for RETIRED_JWKS_WINDOW); both RPs use jose's
// createRemoteJWKSet, which re-fetches on an unknown kid, so signing with the
// new key immediately is safe. Returns the new kid.
export async function rotateSigningKey(): Promise<string> {
  const { publicKey, privateKey } = await generateKeyPair(ALG, { crv: 'Ed25519', extractable: true });
  const publicJwk = (await exportJWK(publicKey)) as unknown as Record<string, unknown>;
  const kid = await calculateJwkThumbprint(publicJwk as any);
  publicJwk.kid = kid;
  publicJwk.alg = ALG;
  publicJwk.use = 'sig';
  const privatePem = await exportPKCS8(privateKey);

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(
      "UPDATE signing_keys SET status = 'retired', retired_at = now() WHERE status = 'current'",
    );
    await client.query(
      `INSERT INTO signing_keys (kid, alg, public_jwk, private_key_enc, status, activated_at)
       VALUES ($1, $2, $3, $4, 'current', now())`,
      [kid, ALG, publicJwk, encrypt(privatePem)],
    );
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }

  cached = null; // next mint loads the new current key
  jwksCache = null;
  return kid;
}
