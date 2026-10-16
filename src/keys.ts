import crypto from 'node:crypto';
import type pg from 'pg';
import {
  generateKeyPair, exportJWK, exportPKCS8, importPKCS8, importJWK, calculateJwkThumbprint,
  SignJWT,jwtVerify,
  type JWK, type JSONWebKeySet,
} from 'jose';
import { pool } from './db.js';
import { config } from './config.js';
import {SigningKeyRotation,SigningKeyStateError,type SigningKeyStatus} from './signingKeyRotation.js';

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

async function generateMaterial() {
  const {publicKey,privateKey}=await generateKeyPair(ALG,{crv:'Ed25519',extractable:true});
  const publicJwk=(await exportJWK(publicKey)) as unknown as Record<string,unknown>;
  const kid=await calculateJwkThumbprint(publicJwk as unknown as JWK);
  Object.assign(publicJwk,{kid,alg:ALG,use:'sig'});
  const proof=await new SignJWT({purpose:'signing-key-self-test'}).setProtectedHeader({alg:ALG,kid}).sign(privateKey);
  await jwtVerify(proof,publicKey,{algorithms:[ALG]});
  publicSigningJwk(publicJwk);
  return{kid,alg:ALG,publicJwk,privateKeyEnc:encrypt(await exportPKCS8(privateKey))};
}
function publicSigningJwk(value:Record<string,unknown>):JWK {
  if(value.kty!=='OKP'||value.crv!=='Ed25519'||typeof value.x!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(value.x)
    ||typeof value.kid!=='string'||!/^[A-Za-z0-9_-]{1,200}$/.test(value.kid)||(value.alg!==undefined&&value.alg!=='EdDSA')
    ||['d','p','q','dp','dq','qi','k'].some(name=>name in value))throw new SigningKeyStateError();
  return{kty:'OKP',crv:'Ed25519',x:value.x,kid:value.kid,alg:'EdDSA',use:'sig'};
}
const rotation=new SigningKeyRotation(pool,generateMaterial,()=>invalidateJwksCache());

// The database selects the current signer on every call. An imported key may
// cache by kid, but another process's activation cannot leave this pointer stale.
export async function getSigningKey() {
  const row=await rotation.current();
  if(cached?.kid===row.kid)return cached;
  try{
    const publicJwk=publicSigningJwk(row.public_jwk);
    if(row.alg!==ALG||publicJwk.kid!==row.kid)throw new SigningKeyStateError();
    const privateKey=(await importPKCS8(decrypt(row.private_key_enc),ALG)) as CryptoKey;
    const proof=await new SignJWT({purpose:'signer-pair-check'}).setProtectedHeader({alg:ALG,kid:row.kid}).sign(privateKey);
    await jwtVerify(proof,await importJWK(publicJwk,ALG),{algorithms:[ALG]});
    const selected={kid:row.kid,privateKey,publicJwk:row.public_jwk};cached=selected;return selected;
  }catch{throw new SigningKeyStateError();}
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

export async function getJwks(db?: pg.PoolClient): Promise<JSONWebKeySet> {
  if (!db && jwksCache && performance.now() - jwksCache.at < JWKS_CACHE_MS) return jwksCache.value;
  const started=performance.now();
  const text=`SELECT public_jwk FROM signing_keys
      WHERE status IN ('current','next')
         OR (status = 'retired' AND retired_at > now() - ${RETIRED_JWKS_WINDOW})
      ORDER BY created_at DESC`;
  // pg supports per-query query_timeout; @types/pg exposes it only on the
  // connection options, so retain the typed extension at this call boundary.
  const bounded:pg.QueryConfig&{query_timeout:number}={text,query_timeout:5000};
  const {rows}=db?await db.query(text):await pool.query(bounded);
  // A stalled read/resumed process must not cache a snapshot from before
  // publication as though it were fresh now. Transactional callers stay uncached.
  if(!db&&performance.now()-started>5000)throw new SigningKeyStateError();
  if(!rows.length)throw new SigningKeyStateError();
  const value = { keys: rows.map((r) => publicSigningJwk(r.public_jwk)) };
  // Transactional proof checks must neither acquire another pool connection
  // nor share uncommitted/public-key snapshots through the process cache.
  if (db) return value;
  jwksCache = { value, at: started };
  return jwksCache.value;
}

export function invalidateJwksCache(): void {
  jwksCache = null;
}

// Schedule publication first. A later status/signing read activates the exact
// pending key after the persisted five-minute propagation window.
export async function rotateSigningKey():Promise<SigningKeyStatus>{return rotation.schedule();}
export async function getSigningKeyStatus():Promise<SigningKeyStatus>{return rotation.status();}
