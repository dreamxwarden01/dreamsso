// OIDC relying-party plumbing for the account console — the TS/ESM sibling of
// videosite's lib/oidc.js. Same DreamSSO OP, same private_key_jwt (RFC 7523,
// EdDSA) client auth; here jose is a normal import (the BFF is ESM).
import crypto from 'node:crypto';
import {
  SignJWT,
  jwtVerify,
  importJWK,
  createRemoteJWKSet,
  type JWTPayload,
} from 'jose';
import { config } from './config.js';
import { s2sFetch } from './s2sFetch.js';
import {selectClientSigningKey,getClientKeyStatus,getClientPublicJwks,scheduleClientKeyRotation} from './client-key-state.js';

// Each selection reads the durable current identity; only its imported key caches.
let cachedSigner:{kid:string;key:Awaited<ReturnType<typeof importJWK>>}|undefined;
async function clientKey() {
  const selected=await selectClientSigningKey(config.clientKeyFile);
  if(cachedSigner?.kid===selected.kid)return cachedSigner;
  const result={kid:selected.kid,key:await importJWK(selected.jwk,'EdDSA')};cachedSigner=result;return result;
}
export const rotateClientKey=()=>scheduleClientKeyRotation(config.clientKeyFile);
export const clientKeyStatus=()=>getClientKeyStatus(config.clientKeyFile);
export const publicClientJwks=()=>getClientPublicJwks(config.clientKeyFile);

let _jwks: ReturnType<typeof createRemoteJWKSet> | undefined;
function jwks() {
  return (_jwks ??= createRemoteJWKSet(new URL(config.internal + '/jwks')));
}

export interface Flow {
  verifier: string;
  challenge: string;
  state: string;
  nonce: string;
}

// PKCE + state + nonce for one authorization request. The caller stashes
// verifier/state/nonce in the short-lived flow cookie and checks them on callback.
export function beginFlow(): Flow {
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  const state = crypto.randomBytes(16).toString('base64url');
  const nonce = crypto.randomBytes(16).toString('base64url');
  return { verifier, challenge, state, nonce };
}

export function authorizeUrl(p: {
  challenge: string;
  state: string;
  nonce: string;
  extra?: Record<string, string>;
}): string {
  const u = new URL(config.issuer + '/authorize');
  u.search = new URLSearchParams({
    response_type: 'code',
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    scope: 'openid profile email',
    state: p.state,
    nonce: p.nonce,
    code_challenge: p.challenge,
    code_challenge_method: 'S256',
    ...(p.extra ?? {}), // step-up (Phase 2) will pass prompt / max_age / acr_values here
  }).toString();
  return u.toString();
}

// Client assertion for the SSO's internal (non-token) endpoints — the same
// private_key_jwt material as /token, carried in the JSON body. The SSO
// verifies it against this client's registered key and pins iss/sub to the
// account portal's client_id.
export async function s2sAssertion(): Promise<string> {
  const {kid,key} = await clientKey();
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({})
    .setProtectedHeader({ alg: 'EdDSA', kid })
    .setIssuer(config.clientId)
    .setSubject(config.clientId)
    .setAudience(config.issuer)
    .setIssuedAt(now)
    .setExpirationTime(now + 60)
    .setJti(crypto.randomUUID())
    .sign(key);
}

export interface TokenResponse {
  id_token: string;
  access_token: string;
  token_type: string;
  expires_in: number;
  scope?: string;
}

// Authorization-code -> tokens, authenticating with private_key_jwt.
export async function exchangeCode(code: string, verifier: string): Promise<TokenResponse> {
  const {kid,key} = await clientKey(); // selected key and kid stay paired through concurrent activation
  const now = Math.floor(Date.now() / 1000);
  const assertion = await new SignJWT({})
    .setProtectedHeader({ alg: 'EdDSA', kid })
    .setIssuer(config.clientId)
    .setSubject(config.clientId)
    .setAudience(config.issuer)
    .setIssuedAt(now)
    .setExpirationTime(now + 60)
    .setJti(crypto.randomUUID())
    .sign(key);

  const r = await s2sFetch(config.internal + '/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: config.redirectUri,
      code_verifier: verifier,
      client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
      client_assertion: assertion,
    }),
  });
  const tok = (await r.json().catch(() => ({}))) as TokenResponse & { error?: string };
  if (!r.ok) {
    const e = new Error('token_endpoint_error') as Error & { detail?: unknown };
    e.detail = tok;
    throw e;
  }
  return tok;
}

// Verify the id_token signature + iss/aud, and bind the nonce.
export async function verifyIdToken(idToken: string, expectedNonce: string): Promise<JWTPayload> {
  const { payload } = await jwtVerify(idToken, jwks(), {
    issuer: config.issuer,
    audience: config.clientId,
  });
  if (payload.nonce !== expectedNonce) throw new Error('nonce_mismatch');
  return payload;
}

export async function userinfo(accessToken: string): Promise<Record<string, unknown> | null> {
  const r = await s2sFetch(config.internal + '/userinfo', {
    headers: { authorization: 'Bearer ' + accessToken },
  });
  return r.ok ? ((await r.json()) as Record<string, unknown>) : null;
}

// RP-initiated logout (SSO discovery: end_session_endpoint = /logout). The SSO
// route lands with its session/logout milestone; until then the BFF logs out
// locally and this URL is unused.
export function endSessionUrl(idTokenHint?: string): string {
  const u = new URL(config.issuer + '/logout');
  u.search = new URLSearchParams({
    post_logout_redirect_uri: config.postLogoutRedirect,
    client_id: config.clientId,
    ...(idTokenHint ? { id_token_hint: idTokenHint } : {}),
  }).toString();
  return u.toString();
}
