// OIDC relying-party plumbing for the account console — the TS/ESM sibling of
// videosite's lib/oidc.js. Same DreamSSO OP, same private_key_jwt (RFC 7523,
// EdDSA) client auth; here jose is a normal import (the BFF is ESM).
import crypto from 'node:crypto';
import fs from 'node:fs';
import {
  SignJWT,
  jwtVerify,
  importJWK,
  createRemoteJWKSet,
  calculateJwkThumbprint,
  type JWTPayload,
  type JWK,
} from 'jose';
import { config } from './config.js';
import { s2sFetch } from './s2sFetch.js';

// Cached client signing key (private_key_jwt) + remote JWKS resolver.
// Key file: legacy single private JWK, or {keys:[current, previous], rotated_at}
// after a rotation. keys[0] signs; the jwks.json route publishes every key.
type KeyFile = { keys: (JWK & { kid?: string })[]; rotated_at?: string };
export function readKeyFile(): KeyFile {
  const raw = JSON.parse(fs.readFileSync(config.clientKeyFile, 'utf8')) as Record<string, unknown>;
  return Array.isArray(raw.keys)
    ? { keys: raw.keys as KeyFile['keys'], rotated_at: raw.rotated_at as string | undefined }
    : { keys: [raw as unknown as JWK & { kid?: string }] };
}
let _privJwk: JWK & { kid?: string };
let _clientKey: Awaited<ReturnType<typeof importJWK>> | undefined;
async function clientKey() {
  if (_clientKey) return _clientKey;
  _privJwk = readKeyFile().keys[0];
  _clientKey = await importJWK(_privJwk, 'EdDSA');
  return _clientKey;
}

// Rotate the client signing key: fresh Ed25519 becomes keys[0], the replaced
// key stays published until the NEXT rotation (overlap for in-flight
// assertions + the SSO's remote-JWKS re-fetch on the unknown kid).
export async function rotateClientKey(): Promise<{ kid: string; rotated_at: string }> {
  const jwk = crypto.generateKeyPairSync('ed25519').privateKey.export({ format: 'jwk' }) as JWK & { kid?: string; alg?: string };
  jwk.kid = await calculateJwkThumbprint(jwk); // RFC 7638 (public members only)
  jwk.alg = 'EdDSA';
  const file: KeyFile = { keys: [jwk, readKeyFile().keys[0]], rotated_at: new Date().toISOString() };
  fs.writeFileSync(config.clientKeyFile, JSON.stringify(file, null, 2) + '\n');
  _privJwk = jwk;
  _clientKey = await importJWK(jwk, 'EdDSA');
  return { kid: jwk.kid, rotated_at: file.rotated_at! };
}

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
  const key = await clientKey();
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({})
    .setProtectedHeader({ alg: 'EdDSA', kid: _privJwk.kid })
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
  const key = await clientKey(); // also populates _privJwk (for the kid)
  const now = Math.floor(Date.now() / 1000);
  const assertion = await new SignJWT({})
    .setProtectedHeader({ alg: 'EdDSA', kid: _privJwk.kid })
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
