import { SignJWT } from 'jose';
import { getSigningKey } from '../keys.js';
import { config } from '../config.js';

const ID_TOKEN_TTL = 600; // 10 min
const ACCESS_TOKEN_TTL = 900; // 15 min

export async function mintIdToken(p: {
  sub: string;
  clientId: string;
  nonce?: string;
  acr?: string;
  amr: string[];
  authTime: number;
  sid?: string;
  extra: Record<string, unknown>;
}): Promise<string> {
  const { kid, privateKey } = await getSigningKey();
  const now = Math.floor(Date.now() / 1000);
  const payload: Record<string, unknown> = { amr: p.amr, auth_time: p.authTime, azp: p.clientId, ...p.extra };
  if (p.nonce) payload.nonce = p.nonce;
  if (p.acr) payload.acr = p.acr;
  if (p.sid) payload.sid = p.sid; // OIDC session id — RP records it for logout/session binding
  return new SignJWT(payload)
    .setProtectedHeader({ alg: 'EdDSA', kid, typ: 'JWT' })
    .setIssuer(config.issuer)
    .setSubject(p.sub)
    .setAudience(p.clientId)
    .setIssuedAt(now)
    .setExpirationTime(now + ID_TOKEN_TTL)
    .sign(privateKey);
}

export async function mintAccessToken(p: { sub: string; clientId: string; scope: string }): Promise<string> {
  const { kid, privateKey } = await getSigningKey();
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({ scope: p.scope, client_id: p.clientId })
    .setProtectedHeader({ alg: 'EdDSA', kid, typ: 'at+jwt' })
    .setIssuer(config.issuer)
    .setSubject(p.sub)
    .setAudience(config.issuer)
    .setIssuedAt(now)
    .setExpirationTime(now + ACCESS_TOKEN_TTL)
    .sign(privateKey);
}
