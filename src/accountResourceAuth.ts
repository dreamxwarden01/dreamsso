import type { Request, Response, NextFunction } from 'express';
import type pg from 'pg';
import { jwtVerify, createLocalJWKSet, type JSONWebKeySet } from 'jose';
import type { AccessTokenState, BearerIdentity } from './oidc/accessTokenState.js';

const UUID = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i;
export class AccessTokenUnavailable extends Error {
  constructor() { super('Access token verification unavailable.'); }
}

export interface ResourceAuth {
  sub: string;
  scopes: string[];
  clientId?: string;
  sid?: string;
  denied?: string;
}
export interface AuthedRequest extends Request { auth?: ResourceAuth }

/** Account resources are separate from the ordinary RP /userinfo capability. */
export function accountResourceError(auth: ResourceAuth, scope: string, accountClientId: string): string | null {
  if (auth.denied) return auth.denied;
  if (auth.clientId !== accountClientId) return 'client_not_allowed';
  if (scope && !auth.scopes.includes(scope)) return 'insufficient_scope';
  return null;
}

export interface AccountResourceDependencies {
  issuer(): string;
  accountClientId(): string;
  jwks(db?: pg.PoolClient): Promise<JSONWebKeySet>;
  readState(auth: BearerIdentity, db?: pg.PoolClient): Promise<AccessTokenState>;
}

/** Injectable key storage keeps verification testable without runtime services. */
export function createAccountResourceAuth(deps: AccountResourceDependencies) {
  async function verifyAccessToken(req: Request, db?: pg.PoolClient): Promise<ResourceAuth | null> {
    const match = /^Bearer (.+)$/.exec(req.headers.authorization ?? '');
    if (!match) return null;
    // Transaction-owned key-storage failures remain unavailability, not invalid auth.
    const transactionKeys = db ? await deps.jwks(db) : undefined;
    let document: JSONWebKeySet;
    try { document = transactionKeys ?? await deps.jwks(); }
    catch { throw new AccessTokenUnavailable(); }
    let auth: ResourceAuth & BearerIdentity;
    try {
      const { payload } = await jwtVerify(match[1], createLocalJWKSet(document), {
        issuer: deps.issuer(), audience: deps.issuer(), typ: 'at+jwt', algorithms: ['EdDSA'],
        requiredClaims: ['sub', 'client_id', 'sid', 'iat', 'exp'], maxTokenAge: '900 seconds',
      });
      if (typeof payload.sub !== 'string' || !UUID.test(payload.sub)
        || typeof payload.sid !== 'string' || !UUID.test(payload.sid)
        || typeof payload.client_id !== 'string' || !payload.client_id || payload.client_id.length > 200
        || !Number.isSafeInteger(payload.iat) || !Number.isSafeInteger(payload.exp)
        || payload.exp! <= payload.iat! || payload.exp! - payload.iat! > 900) return null;
      auth = { sub: payload.sub, clientId: payload.client_id, sid: payload.sid,
        scopes: String(payload.scope ?? '').split(' ').filter(Boolean) };
    } catch { return null; }
    let state: AccessTokenState;
    try { state = await deps.readState(auth, db); }
    catch { throw new AccessTokenUnavailable(); }
    if (state === 'session_gone') return null;
    if (state !== 'active') auth.denied = 'access_denied';
    return auth;
  }

  function requireScope(scope: string) {
    return async (req: AuthedRequest, res: Response, next: NextFunction): Promise<void> => {
      let auth: ResourceAuth | null;
      try { auth = await verifyAccessToken(req); }
      catch { res.status(503).json({ error: 'authentication_unavailable' });return; }
      if (!auth) {
        res.status(401).set('WWW-Authenticate', 'Bearer error="invalid_token"').json({ error: 'invalid_token' });
        return;
      }
      const error = accountResourceError(auth, scope, deps.accountClientId());
      if (error) {
        res.status(403).json(error === 'insufficient_scope'
          ? { error, error_description: `${scope} scope required` } : { error });
        return;
      }
      req.auth = auth;
      next();
    };
  }
  return { verifyAccessToken, requireScope };
}
