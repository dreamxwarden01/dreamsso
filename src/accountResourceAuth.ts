import type { Request, Response, NextFunction } from 'express';
import type pg from 'pg';
import { jwtVerify, createLocalJWKSet, type JSONWebKeySet } from 'jose';

export interface ResourceAuth {
  sub: string;
  scopes: string[];
  clientId?: string;
}
export interface AuthedRequest extends Request { auth?: ResourceAuth }

/** Account resources are separate from the ordinary RP /userinfo capability. */
export function accountResourceError(auth: ResourceAuth, scope: string, accountClientId: string): string | null {
  if (auth.clientId !== accountClientId) return 'client_not_allowed';
  if (scope && !auth.scopes.includes(scope)) return 'insufficient_scope';
  return null;
}

export interface AccountResourceDependencies {
  issuer(): string;
  accountClientId(): string;
  jwks(db?: pg.PoolClient): Promise<JSONWebKeySet>;
}

/** Injectable key storage keeps verification testable without runtime services. */
export function createAccountResourceAuth(deps: AccountResourceDependencies) {
  async function verifyAccessToken(req: Request, db?: pg.PoolClient): Promise<ResourceAuth | null> {
    const match = /^Bearer (.+)$/.exec(req.headers.authorization ?? '');
    if (!match) return null;
    // Transaction-owned key-storage failures remain unavailability, not invalid auth.
    const transactionKeys = db ? await deps.jwks(db) : undefined;
    try {
      const keys = createLocalJWKSet(transactionKeys ?? await deps.jwks());
      const { payload } = await jwtVerify(match[1], keys, {
        issuer: deps.issuer(), audience: deps.issuer(), typ: 'at+jwt',
      });
      if (!payload.sub) return null;
      return {
        sub: payload.sub,
        scopes: String(payload.scope ?? '').split(' ').filter(Boolean),
        ...(typeof payload.client_id === 'string' ? { clientId: payload.client_id } : {}),
      };
    } catch { return null; }
  }

  function requireScope(scope: string) {
    return async (req: AuthedRequest, res: Response, next: NextFunction): Promise<void> => {
      const auth = await verifyAccessToken(req);
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
