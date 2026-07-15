import type { Request, Response, NextFunction } from 'express';
import { jwtVerify, createLocalJWKSet } from 'jose';
import { getJwks } from './keys.js';
import { config } from './config.js';

// Bearer access-token auth for the SSO's own resource APIs (/account/*), the way
// the account-console BFF calls them on the user's behalf. The access token has
// aud = issuer (see oidc/tokens.ts) and carries the granted `scope`.
export interface ResourceAuth {
  sub: string;
  scopes: string[];
}

export interface AuthedRequest extends Request {
  auth?: ResourceAuth;
}

export async function verifyAccessToken(req: Request): Promise<ResourceAuth | null> {
  const m = /^Bearer (.+)$/.exec(req.headers.authorization ?? '');
  if (!m) return null;
  try {
    const jwks = createLocalJWKSet(await getJwks());
    const { payload } = await jwtVerify(m[1], jwks, { issuer: config.issuer, audience: config.issuer });
    if (!payload.sub) return null;
    return { sub: payload.sub, scopes: String(payload.scope ?? '').split(' ').filter(Boolean) };
  } catch {
    return null;
  }
}

// Middleware: 401 on a missing/invalid token, 403 on a missing scope; else sets req.auth.
export function requireScope(scope: string) {
  return async (req: AuthedRequest, res: Response, next: NextFunction): Promise<void> => {
    const auth = await verifyAccessToken(req);
    if (!auth) {
      res.status(401).set('WWW-Authenticate', 'Bearer error="invalid_token"').json({ error: 'invalid_token' });
      return;
    }
    if (scope && !auth.scopes.includes(scope)) {
      res.status(403).json({ error: 'insufficient_scope', error_description: `${scope} scope required` });
      return;
    }
    req.auth = auth;
    next();
  };
}
