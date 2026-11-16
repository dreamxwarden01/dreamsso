import type { Request, Response } from 'express';
import { jwtVerify, createLocalJWKSet, type JSONWebKeySet } from 'jose';

export interface UserinfoProfile { sub: string; username: string; display_name: string;
  email: string | null; email_verified: boolean; avatar: string | null }
export interface UserinfoDependencies {
  issuer(): string;
  jwks(): Promise<JSONWebKeySet>;
  profile(sub: string | undefined): Promise<UserinfoProfile | undefined>;
}

/** Ordinary registered RPs retain their OIDC userinfo capability. */
export function createUserinfoHandler(deps: UserinfoDependencies) {
  return async (req: Request, res: Response) => {
    res.setHeader('Cache-Control', 'no-store');
    const match = /^Bearer (.+)$/.exec(req.headers.authorization ?? '');
    if (!match) return res.status(401).set('WWW-Authenticate', 'Bearer').json({ error: 'invalid_token' });
    try {
      const { payload } = await jwtVerify(match[1], createLocalJWKSet(await deps.jwks()), {
        issuer: deps.issuer(), audience: deps.issuer(),
      });
      const profile = await deps.profile(payload.sub);
      if (!profile) return res.status(401).set('WWW-Authenticate', 'Bearer error="invalid_token"').json({ error: 'invalid_token' });
      const scopes = String(payload.scope ?? '').split(' ');
      const out: Record<string, unknown> = { sub: profile.sub };
      if (scopes.includes('profile')) {
        out.name = profile.display_name;out.preferred_username = profile.username;
        if (profile.avatar) out.picture = profile.avatar;
      }
      if (scopes.includes('email')) { out.email = profile.email;out.email_verified = profile.email_verified; }
      return res.json(out);
    } catch {
      return res.status(401).set('WWW-Authenticate', 'Bearer error="invalid_token"').json({ error: 'invalid_token' });
    }
  };
}
