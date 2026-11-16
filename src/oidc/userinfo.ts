import type { Request, Response } from 'express';
import type { ResourceAuth } from '../accountResourceAuth.js';

export interface UserinfoProfile { sub: string; username: string; display_name: string;
  email: string | null; email_verified: boolean; avatar: string | null }
export interface UserinfoDependencies {
  verifyAccessToken(req: Request): Promise<ResourceAuth | null>;
  profile(sub: string | undefined): Promise<UserinfoProfile | undefined>;
}

/** Ordinary registered RPs retain their OIDC userinfo capability. */
export function createUserinfoHandler(deps: UserinfoDependencies) {
  return async (req: Request, res: Response) => {
    res.setHeader('Cache-Control', 'no-store');
    try {
      const auth = await deps.verifyAccessToken(req);
      if (!auth) return res.status(401).set('WWW-Authenticate', 'Bearer error="invalid_token"').json({ error: 'invalid_token' });
      if (auth.denied) return res.status(403).json({ error: auth.denied });
      const profile = await deps.profile(auth.sub);
      if (!profile) return res.status(401).set('WWW-Authenticate', 'Bearer error="invalid_token"').json({ error: 'invalid_token' });
      const scopes = auth.scopes;
      const out: Record<string, unknown> = { sub: profile.sub };
      if (scopes.includes('profile')) {
        out.name = profile.display_name;out.preferred_username = profile.username;
        if (profile.avatar) out.picture = profile.avatar;
      }
      if (scopes.includes('email')) { out.email = profile.email;out.email_verified = profile.email_verified; }
      return res.json(out);
    } catch {
      return res.status(503).json({ error: 'authentication_unavailable' });
    }
  };
}
