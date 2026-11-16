import { Router, type Request, type Response } from 'express';
import { createUserinfoHandler, type UserinfoProfile } from '../oidc/userinfo.js';
import { assertedClient } from '../oidc/clientAssertion.js';
import { ClientAssertionUnavailable } from '../oidc/clientAssertionValidation.js';
import { pool } from '../db.js';
import { consumeCode } from '../oidc/codes.js';
import { getSessionWindows } from '../oidc/sessions.js';
import { mintIdToken, mintAccessToken } from '../oidc/tokens.js';
import { readAccessStateSnapshot } from '../backchannel/accessStateStore.js';
import { getSigningKey } from '../keys.js';
import { redeemAuthorizationCode, CodeRedemptionError } from '../oidc/codeRedemption.js';
import { config } from '../config.js';
import { getSetting } from '../settings.js';
import { verifyAccessToken } from '../resourceAuth.js';

export const tokenRouter = Router();

const fail = (res: Response, status: number, error: string, desc?: string) =>
  res.status(status).json(desc ? { error, error_description: desc } : { error });

tokenRouter.post('/token', async (req: Request, res: Response) => {
  res.setHeader('Cache-Control', 'no-store');
  const b = (req.body ?? {}) as Record<string, string>;
  if (b.grant_type !== 'authorization_code') return fail(res, 400, 'unsupported_grant_type');

  let clientId: string | null;
  try { clientId = await assertedClient(b, { method: req.method, path: req.path }); }
  catch (error) {
    if (error instanceof ClientAssertionUnavailable) return fail(res, 503, 'temporarily_unavailable');
    throw error;
  }
  if (!clientId) return fail(res, 401, 'invalid_client');

  try {
    const tokens = await redeemAuthorizationCode({ clientId,
      code: b.code ?? '', redirectUri: b.redirect_uri, verifier: b.code_verifier }, {
      database: pool, consumeCode, readAccessStateSnapshot,
      prepare: async () => {
        const [signingKey, windows, siteName] = await Promise.all([
          getSigningKey(), getSessionWindows(), getSetting('site_name', 'DreamSSO'),
        ]);
        return { windows, siteName: siteName ?? 'DreamSSO',
          mintIdToken: claims => mintIdToken(claims, signingKey),
          mintAccessToken: claims => mintAccessToken(claims, signingKey) };
      },
    });
    res.json(tokens);
  } catch (error) {
    if (error instanceof CodeRedemptionError) return fail(res, error.status, error.code, error.description);
    return fail(res, 503, 'temporarily_unavailable');
  }
});

tokenRouter.get('/userinfo', createUserinfoHandler({
  verifyAccessToken,
  profile: async sub => {
    const { rows } = await pool.query<UserinfoProfile>(
      'SELECT sub, username, display_name, email, email_verified, avatar FROM identities WHERE sub = $1', [sub]);
    return rows[0];
  },
}));
