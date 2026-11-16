import { Router, type Request, type Response } from 'express';
import { jwtVerify } from 'jose';
import { createUserinfoHandler, type UserinfoProfile } from '../oidc/userinfo.js';
import { clientKeySet } from '../clientKeys.js';
import { pool } from '../db.js';
import { consumeCode } from '../oidc/codes.js';
import { getSessionWindows } from '../oidc/sessions.js';
import { mintIdToken, mintAccessToken } from '../oidc/tokens.js';
import { readAccessStateSnapshot } from '../backchannel/accessStateStore.js';
import { getJwks, getSigningKey } from '../keys.js';
import { redeemAuthorizationCode, CodeRedemptionError } from '../oidc/codeRedemption.js';
import { config } from '../config.js';
import { getSetting } from '../settings.js';

export const tokenRouter = Router();

const fail = (res: Response, status: number, error: string, desc?: string) =>
  res.status(status).json(desc ? { error, error_description: desc } : { error });

tokenRouter.post('/token', async (req: Request, res: Response) => {
  res.setHeader('Cache-Control', 'no-store');
  const b = (req.body ?? {}) as Record<string, string>;
  if (b.grant_type !== 'authorization_code') return fail(res, 400, 'unsupported_grant_type');

  // --- client authentication: private_key_jwt (RFC 7523) ---
  if (
    b.client_assertion_type !== 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer' ||
    !b.client_assertion
  ) {
    return fail(res, 401, 'invalid_client', 'private_key_jwt required');
  }
  let claimedClient: string;
  try {
    claimedClient = JSON.parse(Buffer.from(b.client_assertion.split('.')[1], 'base64url').toString()).iss;
  } catch {
    return fail(res, 401, 'invalid_client', 'malformed assertion');
  }
  const { rows } = await pool.query(
    'SELECT client_id, jwks, jwks_uri, disabled_at FROM oauth_clients WHERE client_id = $1',
    [claimedClient],
  );
  const client = rows[0];
  if (!client) return fail(res, 401, 'invalid_client', 'unknown client');
  if (client.disabled_at) return fail(res, 401, 'invalid_client', 'client disabled');
  const keySet = clientKeySet(client, { operation: 'token' });
  if (!keySet) return fail(res, 401, 'invalid_client', 'no registered key');
  try {
    await jwtVerify(b.client_assertion, keySet, {
      issuer: client.client_id,
      subject: client.client_id,
      audience: [config.issuer, `${config.issuer}/token`],
    });
  } catch {
    return fail(res, 401, 'invalid_client', 'assertion verification failed');
  }

  try {
    const tokens = await redeemAuthorizationCode({ clientId: client.client_id,
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
  issuer: () => config.issuer,
  jwks: getJwks,
  profile: async sub => {
    const { rows } = await pool.query<UserinfoProfile>(
      'SELECT sub, username, display_name, email, email_verified, avatar FROM identities WHERE sub = $1', [sub]);
    return rows[0];
  },
}));
