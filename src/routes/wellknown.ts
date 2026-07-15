import { Router } from 'express';
import { config } from '../config.js';
import { getJwks } from '../keys.js';

export const wellKnownRouter = Router();

wellKnownRouter.get('/.well-known/openid-configuration', (_req, res) => {
  const i = config.issuer;
  res.setHeader('Cache-Control', 'public, max-age=300');
  res.json({
    issuer: i,
    authorization_endpoint: `${i}/authorize`,
    token_endpoint: `${i}/token`,
    userinfo_endpoint: `${i}/userinfo`,
    jwks_uri: `${i}/jwks`,
    end_session_endpoint: `${i}/logout`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['private_key_jwt'],
    id_token_signing_alg_values_supported: ['EdDSA'],
    subject_types_supported: ['public'],
    scopes_supported: ['openid', 'profile', 'email'],
  });
});

wellKnownRouter.get('/jwks', async (_req, res) => {
  res.setHeader('Cache-Control', 'public, max-age=300');
  res.json(await getJwks());
});
