import { getJwks } from './keys.js';
import { config } from './config.js';
import { createAccountResourceAuth } from './accountResourceAuth.js';
export { accountResourceError } from './accountResourceAuth.js';
export type { ResourceAuth, AuthedRequest } from './accountResourceAuth.js';

// Existing Account tokens already carry client_id and typ=at+jwt. Keep their
// issuer audience; ordinary RP tokens remain valid at the separate /userinfo.
export const { verifyAccessToken, requireScope } = createAccountResourceAuth({
  issuer: () => config.issuer,
  accountClientId: () => config.accountClientId,
  jwks: getJwks,
});
