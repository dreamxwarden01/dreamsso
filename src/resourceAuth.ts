import { getJwks } from './keys.js';
import { pool } from './db.js';
import { readSessionWindows } from './oidc/sessionWindows.js';
import { readAccessTokenState } from './oidc/accessTokenState.js';
import { config } from './config.js';
import { createAccountResourceAuth } from './accountResourceAuth.js';
export { accountResourceError } from './accountResourceAuth.js';
export type { ResourceAuth, AuthedRequest } from './accountResourceAuth.js';

// Keep issuer audience and ordinary RP /userinfo capability. Every accepted
// bearer now names its original live SID; old no-SID tokens must reauthenticate.
export const { verifyAccessToken, requireScope } = createAccountResourceAuth({
  issuer: () => config.issuer,
  accountClientId: () => config.accountClientId,
  jwks: getJwks,
  readState: async (auth, db) => {
    const database = db ?? pool;
    const windows = await readSessionWindows(database);
    return readAccessTokenState(database, auth, windows);
  },
});
