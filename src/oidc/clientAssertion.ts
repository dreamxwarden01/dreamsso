import { pool } from '../db.js';
import { redis } from '../redis.js';
import { config } from '../config.js';
import { clientKeySet, type ClientKeyRegistration } from '../clientKeys.js';
import { createClientAssertionVerifier, type AssertionClient, type AssertionOperation } from './clientAssertionValidation.js';

type RegisteredClient = AssertionClient & ClientKeyRegistration;
const verify = createClientAssertionVerifier<RegisteredClient>({
  issuer: () => config.issuer,
  loadClient: async clientId => {
    const { rows } = await pool.query<RegisteredClient>(
      'SELECT client_id, jwks, jwks_uri, disabled_at FROM oauth_clients WHERE client_id = $1', [clientId]);
    return rows[0] ?? null;
  },
  keySet: (client, operation) => clientKeySet(client, { operation: operation.path === '/token' ? 'token' : 'client_assertion' }),
  claimNonce: async (key, ttl) => (await redis.set(key, '1', 'EX', ttl, 'NX')) === 'OK',
});

/** Authentication failures return null. Storage/transport outages are typed and
 * must be surfaced as sanitized 503 by the HTTP boundary, never invalid-client.
 */
export function assertedClient(body: Record<string, unknown>, operation: AssertionOperation): Promise<string | null> {
  return verify(body, operation);
}
export async function assertedPortal(body: Record<string, unknown>, operation: AssertionOperation): Promise<boolean> {
  return (await verify(body, operation, config.accountClientId)) !== null;
}
