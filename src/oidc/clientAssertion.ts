import { jwtVerify } from 'jose';
import { pool } from '../db.js';
import { config } from '../config.js';
import { clientKeySet } from '../routes/token.js';

// Generic inbound client-assertion check (any enabled client, not just the
// portal): the assertion's iss names the client; verified against its registered
// keys (jwks_uri preferred, inline jwks fallback — see clientKeySet).
//
// Lifted out of routes/avatar.ts so the /internal/* endpoints share ONE verifier
// instead of accumulating copies. The portal-pinned sibling (isPortalAssertion in
// routes/reset.ts) stays separate — it deliberately ignores the assertion's iss
// and hard-pins the account client.
//
// Returns the verified client_id, or null for EVERY failure mode (wrong assertion
// type, unparseable, unknown/disabled client, no registered key, bad signature or
// claims). Never throws, never distinguishes causes — callers answer 401.
export async function assertedClient(body: Record<string, unknown>): Promise<string | null> {
  if (
    body.client_assertion_type !== 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer' ||
    typeof body.client_assertion !== 'string'
  ) {
    return null;
  }
  let iss = '';
  try {
    iss = String(JSON.parse(Buffer.from(body.client_assertion.split('.')[1], 'base64url').toString()).iss ?? '');
  } catch {
    return null;
  }
  if (!iss) return null;
  const { rows } = await pool.query(
    'SELECT client_id, jwks, jwks_uri, disabled_at FROM oauth_clients WHERE client_id = $1',
    [iss],
  );
  const client = rows[0];
  if (!client || client.disabled_at) return null;
  const keySet = clientKeySet(client);
  if (!keySet) return null;
  try {
    await jwtVerify(body.client_assertion, keySet, {
      issuer: client.client_id,
      subject: client.client_id,
      audience: [config.issuer, `${config.issuer}/token`],
    });
    return client.client_id;
  } catch {
    return null;
  }
}
