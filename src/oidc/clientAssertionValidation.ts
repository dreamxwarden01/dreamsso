import { createHash } from 'node:crypto';
import { decodeJwt, jwtVerify, errors, type JWTVerifyGetKey } from 'jose';

export const CLIENT_ASSERTION_TTL_SECONDS = 120;
export const CLIENT_ASSERTION_CLOCK_TOLERANCE = 10;
export const CLIENT_ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
export interface AssertionClient { client_id: string; disabled_at: string | Date | null }
export interface AssertionOperation { method: string; path: string }
export interface ClientAssertionDependencies<Client extends AssertionClient> {
  issuer(): string;
  loadClient(clientId: string): Promise<Client | null>;
  keySet(client: Client, operation: AssertionOperation): JWTVerifyGetKey | null;
  claimNonce(key: string, ttlSeconds: number): Promise<boolean>;
  now?: () => number;
}
export class ClientAssertionUnavailable extends Error {
  constructor() { super('Client assertion verification unavailable.'); }
}

// jose receives a request-time Date, but key resolution and nonce storage can
// yield. Revalidate at each admission boundary using the current injected clock.
function timeCurrent(issued: number, expires: number, now: number): boolean {
  if (!Number.isFinite(now)) return false;
  const seconds = Math.floor(now / 1000);
  return expires > seconds - CLIENT_ASSERTION_CLOCK_TOLERANCE
    && seconds - issued <= CLIENT_ASSERTION_TTL_SECONDS + CLIENT_ASSERTION_CLOCK_TOLERANCE
    && issued <= seconds + CLIENT_ASSERTION_CLOCK_TOLERANCE;
}

/** One replay namespace covers token and internal authentication. Existing
 * first-party senders use a fresh 60-second assertion per HTTP request.
 * Legacy issuer/token audiences remain compatible, while the signed method
 * and exact path bind each proof to one operation. Deploy bound senders first.
 */
export function createClientAssertionVerifier<Client extends AssertionClient>(deps: ClientAssertionDependencies<Client>) {
  return async (body: Record<string, unknown>, operation: AssertionOperation, expectedClientId?: string): Promise<string | null> => {
    if (!operation || typeof operation.method !== 'string' || typeof operation.path !== 'string'
      || !operation.method || !operation.path.startsWith('/')) return null;
    const token = body.client_assertion;
    if (body.client_assertion_type !== CLIENT_ASSERTION_TYPE || typeof token !== 'string' || token.length === 0 || token.length > 16384) return null;
    let claimed: string;
    try {
      const payload = decodeJwt(token);
      if (typeof payload.iss !== 'string' || !payload.iss || payload.iss.length > 200) return null;
      claimed = payload.iss;
      if (expectedClientId && claimed !== expectedClientId) return null;
    } catch { return null; }
    let client: Client | null, keys: JWTVerifyGetKey | null;
    try {
      client = await deps.loadClient(claimed);
      if (!client || client.disabled_at) return null;
      keys = deps.keySet(client, operation);
    } catch { throw new ClientAssertionUnavailable(); }
    if (!keys) return null;
    const now = deps.now?.() ?? Date.now();
    const seconds = Math.floor(now / 1000);
    let keyUnavailable = false, jti: string, issued: number, expires: number;
    try {
      const resolve: JWTVerifyGetKey = async (header, flattened) => {
        try { return await keys!(header, flattened); }
        catch (error) {
          if (!(error instanceof errors.JWKSNoMatchingKey) && !(error instanceof errors.JWKSMultipleMatchingKeys)) keyUnavailable = true;
          throw error;
        }
      };
      const issuer = deps.issuer();
      const { payload } = await jwtVerify(token, resolve, {
        issuer: client.client_id, subject: client.client_id, audience: [issuer, `${issuer}/token`],
        algorithms: ['EdDSA'], requiredClaims: ['iss', 'sub', 'aud', 'iat', 'exp', 'jti'],
        maxTokenAge: `${CLIENT_ASSERTION_TTL_SECONDS} seconds`, clockTolerance: CLIENT_ASSERTION_CLOCK_TOLERANCE,
        currentDate: new Date(now),
      });
      if (!Number.isSafeInteger(payload.iat) || !Number.isSafeInteger(payload.exp)
        || payload.exp! <= payload.iat! || payload.exp! - payload.iat! > CLIENT_ASSERTION_TTL_SECONDS
        || payload.iat! > seconds + CLIENT_ASSERTION_CLOCK_TOLERANCE
        || typeof payload.jti !== 'string' || !payload.jti || Buffer.byteLength(payload.jti) > 256) return null;
      // Current senders use one string audience. Keep both existing values but
      // avoid treating a multi-audience token as an unrestricted shared proof.
      if (typeof payload.aud !== 'string' || ![issuer, `${issuer}/token`].includes(payload.aud)) return null;
      if (!operation || payload.method !== operation.method || payload.path !== operation.path) return null;
      jti = payload.jti;issued = payload.iat!;expires = payload.exp!;
    } catch {
      if (keyUnavailable) throw new ClientAssertionUnavailable();
      return null;
    }
    const verifiedAt = deps.now?.() ?? Date.now();
    if (!timeCurrent(issued, expires, verifiedAt)) return null;
    const digest = createHash('sha256').update(JSON.stringify([client.client_id, jti])).digest('hex');
    const ttl = Math.max(1, Math.ceil(expires + CLIENT_ASSERTION_CLOCK_TOLERANCE - Math.floor(verifiedAt / 1000)));
    let claimedNonce: boolean;
    try { claimedNonce = await deps.claimNonce(`client-assertion:used:${digest}`, ttl); }
    catch { throw new ClientAssertionUnavailable(); }
    if (!claimedNonce || !timeCurrent(issued, expires, deps.now?.() ?? Date.now())) return null;
    return client.client_id;
  };
}
