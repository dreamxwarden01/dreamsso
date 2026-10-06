import { decodeJwt, jwtVerify, errors, type JWTVerifyGetKey } from 'jose';
import { Router } from 'express';
import { randomUUID } from 'node:crypto';
import { safeKeyError, type ClientKeyContext } from '../clientKeys.js';

export const ACCESS_STATE_PATH = '/backchannel/access-state';
export const ACCESS_QUERY_TYPE = 'backchannel-query+jwt';
export const MAX_SUBJECTS = 100;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export interface RegisteredClient {
  client_id: string;
  disabled_at: string | Date | null;
}
export interface AccessState {
  sub: string;
  account: { status: 'active' | 'disabled' | 'locked' | 'deleted' | 'not_found' };
  rp: { catalog_synced: boolean; role_id: number | null;
    role_source: 'override' | 'org' | 'catalog' | 'none'; access: 'allowed' | 'no_access' | 'unmanaged' | 'unknown_role' };
  allowed: boolean;
}
export interface AccessStateDependencies<Client extends RegisteredClient> {
  issuer: () => string;
  loadClient: (id: string) => Promise<Client | null>;
  keySet: (client: Client, context?: ClientKeyContext) => JWTVerifyGetKey | null;
  readStates: (clientId: string, subjects: readonly string[]) => Promise<AccessState[]>;
  now?: () => Date;
  diagnostic?: (event: AccessStateDiagnostic) => void;
}
export interface AccessStateDiagnostic {
  event: 'access_state_unavailable';
  request_id: string;
  stage: 'load_client' | 'key_config' | 'key_resolution' | 'read_states' | 'read_shape';
  error_code: string;
  elapsed_ms: number;
}

/** A separate signed read operation; never routes requests through the event processor. */
export function createAccessStateRouter<Client extends RegisteredClient>(deps: AccessStateDependencies<Client>) {
  const router = Router();
  router.all(ACCESS_STATE_PATH, async (req, res) => {
    const correlationId = randomUUID(), started = performance.now();
    res.setHeader('X-Request-ID', correlationId);
    const diagnostic = (stage: AccessStateDiagnostic['stage'], error?: unknown) => {
      const candidate = error && typeof error === 'object' && 'code' in error ? error.code : undefined;
      const code = (stage === 'load_client' || stage === 'read_states') && typeof candidate === 'string'
        && /^(?:[0-9]{2}[0-9A-Z]{3}|XX00[0-2])$/.test(candidate) ? candidate : safeKeyError(error).code;
      const event: AccessStateDiagnostic = { event: 'access_state_unavailable', request_id: correlationId,
        stage, error_code: code, elapsed_ms: Math.round(performance.now() - started) };
      try { if (deps.diagnostic) deps.diagnostic(event);else console.warn(JSON.stringify(event)); }
      catch { /* Logging failure must not turn a rejected request into success. */ }
    };
    res.set({ 'Cache-Control': 'no-store', Pragma: 'no-cache', 'Referrer-Policy': 'no-referrer' });
    res.vary('Authorization');
    if (req.method !== 'GET') return res.status(405).set('Allow', 'GET').json({ error: 'method_not_allowed' });
    // Neither the signature nor a selectable RP/subject goes in query-string logs.
    if (Object.keys(req.query).length) return res.status(400).json({ error: 'query_parameters_not_allowed' });
    const header = req.headers.authorization;
    const match = typeof header === 'string' && /^Bearer ([A-Za-z0-9_.-]+)$/i.exec(header);
    if (!match || match[1].length > 8192) return res.status(401).json({ error: 'invalid_signature' });
    const token = match[1];let clientId: string;
    try {
      const untrusted = decodeJwt(token);
      if (typeof untrusted.iss !== 'string' || !untrusted.iss || untrusted.iss.length > 200) throw new Error();
      clientId = untrusted.iss;
    } catch { return res.status(401).json({ error: 'invalid_signature' }); }
    let client: Client | null;
    try { client = await deps.loadClient(clientId); }
    catch (error) { diagnostic('load_client', error);return res.status(503).json({ error: 'access_state_unavailable' }); }
    if (!client || client.disabled_at) return res.status(401).json({ error: 'invalid_client' });
    const now = deps.now?.() ?? new Date();let subjects: string[], requestId: string, keyResolutionFailed = false;
    let keySetupComplete = false;
    try {
      const keys = deps.keySet(client, { operation: 'access_state', requestId: correlationId });
      keySetupComplete = true;if (!keys) throw new Error();
      const audience = deps.issuer().replace(/\/$/, '') + ACCESS_STATE_PATH;
      const resolveKeys: JWTVerifyGetKey = async (header, payload) => {
        try { return await keys(header, payload); }
        catch (error) { if (!(error instanceof errors.JWKSNoMatchingKey) && !(error instanceof errors.JWKSMultipleMatchingKeys)) keyResolutionFailed = true;throw error; }
      };
      const { payload } = await jwtVerify(token, resolveKeys, {
        algorithms: ['EdDSA'], typ: ACCESS_QUERY_TYPE, issuer: client.client_id,
        subject: client.client_id, audience, requiredClaims: ['iss', 'sub', 'aud', 'iat', 'exp', 'jti'],
        maxTokenAge: '120 seconds', clockTolerance: 10, currentDate: now,
      });
      if (typeof payload.iat !== 'number' || typeof payload.exp !== 'number'
        || !Number.isInteger(payload.iat) || !Number.isInteger(payload.exp)
        || payload.exp <= payload.iat || payload.exp - payload.iat > 120
        || payload.aud !== audience
        || typeof payload.jti !== 'string' || !UUID.test(payload.jti)
        || payload.method !== 'GET' || payload.path !== ACCESS_STATE_PATH || payload.action !== 'access-state') throw new Error();
      if (!Array.isArray(payload.subjects) || payload.subjects.length < 1 || payload.subjects.length > MAX_SUBJECTS
        || payload.subjects.some(value => typeof value !== 'string' || !UUID.test(value))) {
        return res.status(400).json({ error: 'invalid_subjects' });
      }
      subjects = (payload.subjects as string[]).map(value => value.toLowerCase());
      if (new Set(subjects).size !== subjects.length) return res.status(400).json({ error: 'invalid_subjects' });
      requestId = payload.jti;
    } catch (error) {
      const unavailable = !keySetupComplete || keyResolutionFailed;
      if (unavailable) diagnostic(!keySetupComplete ? 'key_config' : 'key_resolution', error);
      return res.status(unavailable ? 503 : 401).json({ error: unavailable ? 'access_state_unavailable' : 'invalid_signature' });
    }
    try {
      const states = await deps.readStates(client.client_id, subjects);
      if (states.length !== subjects.length || states.some((state, i) => state.sub !== subjects[i])) {
        diagnostic('read_shape');return res.status(503).json({ error: 'access_state_unavailable' });
      }
      return res.json({ client_id: client.client_id, request_id: requestId,
        checked_at: (deps.now?.() ?? new Date()).toISOString(), complete: true, subjects: states });
    } catch (error) { diagnostic('read_states', error);return res.status(503).json({ error: 'access_state_unavailable' }); }
  });
  return router;
}
