import { createLocalJWKSet, createRemoteJWKSet, errors, type JSONWebKeySet, type JWTVerifyGetKey } from 'jose';

export interface ClientKeyRegistration {
  client_id: string;
  jwks_uri: string | null;
  jwks: JSONWebKeySet | null;
}
export interface ClientKeyContext {
  operation: 'token' | 'events' | 'reset' | 'client_assertion' | 'access_state' | 'registration';
  requestId?: string;
}
export interface KeyDiagnostic {
  event: 'client_key_failure';
  operation: ClientKeyContext['operation'];
  stage: 'key_config' | 'key_resolution' | 'key_fetch';
  error_code: string;
  reason: string;
  elapsed_ms: number;
  client_id?: string;
  request_id?: string;
  jwks_host?: string;
  fresh?: boolean;
  cooling_down?: boolean;
}

const SAFE_CODES = new Set([
  'EACCES', 'EPERM', 'ECONNREFUSED', 'ENOTFOUND', 'EAI_AGAIN', 'ECONNRESET',
  'EHOSTUNREACH', 'ENETUNREACH', 'ETIMEDOUT', 'ERR_TLS_CERT_ALTNAME_INVALID',
  'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY',
  'DEPTH_ZERO_SELF_SIGNED_CERT', 'SELF_SIGNED_CERT_IN_CHAIN', 'CERT_HAS_EXPIRED',
  'ERR_JWKS_TIMEOUT', 'ERR_JWKS_INVALID', 'ERR_JWK_INVALID', 'ERR_JOSE_GENERIC',
]);
/** Error messages and causes may contain URLs or credentials; emit only known codes. */
export function safeKeyError(error: unknown): { code: string; reason: string } {
  const value = error && typeof error === 'object' ? error as { code?: unknown; message?: unknown; cause?: unknown } : {};
  const cause = value.cause && typeof value.cause === 'object' ? value.cause as { code?: unknown } : {};
  const code = [value.code, cause.code].find(candidate => typeof candidate === 'string' && SAFE_CODES.has(candidate)) as string | undefined;
  const reason = value.message === 'Expected 200 OK from the JSON Web Key Set HTTP response' ? 'jwks_http_non_200'
    : value.message === 'Failed to parse the JSON Web Key Set HTTP response as JSON' ? 'jwks_bad_json'
    : code === 'ERR_JWKS_TIMEOUT' ? 'jwks_timeout'
    : code === 'ERR_JWKS_INVALID' || code === 'ERR_JWK_INVALID' ? 'invalid_key_material'
    : code ? 'key_transport_or_material_failure' : 'key_configuration_or_resolution_failure';
  return { code: code ?? 'UNKNOWN', reason };
}
function defaultLog(event: KeyDiagnostic): void { console.warn(JSON.stringify(event)); }
function report(log: (event: KeyDiagnostic) => void, event: KeyDiagnostic): void {
  try { log(event); } catch { /* Diagnostics must never change authentication results. */ }
}
function endpoint(value: string, registration = false): URL {
  const url = new URL(value);
  if (registration && url.protocol !== 'https:' && !(url.protocol === 'http:' && ['localhost', '127.0.0.1'].includes(url.hostname))) {
    throw new Error('Invalid JWKS endpoint protocol.');
  }
  return url;
}
function identityFields(client?: ClientKeyRegistration, context?: ClientKeyContext) {
  const clientId = client?.client_id;
  return {
    ...(clientId && /^[A-Za-z0-9_.-]{1,200}$/.test(clientId) ? { client_id: clientId } : {}),
    ...(context?.requestId && /^[0-9a-f-]{36}$/i.test(context.requestId) ? { request_id: context.requestId } : {}),
  };
}

/** Shared transport policy; preserve existing registered URI behavior at runtime. */
function remoteSet(url: URL) {
  return createRemoteJWKSet(url, {
    timeoutDuration: 3000,
    cacheMaxAge: 600_000,
    cooldownDuration: 30_000,
    headers: { Accept: 'application/json' },
  });
}

export class ClientKeyResolver {
  private readonly remote = new Map<string, ReturnType<typeof remoteSet>>();
  constructor(private readonly log: (event: KeyDiagnostic) => void = defaultLog) {}

  keySet(client: ClientKeyRegistration, context: ClientKeyContext = { operation: 'client_assertion' }): JWTVerifyGetKey | null {
    const started = performance.now();
    let set: JWTVerifyGetKey;
    let remote: ReturnType<typeof remoteSet> | undefined;
    let host: string | undefined;
    try {
      if (client.jwks_uri) {
        const url = endpoint(client.jwks_uri);host = url.hostname;
        const cacheKey = JSON.stringify([client.client_id, client.jwks_uri]);
        remote = this.remote.get(cacheKey);
        if (!remote) { remote = remoteSet(url);this.remote.set(cacheKey, remote); }
        set = remote;
      } else if (client.jwks) set = createLocalJWKSet(client.jwks);
      else return null;
    } catch (error) {
      const detail = safeKeyError(error);
      report(this.log, { event: 'client_key_failure', operation: context.operation, stage: 'key_config',
        error_code: detail.code, reason: detail.reason, elapsed_ms: Math.round(performance.now() - started),
        ...identityFields(client, context), ...(host ? { jwks_host: host } : {}) });
      throw error;
    }
    return async (header, token) => {
      const started = performance.now();
      try { return await set(header, token); }
      catch (error) {
        // Caller-controlled unknown/ambiguous kid is an authentication failure, not a fetch diagnostic.
        if (!(error instanceof errors.JWKSNoMatchingKey) && !(error instanceof errors.JWKSMultipleMatchingKeys)) {
          const detail = safeKeyError(error);
          report(this.log, { event: 'client_key_failure', operation: context.operation, stage: 'key_resolution',
            error_code: detail.code, reason: detail.reason, elapsed_ms: Math.round(performance.now() - started),
            ...identityFields(client, context), ...(host ? { jwks_host: host } : {}),
            ...(remote ? { fresh: remote.fresh, cooling_down: remote.coolingDown } : {}) });
        }
        throw error;
      }
    };
  }


  // Registration-time key fetch — the "confirm" step of the install flow: the app
  // is expected to be live and serving its JWKS BEFORE it's registered here, so a
  // jwks_uri that can't produce keys right now is a config error, not a race.
  // (Install-time bootstrap for a not-yet-live app = paste the inline JWKS instead.)
  // On success the fetched JWKS is returned and stored alongside the uri as a
  // snapshot: jwks_uri non-null = automatic fetch active (what /token prefers),
  // while the snapshot gives the edit form's paste view real content — saving in
  // paste mode then pins those keys and clears the uri (fetch off).
  async verifyUri(value: string): Promise<{ error: string | null; jwks?: JSONWebKeySet }> {
    const started = performance.now();let host: string | undefined;
    let stage: KeyDiagnostic['stage'] = 'key_config';
    try {
      const url = endpoint(value, true);host = url.hostname;
      const set = remoteSet(url);stage = 'key_fetch';
      await set.reload();
      const jwks = set.jwks();stage = 'key_config';
      if (!jwks || jwks.keys.length === 0) throw new errors.JWKSInvalid('JWKS must contain keys.');
      return { error: null, jwks };
    } catch (error) {
      const detail = safeKeyError(error);
      report(this.log, { event: 'client_key_failure', operation: 'registration', stage,
        error_code: detail.code, reason: detail.reason, elapsed_ms: Math.round(performance.now() - started),
        ...(host ? { jwks_host: host } : {}) });
      return { error: `JWKS check failed (${detail.code}: ${detail.reason})` };
    }
  }
}

const shared = new ClientKeyResolver();
export const clientKeySet = (client: ClientKeyRegistration, context?: ClientKeyContext) => shared.keySet(client, context);
export const verifyJwksUri = (url: string) => shared.verifyUri(url);
