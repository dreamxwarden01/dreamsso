import http from 'node:http';
import https from 'node:https';
import { createRequire } from 'node:module';
import { performance } from 'node:perf_hooks';
import { errors } from 'jose';

const require = createRequire(import.meta.url);
// Preserve the public-key request identity used by the installed jose resolver.
const userAgent = `jose/v${require('jose/package.json').version}`;
export const CLIENT_JWKS_TIMEOUT_MS = 3000;
export const CLIENT_JWKS_MAX_BYTES = 256 * 1024;

export class ClientJwksTooLarge extends errors.JOSEError {
  code = 'ERR_JWKS_RESPONSE_TOO_LARGE';
  constructor() { super('JWKS response exceeds the size limit.'); }
}

/** One deadline spans connection, TLS, headers and the entire response body.
 * Destroy the transport on every failure; rejecting a racing promise alone
 * would leave a stalled fetch running and hold the resolver's in-flight slot.
 */
export function fetchClientJwks(url: URL, options: { timeoutMs?: number; maxBytes?: number } = {}): Promise<unknown> {
  const timeoutMs = options.timeoutMs ?? CLIENT_JWKS_TIMEOUT_MS;
  const maxBytes = options.maxBytes ?? CLIENT_JWKS_MAX_BYTES;
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0 || !Number.isSafeInteger(maxBytes) || maxBytes <= 0) {
    return Promise.reject(new TypeError('Invalid JWKS transport limits.'));
  }
  return new Promise((resolve, reject) => {
    const started = performance.now();
    let request: http.ClientRequest | undefined;
    let response: http.IncomingMessage | undefined;
    let done = false;
    let bytes = 0;
    let chunks: Buffer[] = [];
    const timer = setTimeout(() => fail(new errors.JWKSTimeout()), timeoutMs);
    function fail(error: Error) {
      if (done) return;
      done = true;
      clearTimeout(timer);
      chunks = [];
      // Listeners below also absorb errors produced by destroy().
      response?.destroy();
      request?.destroy();
      reject(error);
    }
    try {
      const get = url.protocol === 'https:' ? https.get : url.protocol === 'http:' ? http.get : null;
      if (!get) throw new TypeError('Unsupported URL protocol.');
      request = get(url, { headers: { Accept: 'application/json', 'User-Agent': userAgent } }, (res) => {
        response = res;
        res.on('error', fail);
        res.once('aborted', () => fail(new errors.JOSEError('Incomplete JWKS response.')));
        if (done) { res.destroy(); return; }
        // Deliberately do not follow redirects or apply extra credentials/trust overrides.
        if (res.statusCode !== 200) {
          fail(new errors.JOSEError('Expected 200 OK from the JSON Web Key Set HTTP response'));
          return;
        }
        const length = res.headers['content-length'];
        if (length && /^\d+$/.test(length) && Number(length) > maxBytes) { fail(new ClientJwksTooLarge()); return; }
        res.on('data', (part: Buffer) => {
          if (done) return;
          bytes += part.length;
          if (bytes > maxBytes) { fail(new ClientJwksTooLarge()); return; }
          chunks.push(part);
        });
        res.once('end', () => {
          if (done) return;
          if (!res.complete) { fail(new errors.JOSEError('Incomplete JWKS response.')); return; }
          let value: unknown;
          try { value = JSON.parse(Buffer.concat(chunks, bytes).toString('utf8')); }
          catch { fail(new errors.JOSEError('Failed to parse the JSON Web Key Set HTTP response as JSON')); return; }
          if (performance.now() - started >= timeoutMs) { fail(new errors.JWKSTimeout()); return; }
          done = true;
          clearTimeout(timer);
          chunks = [];
          resolve(value);
        });
      });
      request.on('error', fail);
    } catch (error) {
      fail(error instanceof Error ? error : new errors.JOSEError());
    }
  });
}
