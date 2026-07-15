import { Router, type Request, type Response } from 'express';
import crypto from 'node:crypto';
import { importJWK, jwtVerify, type JWK } from 'jose';
import { config } from '../config.js';
import { s2sAssertion } from '../oidc.js';
import { getSession } from '../session.js';
import { s2sFetch } from '../s2sFetch.js';
import { SESSION_COOKIE } from './auth.js';

// Public (no session) password-reset API for the /forgot and /reset pages.
// The BFF plays videosite's turnstile-gate worker: it verifies the Turnstile
// token server-side BEFORE anything else, validates the identifier's shape,
// then proxies to the SSO's /internal/reset/* over the signed S2S channel.
// The SSO owns everything real (lookup, rate limit, token, email, challenge,
// password write, revocation, login ticket).
export const resetRouter = Router();

const SITEVERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';

// Same rule as the SPA's client-side check and the SSO's re-check: bare
// username = videosite's 3–20 of [A-Za-z0-9_-]; with an @ it's an email
// (dot fine, RFC 5321 length cap).
function identifierOk(id: string): boolean {
  if (id.includes('@')) return id.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(id);
  return /^[A-Za-z0-9_-]{3,20}$/.test(id);
}

// Gate config (enabled + sealed secret) from the SSO's assertion-authed
// internal endpoint. Cached briefly; a fetch failure THROWS — the gate fails
// closed, and the caller surfaces 502 (the S2S forward would fail anyway).
interface TurnstileConfig {
  enabled: boolean;
  site_key: string | null;
  secret_key: string | null;
  gate_public_jwk: (JWK & { kid?: string }) | null;
}
let tsCache: { cfg: TurnstileConfig; at: number } | null = null;
async function turnstileConfig(): Promise<TurnstileConfig> {
  if (tsCache && Date.now() - tsCache.at < 10_000) return tsCache.cfg;
  const r = await s2sPost('/internal/settings/turnstile', {});
  if (!r.ok) throw new Error('turnstile_config_' + r.status);
  tsCache = { cfg: (await r.json()) as TurnstileConfig, at: Date.now() };
  return tsCache.cfg;
}

// x-gate-assertion: the edge worker verified the Turnstile token, stripped it,
// and signed what it forwarded (Ed25519 JWT — the back-channel style). Accept
// iff the signature verifies against the stored PUBLIC JWK, it's fresh
// (exp = iat+90s at the worker), it's bound to THIS path, and its body hash
// matches the exact bytes we received. Replay is already defeated upstream
// (the worker strips inbound x-gate-* on every request, like cf-connecting-ip);
// the freshness window covers a directly-exposed origin.
const gateKeys = new Map<string, Awaited<ReturnType<typeof importJWK>>>();
async function verifyGateAssertion(
  assertion: string,
  jwk: JWK & { kid?: string },
  req: Request & { rawBody?: Buffer },
): Promise<boolean> {
  try {
    const cacheKey = JSON.stringify(jwk);
    let key = gateKeys.get(cacheKey);
    if (!key) {
      key = await importJWK(jwk, 'EdDSA');
      gateKeys.clear(); // single active key — drop rotated-out ones
      gateKeys.set(cacheKey, key);
    }
    const { payload } = await jwtVerify(assertion, key, {
      issuer: 'turnstile-gate',
      audience: 'account-bff',
      clockTolerance: 5,
      maxTokenAge: '2 minutes',
    });
    if (payload.path !== req.path) return false;
    const bodyHash = crypto.createHash('sha256').update(req.rawBody ?? Buffer.alloc(0)).digest('base64url');
    return payload.body_sha256 === bodyHash;
  } catch {
    return false;
  }
}

async function verifyTurnstile(token: unknown, secret: string, ip?: string): Promise<boolean> {
  if (!token || typeof token !== 'string') return false;
  const form = new FormData();
  form.append('secret', secret);
  form.append('response', token);
  if (ip) form.append('remoteip', ip);
  try {
    const r = await fetch(SITEVERIFY_URL, { method: 'POST', body: form, signal: AbortSignal.timeout(10_000) });
    if (!r.ok) return false;
    const data = (await r.json()) as { success?: boolean };
    return data.success === true;
  } catch {
    // siteverify unreachable -> fail closed (a rare flap surfaces as a 403;
    // better than letting a bot through). Same call videosite's worker makes.
    return false;
  }
}

// The whole gate decision (shared with the registration routes — same worker,
// same rules): token present -> siteverify here; no token + gate key set -> a
// valid x-gate-assertion proves the edge worker already verified + stripped
// it; neither -> 403. Returns false when the 403 was already sent.
export async function enforceTurnstileGate(req: Request, res: Response): Promise<boolean> {
  const ts = await turnstileConfig();
  if (!ts.enabled) return true;
  const token = (req.body ?? {}).turnstile_token;
  if (token) {
    if (!(await verifyTurnstile(token, ts.secret_key!, req.ip))) {
      res.status(403).json({ error: 'turnstile_failed' });
      return false;
    }
    return true;
  }
  const assertion = req.headers['x-gate-assertion'];
  const ok =
    !!ts.gate_public_jwk && typeof assertion === 'string' &&
    (await verifyGateAssertion(assertion, ts.gate_public_jwk, req as Request & { rawBody?: Buffer }));
  if (!ok) {
    res.status(403).json({ error: 'turnstile_failed' });
    return false;
  }
  return true;
}

export async function s2sPost(path: string, body: Record<string, unknown>): Promise<globalThis.Response> {
  const assertion = await s2sAssertion();
  return s2sFetch(config.internal + path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      ...body,
      client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
      client_assertion: assertion,
    }),
    signal: AbortSignal.timeout(10_000),
  });
}

// Mirror an SSO response. A 401 here means OUR assertion was rejected — a
// deployment problem, not something the visitor can act on: surface as 502.
export async function mirror(res: Response, upstream: globalThis.Response): Promise<void> {
  if (upstream.status === 204) {
    res.status(204).end();
    return;
  }
  const data = await upstream.json().catch(() => null);
  if (upstream.status === 401 && (data as { error?: string } | null)?.error === 'invalid_client') {
    console.error('reset proxy: SSO rejected our client assertion');
    res.status(502).json({ error: 'upstream_unreachable' });
    return;
  }
  res.status(upstream.status).json(data);
}

const qstr = (v: unknown): string => (typeof v === 'string' ? v : '');

// POST /api/reset/request {identifier, turnstile_token} — Turnstile gate ->
// shape check -> forward. Always 204 for acceptable input (the SSO does the
// real work asynchronously); only "email isn't configured" surfaces (503).
resetRouter.post('/api/reset/request', async (req: Request, res: Response) => {
  try {
    // Signed-in users change their password in Security instead (parity with
    // videosite's already-logged-in check).
    if (await getSession(req.cookies?.[SESSION_COOKIE])) {
      return res.status(400).json({ error: 'already_authenticated' });
    }

    const identifier = qstr((req.body ?? {}).identifier).trim();
    if (!identifierOk(identifier)) return res.status(422).json({ error: 'invalid_identifier' });

    if (!(await enforceTurnstileGate(req, res))) return;

    await mirror(res, await s2sPost('/internal/reset/request', { identifier }));
  } catch (e) {
    console.error('reset request proxy failed:', (e as Error).message);
    res.status(502).json({ error: 'upstream_unreachable' });
  }
});

// The rest are thin capability-keyed proxies (the reset token does the
// authorizing); bodies are whitelisted field by field.
resetRouter.post('/api/reset/validate', async (req: Request, res: Response) => {
  try {
    await mirror(res, await s2sPost('/internal/reset/validate', { token: qstr((req.body ?? {}).token) }));
  } catch (e) {
    console.error('reset validate proxy failed:', (e as Error).message);
    res.status(502).json({ error: 'upstream_unreachable' });
  }
});

resetRouter.post('/api/reset/passkey-options', async (req: Request, res: Response) => {
  try {
    await mirror(res, await s2sPost('/internal/reset/passkey-options', { token: qstr((req.body ?? {}).token) }));
  } catch (e) {
    console.error('reset passkey-options proxy failed:', (e as Error).message);
    res.status(502).json({ error: 'upstream_unreachable' });
  }
});

resetRouter.post('/api/reset/confirm', async (req: Request, res: Response) => {
  try {
    const b = (req.body ?? {}) as Record<string, unknown>;
    await mirror(res, await s2sPost('/internal/reset/confirm', {
      token: qstr(b.token),
      password: typeof b.password === 'string' ? b.password : '',
      ...(b.method !== undefined ? { method: qstr(b.method) } : {}),
      ...(b.code !== undefined ? { code: qstr(b.code) } : {}),
      ...(b.credential !== undefined ? { credential: qstr(b.credential) } : {}),
    }));
  } catch (e) {
    console.error('reset confirm proxy failed:', (e as Error).message);
    res.status(502).json({ error: 'upstream_unreachable' });
  }
});

// POST /api/verify-email {token} — public capability hop for the emailed
// verification link (email change + confirm-current). The clicker may be
// signed out; the single-use token authorizes.
resetRouter.post('/api/verify-email', async (req: Request, res: Response) => {
  try {
    await mirror(res, await s2sPost('/internal/email-change/verify', { token: qstr((req.body ?? {}).token) }));
  } catch (e) {
    console.error('verify-email proxy failed:', (e as Error).message);
    res.status(502).json({ error: 'upstream_unreachable' });
  }
});
