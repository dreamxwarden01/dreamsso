import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import IORedis from 'ioredis';
import { calculateJwkThumbprint, type JWK } from 'jose';
import { applyConfig, config } from '../config.js';
import { reconnectRedis } from '../redis.js';

// Where the wizard writes the resolved .env. Overridable for tests so the real file
// is never touched.
const ENV_FILE = process.env.SETUP_ENV_FILE || path.resolve(process.cwd(), '.env');

const str = (v: unknown): string => (typeof v === 'string' ? v.trim() : '');
const noSlash = (u: string): string => u.replace(/\/+$/, '');

// The portal's three real inputs. Everything else the SSO needs (callback, logout,
// jwks_uri, events_uri) is DERIVED from the public URL — one source of truth, and
// the operator can't typo a path.
export const derived = (publicUrl: string) => ({
  redirectUri: noSlash(publicUrl) + '/auth/callback',
  postLogoutRedirect: noSlash(publicUrl) + '/',
  jwksUri: noSlash(publicUrl) + '/.well-known/jwks.json',
  eventsUri: noSlash(publicUrl) + '/backchannel/events',
});

// Presence is read from process.env (what's actually in .env), NOT config — config
// carries defaults (client id, redis) that would mask "not set".
export function readEnvState() {
  const p = process.env;
  const field = (raw: string | undefined) => (raw ? { present: true, value: raw } : { present: false as const });
  return {
    hasClientKey: fs.existsSync(config.clientKeyFile),
    clientKeyFile: config.clientKeyFile,
    clientId: config.clientId,
    fields: {
      publicUrl: field(p.PUBLIC_URL),
      issuer: field(p.SSO_ISSUER),
      redis: field(p.REDIS_URL),
    },
  };
}

export type ResolvedConfig = {
  publicUrl: string;
  issuer: string;
  redisUrl: string;
};

// The wizard OMITS fields already present in .env; fill those from process.env.
export function resolveInput(input: Record<string, unknown>): ResolvedConfig {
  const p = process.env;
  return {
    publicUrl: noSlash(str(input.publicUrl) || (p.PUBLIC_URL ?? '')),
    issuer: noSlash(str(input.issuer) || (p.SSO_ISSUER ?? '')),
    redisUrl: str(input.redisUrl) || (p.REDIS_URL ?? ''),
  };
}

// Client + server share this rule set (the wizard mirrors it for live UX).
export function validateConfig(r: ResolvedConfig): Record<string, string> {
  const errors: Record<string, string> = {};
  const httpsUrl = (v: string): boolean => {
    try {
      return new URL(v).protocol === 'https:';
    } catch {
      return false;
    }
  };
  if (!httpsUrl(r.publicUrl)) {
    errors.publicUrl = 'Enter the portal’s own https:// origin, e.g. https://account.example.com';
  }
  if (!httpsUrl(r.issuer)) errors.issuer = 'Enter the SSO’s https:// issuer, e.g. https://sso.example.com';
  if (!/^rediss?:\/\/.+/.test(r.redisUrl)) errors.redis = 'Enter a redis:// URL (or rediss:// for TLS).';
  return errors;
}

const short = (m: string): string => (m.length > 160 ? m.slice(0, 157) + '…' : m);

// Connectivity probe on a throwaway client — run before anything is committed.
export async function testRedis(url: string): Promise<string | null> {
  // `any` avoids the project-wide ioredis default-import "not constructable" typing.
  const r: any = new (IORedis as any)(url, {
    lazyConnect: true,
    maxRetriesPerRequest: 1,
    connectTimeout: 4000,
    retryStrategy: () => null,
  });
  try {
    await r.connect();
    await r.ping();
    return null;
  } catch (e) {
    return short((e as Error).message);
  } finally {
    try {
      r.disconnect();
    } catch {
      /* */
    }
  }
}

// Is the SSO up, and does it publish the discovery document we'll be talking to?
// Informational only — the SSO may legitimately be brought up after the portal.
export async function probeSso(issuer: string): Promise<{
  ok: boolean;
  reachable: boolean;
  status?: number;
  reason?: string;
  issuer?: string;
}> {
  let target: string;
  try {
    if (new URL(issuer).protocol !== 'https:') throw new Error('scheme');
    target = noSlash(issuer) + '/.well-known/openid-configuration';
  } catch {
    return { ok: false, reachable: false, reason: 'bad_url' };
  }
  try {
    const r = await fetch(target, { signal: AbortSignal.timeout(4000) });
    if (r.status !== 200) return { ok: false, reachable: true, status: r.status, reason: 'no_discovery' };
    const body = (await r.json().catch(() => null)) as { issuer?: string } | null;
    // A mismatched `issuer` in the document means our config would fail id_token
    // validation later — worth catching now rather than at first login.
    if (!body?.issuer) return { ok: false, reachable: true, status: 200, reason: 'no_discovery' };
    if (noSlash(body.issuer) !== noSlash(issuer)) {
      return { ok: false, reachable: true, status: 200, reason: 'issuer_mismatch', issuer: body.issuer };
    }
    return { ok: true, reachable: true, status: 200, issuer: body.issuer };
  } catch (err) {
    return {
      ok: false,
      reachable: false,
      reason: (err as Error).name === 'TimeoutError' ? 'timeout' : 'unreachable',
    };
  }
}

// The portal's OIDC client key (private_key_jwt). The SSO never receives it — it
// reads the PUBLIC half from our jwks_uri — so we mint it ourselves rather than
// asking the operator for anything. Idempotent: an existing file is left alone.
export async function ensureClientKey(): Promise<{ kid: string; created: boolean }> {
  const file = config.clientKeyFile;
  if (fs.existsSync(file)) {
    const raw = JSON.parse(fs.readFileSync(file, 'utf8')) as Record<string, unknown>;
    const first = (Array.isArray(raw.keys) ? raw.keys[0] : raw) as JWK & { kid?: string };
    return { kid: first.kid ?? (await calculateJwkThumbprint(first)), created: false };
  }
  const jwk = crypto.generateKeyPairSync('ed25519').privateKey.export({ format: 'jwk' }) as JWK & {
    kid?: string;
    alg?: string;
  };
  jwk.kid = await calculateJwkThumbprint(jwk); // RFC 7638 (public members only)
  jwk.alg = 'EdDSA';
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify({ keys: [jwk] }, null, 2) + '\n', { mode: 0o600 });
  return { kid: jwk.kid, created: true };
}

function fmtVal(v: string): string {
  // Quote only when needed; dotenv reads JSON-style double-quoted values back.
  return /[\s#"'\\]/.test(v) ? JSON.stringify(v) : v;
}

// Merge into .env: update managed keys in place, append the rest — preserving
// comments and unmanaged keys (PORT, NODE_ENV, SESSION_TTL_SECONDS…).
function upsertEnv(updates: Record<string, string>): void {
  let lines: string[] = [];
  try {
    lines = fs.readFileSync(ENV_FILE, 'utf8').split('\n');
  } catch {
    /* fresh file */
  }
  const seen = new Set<string>();
  const out = lines.map((line) => {
    const m = line.match(/^\s*([A-Za-z0-9_]+)\s*=/);
    if (m && updates[m[1]] !== undefined) {
      seen.add(m[1]);
      return `${m[1]}=${fmtVal(updates[m[1]])}`;
    }
    return line;
  });
  const extra = Object.keys(updates).filter((k) => !seen.has(k));
  if (extra.length) {
    if (out.length && out[out.length - 1].trim() !== '') out.push('');
    out.push('# --- written by first-run setup ---');
    for (const k of extra) out.push(`${k}=${fmtVal(updates[k])}`);
  }
  // A file that already ended in a newline round-trips with a trailing '' element;
  // a fresh one doesn't — either way, end with exactly one.
  const text = out.join('\n');
  fs.writeFileSync(ENV_FILE, text.endsWith('\n') ? text : text + '\n', { mode: 0o600 });
}

// The config step: mint the client key if absent → write .env → adopt it in-process
// (reconnect Redis). No restart, and nothing here needs the SSO to be up. Callers
// must have validated + probed Redis first.
export async function applyAndPersist(
  r: ResolvedConfig,
): Promise<{ kid: string; created: boolean; jwksUri: string }> {
  const d = derived(r.publicUrl);

  const managed: Record<string, string> = {
    PUBLIC_URL: r.publicUrl,
    SSO_ISSUER: r.issuer,
    REDIS_URL: r.redisUrl,
    OIDC_CLIENT_ID: config.clientId,
    OIDC_REDIRECT_URI: d.redirectUri,
    OIDC_POST_LOGOUT_REDIRECT: d.postLogoutRedirect,
    OIDC_CLIENT_KEY_FILE: config.clientKeyFile,
  };
  upsertEnv(managed);
  Object.assign(process.env, managed); // keep a re-read of /setup/env accurate

  applyConfig({
    publicUrl: r.publicUrl,
    issuer: r.issuer,
    redisUrl: r.redisUrl,
    redirectUri: d.redirectUri,
    postLogoutRedirect: d.postLogoutRedirect,
  });
  await reconnectRedis();

  // Last, so a failure above leaves no key behind: the SSO registration reads this
  // key from our jwks_uri, so it must exist before the operator runs the SSO setup.
  const key = await ensureClientKey();
  return { ...key, jwksUri: d.jwksUri };
}
