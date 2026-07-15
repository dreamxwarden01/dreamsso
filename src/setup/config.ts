import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import pg from 'pg';
import IORedis from 'ioredis';
import { applyConfig, isValidKek } from '../config.js';
import { reconnectDb } from '../db.js';
import { reconnectRedis } from '../redis.js';
import { markConfigured } from './state.js';

// Where the wizard writes the resolved .env, and the consolidated schema it applies
// to a fresh DB. Overridable for tests so the real files are never touched.
const ENV_FILE = process.env.SETUP_ENV_FILE || path.resolve(process.cwd(), '.env');
const SCHEMA_FILE = process.env.SETUP_SCHEMA_FILE || path.resolve(process.cwd(), 'db/schema.sql');

const str = (v: unknown): string => (typeof v === 'string' ? v.trim() : '');

// A freshly generated KEK candidate, held in RAM until the operator saves — so the
// value shown by GET /setup/env matches what POST /setup/config writes.
let pendingKek: string | null = null;
function ensureKek(): string {
  if (!pendingKek) pendingKek = crypto.randomBytes(32).toString('hex');
  return pendingKek;
}
export function regenKek(): string {
  pendingKek = crypto.randomBytes(32).toString('hex');
  return pendingKek;
}

// Mask the password of a postgres URL for display (the operator can already read
// .env, but there's no reason to echo credentials back into the browser).
function maskDbUrl(u: string): string {
  try {
    const url = new URL(u);
    if (url.password) url.password = '****';
    return url.toString();
  } catch {
    return u;
  }
}

// Presence is read from process.env (what's actually in .env), NOT config — config
// carries dev defaults for issuer/redis/webauthn that would mask "not set".
export function readEnvState() {
  const p = process.env;
  const field = (raw: string | undefined, mask = false) =>
    raw ? { present: true, value: mask ? maskDbUrl(raw) : raw } : { present: false as const };
  const hasKey = isValidKek(p.KEY_ENCRYPTION_KEY ?? '');
  return {
    hasKey,
    generatedKey: hasKey ? null : ensureKek(), // never echo an existing KEK, only a fresh candidate
    fields: {
      database: field(p.DATABASE_URL, true),
      redis: field(p.REDIS_URL),
      issuer: field(p.ISSUER),
      rpId: field(p.WEBAUTHN_RP_ID),
      origins: field(p.WEBAUTHN_ORIGINS),
    },
  };
}

export type ConfigInput = {
  databaseUrl?: unknown;
  redisUrl?: unknown;
  issuer?: unknown;
  rpId?: unknown;
  origins?: unknown;
};

export type ResolvedConfig = {
  databaseUrl: string;
  redisUrl: string;
  issuer: string;
  rpId: string;
  origins: string;
};

// The wizard OMITS fields already present in .env (so it never round-trips the
// masked DB password); fill those from process.env here.
export function resolveInput(input: ConfigInput): ResolvedConfig {
  const p = process.env;
  return {
    databaseUrl: str(input.databaseUrl) || (p.DATABASE_URL ?? ''),
    redisUrl: str(input.redisUrl) || (p.REDIS_URL ?? ''),
    issuer: str(input.issuer) || (p.ISSUER ?? ''),
    rpId: str(input.rpId) || (p.WEBAUTHN_RP_ID ?? ''),
    origins: str(input.origins) || (p.WEBAUTHN_ORIGINS ?? ''),
  };
}

// Client + server share this rule set (the wizard mirrors it for live UX).
export function validateConfig(r: ResolvedConfig): Record<string, string> {
  const errors: Record<string, string> = {};
  const { databaseUrl: db, redisUrl: redis, issuer, rpId, origins } = r;

  if (!/^postgres(ql)?:\/\/.+/.test(db)) errors.database = 'Enter a postgres:// connection string.';
  if (!/^rediss?:\/\/.+/.test(redis)) errors.redis = 'Enter a redis:// URL (or rediss:// for TLS).';
  try {
    if (new URL(issuer).protocol !== 'https:') errors.issuer = 'The issuer must be an https:// URL.';
  } catch {
    errors.issuer = 'Enter a full URL, e.g. https://sso.example.com';
  }
  if (rpId && !/^[a-z0-9.-]+$/i.test(rpId)) errors.rpId = 'A bare domain like example.com — no scheme, no port.';
  if (origins) {
    const bad = origins.split(',').some((o) => {
      o = o.trim();
      if (!o) return false;
      try {
        return new URL(o).protocol !== 'https:';
      } catch {
        return true;
      }
    });
    if (bad) errors.origins = 'Comma-separated https origins.';
  }
  // Passkeys are all-or-nothing: RP ID and origins go together.
  if ((rpId && !origins) || (!rpId && origins)) {
    errors.origins = errors.origins ?? 'Set both an RP ID and origins, or leave both blank.';
  }
  return errors;
}

const short = (m: string): string => (m.length > 160 ? m.slice(0, 157) + '…' : m);

// Connectivity probes on throwaway clients — run before anything is committed.
export async function testDb(url: string): Promise<string | null> {
  const p = new pg.Pool({ connectionString: url, connectionTimeoutMillis: 4000, max: 1 });
  try {
    await p.query('SELECT 1');
    return null;
  } catch (e) {
    return short((e as Error).message);
  } finally {
    await p.end().catch(() => {});
  }
}

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

function fmtVal(v: string): string {
  // Quote only when needed; dotenv reads JSON-style double-quoted values back.
  return /[\s#"'\\]/.test(v) ? JSON.stringify(v) : v;
}

// Merge into .env: update managed keys in place, append the rest — preserving
// comments and unmanaged keys (POSTGRES_*/PG*, etc.).
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

// The step-1 transaction: schema (via a throwaway pool, so a failure commits
// nothing) → write .env → adopt the config in-process (reconnect DB/Redis) →
// mark configured. Callers must have validated + probed connectivity first.
export async function applyAndPersist(r: ResolvedConfig): Promise<void> {
  const databaseUrl = r.databaseUrl;
  const redisUrl = r.redisUrl;
  const issuer = r.issuer.replace(/\/+$/, ''); // no trailing slash in the issuer
  const rpId = r.rpId;
  const origins = r.origins;
  const kek = isValidKek(process.env.KEY_ENCRYPTION_KEY ?? '')
    ? process.env.KEY_ENCRYPTION_KEY!
    : ensureKek();

  // Apply the schema on a throwaway pool if the core table is absent.
  const tmp = new pg.Pool({ connectionString: databaseUrl, max: 1 });
  try {
    const { rows } = await tmp.query<{ t: string | null }>("SELECT to_regclass('public.identities') AS t");
    if (!rows[0]?.t) await tmp.query(fs.readFileSync(SCHEMA_FILE, 'utf8'));
  } finally {
    await tmp.end().catch(() => {});
  }

  // Persist (nothing above wrote state), then go live in-process.
  const managed: Record<string, string> = {
    KEY_ENCRYPTION_KEY: kek,
    DATABASE_URL: databaseUrl,
    REDIS_URL: redisUrl,
    ISSUER: issuer,
    WEBAUTHN_RP_ID: rpId,
    WEBAUTHN_ORIGINS: origins,
  };
  upsertEnv(managed);
  Object.assign(process.env, managed); // keep a re-read of /setup/env accurate

  applyConfig({
    databaseUrl,
    redisUrl,
    keyEncryptionKey: kek,
    issuer,
    webauthnRpId: rpId,
    webauthnOrigins: origins ? origins.split(',').map((s) => s.trim()).filter(Boolean) : [],
  });
  await reconnectDb();
  await reconnectRedis();
  pendingKek = null;
  markConfigured();
}
