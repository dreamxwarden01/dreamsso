import { pool } from './db.js';
import { sealSecret, openSecret } from './secretbox.js';

// Admin-editable settings (settings table). Small in-process cache so hot paths
// (e.g. GET / redirect) don't hit Postgres per request; writes go through
// setSetting/setSecretSetting which invalidate in-process immediately.
// Secret values are sealed (KEY_ENCRYPTION_KEY) and stored as 'enc:v1:<base64>'.
const ENC_PREFIX = 'enc:v1:';
const TTL_MS = 5_000;
const cache = new Map<string, { v: string | null; at: number }>();

async function readRaw(key: string): Promise<string | null> {
  const hit = cache.get(key);
  if (hit && Date.now() - hit.at < TTL_MS) return hit.v;
  const { rows } = await pool.query<{ value: string }>('SELECT value FROM settings WHERE key = $1', [key]);
  const v = rows[0]?.value ?? null;
  cache.set(key, { v, at: Date.now() });
  return v;
}

export async function getSetting(key: string, fallback: string | null = null): Promise<string | null> {
  const v = await readRaw(key);
  return v != null && v !== '' ? v : fallback;
}

export async function getSecretSetting(key: string): Promise<string | null> {
  const v = await readRaw(key);
  if (!v) return null;
  if (!v.startsWith(ENC_PREFIX)) return null; // refuse to treat plaintext as a secret
  try {
    return openSecret(Buffer.from(v.slice(ENC_PREFIX.length), 'base64'));
  } catch {
    return null; // KEK changed / corrupted — treat as unset
  }
}

async function writeRaw(key: string, value: string | null): Promise<void> {
  if (value == null || value === '') {
    await pool.query('DELETE FROM settings WHERE key = $1', [key]);
  } else {
    await pool.query(
      `INSERT INTO settings (key, value) VALUES ($1, $2)
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
      [key, value],
    );
  }
  cache.set(key, { v: value == null || value === '' ? null : value, at: Date.now() });
}

export const setSetting = (key: string, value: string | null) => writeRaw(key, value);

export async function setSecretSetting(key: string, value: string | null): Promise<void> {
  await writeRaw(key, value == null || value === '' ? null : ENC_PREFIX + sealSecret(value).toString('base64'));
}

// True when a (secret) setting exists — for "configured" indicators that must
// never echo the value itself.
export async function hasSetting(key: string): Promise<boolean> {
  return (await readRaw(key)) != null;
}
