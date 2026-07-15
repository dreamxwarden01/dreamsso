import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

// The portal's /setup wizard is an unauthenticated takeover surface, so it's gated
// by a token written to a file only someone with host access can read. Generated on
// first boot when setup isn't complete; the path is logged for the operator.
export const SETUP_TOKEN_FILE =
  process.env.SETUP_TOKEN_FILE || path.resolve(process.cwd(), '.setup-token');

let cached: string | null = null;

export function ensureSetupToken(): string {
  if (cached) return cached;
  try {
    const existing = fs.readFileSync(SETUP_TOKEN_FILE, 'utf8').trim();
    if (existing) {
      cached = existing;
      return existing;
    }
  } catch {
    /* not present yet */
  }
  const tok = crypto.randomBytes(32).toString('base64url');
  fs.writeFileSync(SETUP_TOKEN_FILE, tok + '\n', { mode: 0o600 });
  cached = tok;
  return tok;
}

// Constant-time compare against the live token.
export function verifySetupToken(candidate: unknown): boolean {
  if (typeof candidate !== 'string' || !candidate || !cached) return false;
  const a = Buffer.from(candidate);
  const b = Buffer.from(cached);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

export function clearSetupToken(): void {
  try {
    fs.unlinkSync(SETUP_TOKEN_FILE);
  } catch {
    /* already gone */
  }
  cached = null;
}
