import crypto from 'node:crypto';
import type { Request, Response } from 'express';
import { pool } from '../db.js';
import { getSetting } from '../settings.js';

export const SESSION_COOKIE = 'sso_session';
const sha256 = (s: string) => crypto.createHash('sha256').update(s).digest();

// Session validity (videosite's model, admin-configurable): an IDLE window
// against last_seen plus an ABSOLUTE window against created_at, both in HOURS,
// read from settings at check time — tightening the settings applies to live
// sessions immediately. `expires_at` is still written (absolute cap at creation)
// but the dynamic windows are the source of truth. Ranges: idle 1–2160 (90d),
// absolute 1–8760 (1y), idle ≤ absolute (enforced at write; reads clamp
// defensively). Defaults: 72h idle / 168h absolute.
const clampHours = (v: string | null, fallback: number, maxRange: number) => {
  const n = parseInt(v ?? '', 10);
  return Number.isFinite(n) && n >= 1 && n <= maxRange ? n : fallback;
};
export async function getSessionWindows(): Promise<{ idleHours: number; maxHours: number; transientMaxHours: number }> {
  const [idle, max, transient] = await Promise.all([
    getSetting('session_idle_hours'),
    getSetting('session_max_hours'),
    getSetting('session_transient_max_hours'),
  ]);
  const maxHours = clampHours(max, 168, 8760);
  return {
    idleHours: Math.min(clampHours(idle, 72, 2160), maxHours),
    maxHours,
    // Absolute cap for TRANSIENT sessions (KMSI answered "No"/unanswered) —
    // never longer than the persistent cap.
    transientMaxHours: Math.min(clampHours(transient, 24, 8760), maxHours),
  };
}
export const hoursAgo = (hours: number) => new Date(Date.now() - hours * 60 * 60 * 1000);

// --- step-up sudo window (tiered) ---
// Every session records BOTH the timestamp (stepup_at) and the METHOD
// (stepup_method) of its last verification, so a scenario can demand a tier —
// org/settings accept strong factors only; the factor pages fall back to
// email/password. Strength order: passkey > totp > email > password. Validity
// is admin-configurable (minutes).
export type StepupMethod = 'passkey' | 'totp' | 'email' | 'password';

export const isStrongAmr = (amr: string[]) => amr.includes('otp') || amr.includes('passkey');

// The HIGHEST-strength factor an amr proves — the method the session is born with.
// 'otp' is TOTP; 'email' only appears when the user passed an email challenge
// (which only happens with the MFA toggle on), so it never over-credits.
export function methodFromAmr(amr: string[]): StepupMethod {
  if (amr.includes('passkey')) return 'passkey';
  if (amr.includes('otp')) return 'totp';
  if (amr.includes('email')) return 'email';
  return 'password';
}

export async function getStepupValidityMinutes(): Promise<number> {
  const n = parseInt((await getSetting('stepup_validity_minutes')) ?? '', 10);
  return Number.isFinite(n) && n >= 1 && n <= 1440 ? n : 30;
}

// Stamp a fresh sudo window on `sid`, recording WHICH method was proven. Gates
// compare both the age AND the method against the scenario's accepted set.
export async function stampStepup(sid: string, method: StepupMethod): Promise<void> {
  await pool.query('UPDATE sessions SET stepup_at = now(), stepup_method = $2 WHERE sid = $1', [sid, method]);
}

// null stamp -> not verified; otherwise fresh iff younger than the window.
export async function isStepupFresh(stepupAt: number | null): Promise<boolean> {
  if (!stepupAt) return false;
  const minutes = await getStepupValidityMinutes();
  return Date.now() / 1000 - stepupAt < minutes * 60;
}

export interface NewSession {
  userSub: string;
  amr: string[];
  acr?: string;
  ip?: string;
  userAgent?: string;
  country?: string; // cf-ipcountry at login (null/absent -> Unknown)
}

// Create an SSO master session: a server-side row keyed by sha-256 of the cookie
// secret. The opaque token goes to the browser as an httpOnly/Secure/SameSite=Lax
// cookie. `sid` is the public session id that travels in tokens / back-channel logout.
// Sessions are born TRANSIENT: a browser-session cookie (no Expires — dies with
// the browser) and the short transient absolute window. Answering "Stay signed
// in? Yes" upgrades via persistSession(). Pre-clearance: EVERY login seeds a
// fresh sudo stamp recording the method it proved (methodFromAmr) — even a
// password-only login is a `password` step-up. Scenarios that demand a stronger
// tier (org/settings need passkey/totp) re-challenge on the method check.
export async function createSession(res: Response, s: NewSession): Promise<{ sid: string }> {
  const token = crypto.randomBytes(32).toString('base64url');
  const { transientMaxHours } = await getSessionWindows();
  const expires = new Date(Date.now() + transientMaxHours * 60 * 60 * 1000); // expires_at is vestigial; windows are dynamic
  const { rows } = await pool.query(
    `INSERT INTO sessions (user_sub, token_hash, amr, acr, auth_time, ip, user_agent, country, expires_at, stepup_at, stepup_method)
     VALUES ($1, $2, $3, $4, now(), $5, $6, $7, $8, now(), $9)
     RETURNING sid`,
    [s.userSub, sha256(token), s.amr, s.acr ?? null, s.ip ?? null, s.userAgent ?? null, s.country ?? null, expires,
     methodFromAmr(s.amr)],
  );
  res.cookie(SESSION_COOKIE, token, {
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    path: '/',
    // no expires/maxAge -> browser-session cookie
  });
  return { sid: rows[0].sid };
}

// KMSI "Yes": mark the session persistent and replace the cookie with an
// expiring one (full absolute window). The UPDATE is bound to BOTH the sid and
// the caller's cookie hash — a txn can never persist a session it doesn't hold.
export async function persistSession(req: Request, res: Response, sid: string): Promise<boolean> {
  const token = req.cookies?.[SESSION_COOKIE];
  if (!token) return false;
  const { maxHours } = await getSessionWindows();
  const expires = new Date(Date.now() + maxHours * 60 * 60 * 1000);
  const { rowCount } = await pool.query(
    `UPDATE sessions SET persistent = true, expires_at = $3 WHERE sid = $1 AND token_hash = $2`,
    [sid, sha256(token), expires],
  );
  if (!rowCount) return false;
  res.cookie(SESSION_COOKIE, token, {
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    path: '/',
    expires,
  });
  return true;
}

export interface ActiveSession {
  sid: string;
  userSub: string;
  amr: string[];
  acr?: string;
  authTime: number; // epoch seconds — the ORIGINAL authentication time
  stepupAt: number | null; // epoch seconds — last verification (sudo window)
  stepupMethod: string | null; // method of that verification: passkey|totp|email|password
  persistent: boolean; // KMSI answer — picks which absolute window applies
  createdAt: number; // epoch seconds — anchors the absolute window
}

// last_seen write-coalescing (videosite's dirty-set/flusher idea, sized for a
// single native process): skip the UPDATE when this process touched the sid
// recently. Granularity trade-off is display-only (Devices pane "last seen").
const TOUCH_INTERVAL_MS = 60_000;
const lastTouched = new Map<string, number>();
function touchSession(sid: string): void {
  const now = Date.now();
  const prev = lastTouched.get(sid);
  if (prev && now - prev < TOUCH_INTERVAL_MS) return;
  lastTouched.set(sid, now);
  if (lastTouched.size > 10_000) lastTouched.clear(); // crude bound; repopulates on next touches
  pool.query('UPDATE sessions SET last_seen = now() WHERE sid = $1', [sid]).catch(() => {});
}

// Validate the sso_session cookie against the live master session: idle + absolute
// windows (settings-driven) AND the identity still active. Used by /authorize to
// reuse a session instead of re-prompting. Revocation = row delete.
export async function loadSession(req: Request): Promise<ActiveSession | null> {
  const token = req.cookies?.[SESSION_COOKIE];
  if (!token) return null;
  const { idleHours, maxHours, transientMaxHours } = await getSessionWindows();
  // The absolute window is per-row: persistent sessions get the full cap,
  // transient ones the short cap.
  const { rows } = await pool.query(
    `SELECT s.sid, s.user_sub, s.amr, s.acr, s.persistent,
            EXTRACT(EPOCH FROM s.auth_time)::bigint AS auth_time,
            EXTRACT(EPOCH FROM s.stepup_at)::bigint AS stepup_at, s.stepup_method,
            EXTRACT(EPOCH FROM s.created_at)::bigint AS created_at
       FROM sessions s JOIN identities i ON i.sub = s.user_sub
      WHERE s.token_hash = $1 AND s.last_seen > $2
        AND s.created_at > (CASE WHEN s.persistent THEN $3::timestamptz ELSE $4::timestamptz END)
        AND i.status = 'active' AND i.deleted_at IS NULL`,
    [sha256(token), hoursAgo(idleHours), hoursAgo(maxHours), hoursAgo(transientMaxHours)],
  );
  if (!rows[0]) return null;
  touchSession(rows[0].sid);
  return {
    sid: rows[0].sid,
    userSub: rows[0].user_sub,
    amr: rows[0].amr,
    acr: rows[0].acr ?? undefined,
    authTime: Number(rows[0].auth_time),
    stepupAt: rows[0].stepup_at != null ? Number(rows[0].stepup_at) : null,
    stepupMethod: rows[0].stepup_method ?? null,
    persistent: rows[0].persistent,
    createdAt: Number(rows[0].created_at),
  };
}

// Same liveness rules as loadSession, but keyed by sid instead of the cookie
// token — for the account portal's S2S access-token renewal (the BFF holds the
// sid from the id_token; the cookie token never leaves the browser<->SSO leg).
export async function loadSessionBySid(sid: string): Promise<ActiveSession | null> {
  const { idleHours, maxHours, transientMaxHours } = await getSessionWindows();
  const { rows } = await pool.query(
    `SELECT s.sid, s.user_sub, s.amr, s.acr, s.persistent,
            EXTRACT(EPOCH FROM s.auth_time)::bigint AS auth_time,
            EXTRACT(EPOCH FROM s.stepup_at)::bigint AS stepup_at, s.stepup_method,
            EXTRACT(EPOCH FROM s.created_at)::bigint AS created_at
       FROM sessions s JOIN identities i ON i.sub = s.user_sub
      WHERE s.sid = $1 AND s.last_seen > $2
        AND s.created_at > (CASE WHEN s.persistent THEN $3::timestamptz ELSE $4::timestamptz END)
        AND i.status = 'active' AND i.deleted_at IS NULL`,
    [sid, hoursAgo(idleHours), hoursAgo(maxHours), hoursAgo(transientMaxHours)],
  );
  if (!rows[0]) return null;
  touchSession(rows[0].sid);
  return {
    sid: rows[0].sid,
    userSub: rows[0].user_sub,
    amr: rows[0].amr,
    acr: rows[0].acr ?? undefined,
    authTime: Number(rows[0].auth_time),
    stepupAt: rows[0].stepup_at != null ? Number(rows[0].stepup_at) : null,
    stepupMethod: rows[0].stepup_method ?? null,
    persistent: rows[0].persistent,
    createdAt: Number(rows[0].created_at),
  };
}

// DB backstop (videosite's cleanExpiredSessions): prune rows past either window
// so the table and the Devices pane stay clean. Called hourly from server.ts.
export async function cleanExpiredSessions(): Promise<void> {
  try {
    const { idleHours, maxHours, transientMaxHours } = await getSessionWindows();
    await pool.query(
      `DELETE FROM sessions
        WHERE last_seen < $1
           OR created_at < (CASE WHEN persistent THEN $2::timestamptz ELSE $3::timestamptz END)`,
      [hoursAgo(idleHours), hoursAgo(maxHours), hoursAgo(transientMaxHours)],
    );
  } catch (e) {
    console.error('cleanExpiredSessions failed:', (e as Error).message);
  }
}
