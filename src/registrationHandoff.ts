import crypto from 'node:crypto';
import { redis } from './redis.js';

// A completed welcome hop may be requested again by the same browser. This
// receipt never authenticates anyone: the caller must already hold the exact
// live SSO session created by the first, single-use ticket redemption.
const RECEIPT_SECONDS = 60;
const TICKET_RE = /^[A-Za-z0-9_-]{43}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
interface HandoffReceipt { sid: string; sub: string; expiresAt: number }
const key = (ticket: string): string =>
  `reg:handoff:${crypto.createHash('sha256').update(ticket).digest('hex')}`;

export async function rememberRegistrationHandoff(ticket: string, session: { sid: string; sub: string }): Promise<void> {
  if (!TICKET_RE.test(ticket) || !UUID_RE.test(session.sid) || !UUID_RE.test(session.sub)) throw new Error('invalid_handoff_receipt');
  const receipt: HandoffReceipt = { sid: session.sid, sub: session.sub, expiresAt: Date.now() + RECEIPT_SECONDS * 1000 };
  // NX prevents an accidental second write from moving the recovery deadline.
  await redis.set(key(ticket), JSON.stringify(receipt), 'EX', RECEIPT_SECONDS, 'NX');
}

export async function readRegistrationHandoff(ticket: string): Promise<HandoffReceipt | null> {
  if (!TICKET_RE.test(ticket)) return null;
  const raw = await redis.get(key(ticket));
  if (!raw) return null;
  try {
    const value = JSON.parse(raw) as HandoffReceipt;
    if (!value || typeof value.sid !== 'string' || typeof value.sub !== 'string' ||
        !UUID_RE.test(value.sid) || !UUID_RE.test(value.sub) ||
        !Number.isSafeInteger(value.expiresAt) || value.expiresAt <= Date.now() ||
        value.expiresAt > Date.now() + RECEIPT_SECONDS * 1000) return null;
    return { sid: value.sid, sub: value.sub, expiresAt: value.expiresAt };
  } catch { return null; }
}
