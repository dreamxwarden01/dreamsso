import { Router, type Request, type Response } from 'express';
import crypto from 'node:crypto';
import { SignJWT } from 'jose';
import { pool } from '../db.js';
import { config } from '../config.js';
import { getSigningKey } from '../keys.js';
import { assertedClient } from '../oidc/clientAssertion.js';
import { getSessionWindows, hoursAgo } from '../oidc/sessions.js';

// RP activity reporting.
//
//   POST /internal/session-activity   { client_assertion*, sid, last_seen? }
//
// Why this exists: the SSO's IDLE window is measured against sessions.last_seen,
// which only moved when the SSO ITSELF was hit (/authorize, portal S2S renewal).
// An RP could be in continuous use for days while the master session sat
// untouched and idled out from under it — and because every revocation path is
// sid-scoped over the row's `clients`, once the row was swept the RP session
// became unreachable by "sign out everywhere" or an admin terminate. RPs now
// report activity here (coalesced, ~5 min), so the idle window is genuinely
// shared rather than SSO-traffic-only.
//
// Two outcomes, and the asymmetry is deliberate:
//   204  accepted — last_seen advanced.
//   410  gone — this session is no longer valid; the RP must terminate its own.
//        The verdict is SIGNED because it triggers a destructive action: a bare
//        status line is injectable by anything in the path (proxy, WAF, captive
//        portal), and a forged 410 would log users out en masse. The RP verifies
//        the JWT before acting and treats every other outcome (401/404/5xx/HTML/
//        timeout) as "unknown — do nothing, retry later". Fail-open on ambiguity:
//        a session living a few extra minutes beats a fleet-wide logout caused by
//        a transport hiccup.
export const sessionActivityRouter = Router();

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// Signed "this session is gone" verdict, addressed to the reporting client.
// Same iss/aud/freshness contract as the outbound event envelope, so the RP
// verifies it with the machinery it already has.
async function signVerdict(clientId: string, sid: string): Promise<string> {
  const { kid, privateKey } = await getSigningKey();
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({ status: 'invalid', sid })
    .setProtectedHeader({ alg: 'EdDSA', kid, typ: 'verdict+jwt' })
    .setIssuer(config.issuer)
    .setAudience(clientId)
    .setIssuedAt(now)
    .setExpirationTime(now + 120)
    .setJti(crypto.randomUUID())
    .sign(privateKey);
}

sessionActivityRouter.post('/internal/session-activity', async (req: Request, res: Response) => {
  const body = (req.body ?? {}) as Record<string, unknown>;
  const clientId = await assertedClient(body);
  if (!clientId) return res.status(401).json({ error: 'invalid_client' });

  const sid = String(body.sid ?? '');
  if (!UUID_RE.test(sid)) return res.status(400).json({ error: 'invalid_sid' });

  // Reported activity timestamp (epoch ms). Clamped to now() below — a skewed or
  // hostile RP must not be able to push last_seen into the future and hold the
  // session open past the idle window indefinitely.
  const reported = Number(body.last_seen);
  const lastSeenSec = Number.isFinite(reported) && reported > 0 ? reported / 1000 : null;

  const { idleHours, maxHours, transientMaxHours } = await getSessionWindows();
  // One statement does authz + liveness + the bump. `$2 = ANY(clients)` scopes
  // the report to sessions this client actually participated in (clients[] is
  // appended at token exchange), so one RP can't keep another's session alive.
  // Liveness mirrors loadSession exactly: idle + per-row absolute + identity active.
  // GREATEST(...) never moves last_seen backwards on a late/out-of-order report.
  const { rows } = await pool.query(
    `UPDATE sessions s
        SET last_seen = GREATEST(s.last_seen, LEAST(to_timestamp($3), now()))
       FROM identities i
      WHERE i.sub = s.user_sub
        AND s.sid = $1
        AND $2::text = ANY(s.clients)
        AND s.last_seen > $4
        AND s.created_at > (CASE WHEN s.persistent THEN $5::timestamptz ELSE $6::timestamptz END)
        AND i.status = 'active' AND i.deleted_at IS NULL
      RETURNING s.sid`,
    [
      sid,
      clientId,
      lastSeenSec ?? Math.floor(Date.now() / 1000),
      hoursAgo(idleHours),
      hoursAgo(maxHours),
      hoursAgo(transientMaxHours),
    ],
  );

  if (!rows[0]) {
    res.status(410).json({ error: 'session_invalid', verdict: await signVerdict(clientId, sid) });
    return;
  }
  res.status(204).end();
});
