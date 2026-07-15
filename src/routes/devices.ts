import { Router } from 'express';
import { pool } from '../db.js';
import { config } from '../config.js';
import { requireScope, type AuthedRequest } from '../resourceAuth.js';
import { requirePerm } from '../rbac/index.js';
import { fanOutLogout } from '../oidc/backchannel.js';
import { getSessionWindows, hoursAgo } from '../oidc/sessions.js';
import { parseDevice } from '../deviceName.js';

// The Devices pane's resource API — lists the caller's live SSO master sessions
// (one per browser) and terminates them. Access-token protected; the BFF proxies
// these and marks the current session (the SSO can't know the caller's own sid,
// since the access token carries no `sid` claim — that's the BFF's job).
export const devicesRouter = Router();
const scoped = requireScope('profile');

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

interface SessionRow {
  sid: string;
  user_agent: string | null;
  country: string | null;
  auth_time: Date;
  last_seen: Date;
  clients: string[];
}

// GET /account/sessions — the caller's active sessions, newest-active first.
devicesRouter.get('/account/sessions', scoped, requirePerm('profile.security.sessions.view'), async (req: AuthedRequest, res) => {
  const sub = req.auth!.sub;
  // Same idle + per-row absolute windows as loadSession — the pane never lists a
  // session that /authorize would reject.
  const { idleHours, maxHours, transientMaxHours } = await getSessionWindows();
  const { rows } = await pool.query<SessionRow>(
    `SELECT sid, user_agent, country, auth_time, last_seen, clients
       FROM sessions
      WHERE user_sub = $1 AND last_seen > $2
        AND created_at > (CASE WHEN persistent THEN $3::timestamptz ELSE $4::timestamptz END)
      ORDER BY last_seen DESC`,
    [sub, hoursAgo(idleHours), hoursAgo(maxHours), hoursAgo(transientMaxHours)],
  );

  // Resolve client_id -> display name once for all sessions (avoid N+1).
  const allClients = [...new Set(rows.flatMap((r) => r.clients))];
  const nameMap = new Map<string, string>();
  if (allClients.length) {
    const { rows: cs } = await pool.query<{ client_id: string; name: string }>(
      `SELECT client_id, name FROM oauth_clients WHERE client_id = ANY($1)`,
      [allClients],
    );
    for (const c of cs) nameMap.set(c.client_id, c.name);
  }

  const sessions = rows.map((r) => {
    const d = parseDevice(r.user_agent);
    return {
      sid: r.sid,
      device_name: d.name,
      device_type: d.type,
      country: r.country, // raw code; the SPA formats (Intl.DisplayNames, T1 -> Tor, null -> Unknown)
      first_signin: r.auth_time,
      last_seen: r.last_seen,
      // The account console itself is hidden — it's the portal, not a service the
      // user "accessed" (still kept in clients[] for back-channel logout).
      apps: r.clients
        .filter((id) => id !== config.accountClientId)
        .map((id) => ({ client_id: id, name: nameMap.get(id) ?? id })),
    };
  });
  res.json({ sessions });
});

// DELETE /account/sessions/:sid — terminate one of the caller's sessions. The row
// is deleted and we fan out back-channel logout to the apps it touched. (The BFF
// refuses to call this for the caller's own current session — that's logout.)
devicesRouter.delete('/account/sessions/:sid', scoped, requirePerm('profile.security.sessions.terminate'), async (req: AuthedRequest, res) => {
  const sub = req.auth!.sub;
  const sid = String(req.params.sid);
  if (!UUID_RE.test(sid)) return res.status(404).json({ error: 'not_found' });
  // Ownership is enforced in the WHERE clause (user_sub = caller) — a foreign sid
  // returns no row, indistinguishable from a missing one.
  const { rows } = await pool.query<{ clients: string[] }>(
    `DELETE FROM sessions WHERE sid = $1 AND user_sub = $2 RETURNING clients`,
    [sid, sub],
  );
  if (!rows[0]) return res.status(404).json({ error: 'not_found' });
  await fanOutLogout(sub, sid, rows[0].clients ?? []);
  res.status(204).end();
});

// POST /account/sessions/terminate-others { keep_sid } — sign out everywhere except
// one session (the caller's current one, supplied by the BFF as session.ssoSid).
devicesRouter.post('/account/sessions/terminate-others', scoped, requirePerm('profile.security.sessions.terminate'), async (req: AuthedRequest, res) => {
  const sub = req.auth!.sub;
  const keep = String((req.body ?? {}).keep_sid ?? '');
  if (!UUID_RE.test(keep)) return res.status(400).json({ error: 'invalid_keep_sid' });
  const { rows } = await pool.query<{ sid: string; clients: string[] }>(
    `DELETE FROM sessions WHERE user_sub = $1 AND sid <> $2 RETURNING sid, clients`,
    [sub, keep],
  );
  await Promise.allSettled(rows.map((r) => fanOutLogout(sub, r.sid, r.clients ?? [])));
  res.status(204).end();
});
