import { Router, type Request, type Response } from 'express';
import { jwtVerify } from 'jose';
import { pool } from '../db.js';
import { config } from '../config.js';
import { clientKeySet } from './token.js';
import { effectiveAppRole } from '../rbac/appRoles.js';
import { enqueueEvents } from '../events.js';
import { audit } from '../audit.js';

// Inbound event channel (RP -> SSO): POST /backchannel/events, the mirror of
// what the SSO sends outbound. Envelope = a JWT signed with the RP's
// REGISTERED client key (same trust as private_key_jwt at /token; key fetched
// via jwks_uri automatically), claims {iss=client_id, aud=issuer, iat, jti,
// events: [{id, type, payload}...]}. At-least-once safe: per-event dedupe by
// id (processed_events), full-state semantics, and an envelope-iat guard so a
// delayed retry can never regress a newer sync. Unknown event types are
// ACKNOWLEDGED (logged) — adding types never wedges an older peer.
export const eventsRouter = Router();

const MAX_EVENTS = 100;
const MAX_ROLES = 500;

interface InboundEvent {
  id?: unknown;
  type?: unknown;
  payload?: unknown;
}

eventsRouter.post('/backchannel/events', async (req: Request, res: Response) => {
  const token = (req.body ?? {}).event_token;
  if (typeof token !== 'string' || token.length > 262_144) {
    return res.status(400).json({ error: 'missing_event_token' });
  }
  let iss: string;
  try {
    iss = String(JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString()).iss);
  } catch {
    return res.status(400).json({ error: 'malformed_token' });
  }
  const { rows: [client] } = await pool.query(
    'SELECT client_id, jwks, jwks_uri, disabled_at FROM oauth_clients WHERE client_id = $1',
    [iss],
  );
  if (!client || client.disabled_at) return res.status(401).json({ error: 'unknown_client' });
  const keySet = clientKeySet(client);
  if (!keySet) return res.status(401).json({ error: 'no_registered_key' });

  let payload;
  try {
    ({ payload } = await jwtVerify(token, keySet, {
      issuer: client.client_id,
      audience: config.issuer,
      clockTolerance: 10,
      maxTokenAge: '5 minutes',
    }));
  } catch {
    return res.status(401).json({ error: 'invalid_token' });
  }

  const events = payload.events;
  if (!Array.isArray(events) || events.length === 0 || events.length > MAX_EVENTS) {
    return res.status(400).json({ error: 'invalid_events' });
  }

  for (const raw of events as InboundEvent[]) {
    const id = typeof raw.id === 'string' && /^[0-9a-f]{8}-[0-9a-f-]{27}$/i.test(raw.id) ? raw.id : null;
    const type = typeof raw.type === 'string' ? raw.type : '';
    if (!id) return res.status(400).json({ error: 'invalid_event_id' });

    // Dedupe: the INSERT claims the id; a conflict means we already processed it.
    const { rowCount } = await pool.query(
      `INSERT INTO processed_events (id, source) VALUES ($1, $2) ON CONFLICT (id) DO NOTHING`,
      [id, client.client_id],
    );
    if (!rowCount) continue;

    try {
      if (type === 'roles.sync') {
        await applyRolesSync(client.client_id, Number(payload.iat ?? 0), raw.payload);
      } else {
        console.log(`events: acked unknown type '${type}' from ${client.client_id}`);
      }
    } catch (e) {
      console.warn(`events: ${type} from ${client.client_id} failed:`, (e as Error).message);
      // Give the id back so the sender's retry can reprocess.
      await pool.query('DELETE FROM processed_events WHERE id = $1', [id]).catch(() => { /* best effort */ });
      return res.status(e instanceof PayloadError ? 400 : 500).json({ error: e instanceof PayloadError ? e.message : 'processing_failed' });
    }
  }
  res.status(204).end();
});

class PayloadError extends Error {}

// roles.sync — full-state replacement of the client's role catalog.
// default_role is SINGULAR (catalog-level), validated against the sent list;
// invalid/absent -> stored NULL (deny-safe; surfaced in admin).
async function applyRolesSync(clientId: string, envelopeIat: number, payload: unknown): Promise<void> {
  const p = (payload ?? {}) as { roles?: unknown; default_role?: unknown; site_name?: unknown };
  if (!Array.isArray(p.roles) || p.roles.length > MAX_ROLES) throw new PayloadError('invalid_roles');
  const roles = p.roles.map((r) => {
    const x = (r ?? {}) as Record<string, unknown>;
    const roleId = Number(x.role_id);
    const level = Number(x.level);
    if (!Number.isInteger(roleId) || !Number.isInteger(level) || typeof x.name !== 'string' || !x.name.trim()) {
      throw new PayloadError('invalid_role_row');
    }
    return { role_id: roleId, name: x.name.trim().slice(0, 100), level, is_system: x.is_system === true };
  });
  const def = Number(p.default_role);
  const defaultRole = Number.isInteger(def) && roles.some((r) => r.role_id === def) ? def : null;

  const c = await pool.connect();
  const affected: string[] = [];
  try {
    await c.query('BEGIN');
    // Ordering guard: a delayed retry must never regress a newer sync.
    const { rows: [cat] } = await c.query(
      'SELECT last_sync_iat FROM app_role_catalogs WHERE client_id = $1 FOR UPDATE',
      [clientId],
    );
    if (cat && Number(cat.last_sync_iat) >= envelopeIat) {
      await c.query('ROLLBACK');
      return;
    }

    // Reconciliation: SSO-held assignments referencing a role the app just
    // removed. Rule (user-specified, deny-safe): removed role OUTRANKED the
    // new default (strictly smaller level) -> move to the default; otherwise
    // (or no valid default) -> No access. A deletion can never upgrade anyone.
    const { rows: oldRoles } = await c.query<{ role_id: number; level: number }>(
      'SELECT role_id, level FROM app_roles WHERE client_id = $1', [clientId]);
    const topOf = (list: { role_id: number; level: number }[]) =>
      list.length ? list.reduce((a, b) => (b.level < a.level || (b.level === a.level && b.role_id < a.role_id) ? b : a)).role_id : null;
    const newIds = new Set(roles.map((r) => r.role_id));
    const removed = oldRoles.filter((r) => !newIds.has(r.role_id));
    if (removed.length) {
      const defLevel = defaultRole != null ? roles.find((r) => r.role_id === defaultRole)!.level : null;
      for (const rem of removed) {
        const moveTo = defaultRole != null && defLevel != null && rem.level < defLevel ? defaultRole : null;
        const { rows: ovs } = await c.query<{ user_sub: string }>(
          `UPDATE user_app_role_overrides SET app_role_id = $3, updated_at = now()
            WHERE client_id = $1 AND app_role_id = $2 RETURNING user_sub`,
          [clientId, rem.role_id, moveTo]);
        affected.push(...ovs.map((x) => x.user_sub));
        const { rows: ods } = await c.query<{ role_slug: string }>(
          `UPDATE org_role_app_defaults SET app_role_id = $3, updated_at = now()
            WHERE client_id = $1 AND app_role_id = $2 RETURNING role_slug`,
          [clientId, rem.role_id, moveTo]);
        if (ods.length) {
          const { rows: members } = await c.query<{ user_sub: string }>(
            `SELECT ur.user_sub FROM user_org_roles ur
              WHERE ur.org_role_slug = ANY($1)
                AND NOT EXISTS (SELECT 1 FROM user_app_role_overrides o
                                 WHERE o.user_sub = ur.user_sub AND o.client_id = $2)`,
            [ods.map((x) => x.role_slug), clientId]);
          affected.push(...members.map((x) => x.user_sub));
        }
      }
    }

    for (const r of roles) {
      await c.query(
        `INSERT INTO app_roles (client_id, role_id, name, level, is_system, updated_at)
           VALUES ($1, $2, $3, $4, $5, now())
         ON CONFLICT (client_id, role_id) DO UPDATE
           SET name = EXCLUDED.name, level = EXCLUDED.level, is_system = EXCLUDED.is_system, updated_at = now()`,
        [clientId, r.role_id, r.name, r.level, r.is_system],
      );
    }
    await c.query(
      `DELETE FROM app_roles WHERE client_id = $1 AND NOT (role_id = ANY($2::int[]))`,
      [clientId, roles.map((r) => r.role_id)],
    );
    await c.query(
      `INSERT INTO app_role_catalogs (client_id, default_role_id, synced_at, last_sync_iat)
         VALUES ($1, $2, now(), $3)
       ON CONFLICT (client_id) DO UPDATE
         SET default_role_id = $2, synced_at = now(), last_sync_iat = $3`,
      [clientId, defaultRole, envelopeIat],
    );

    // The app is the source of truth for its own display name: a site_name in
    // the report updates the client registry (login page, org Apps pane).
    const appName = typeof p.site_name === 'string' && p.site_name.trim()
      ? p.site_name.trim().slice(0, 100) : null;
    if (appName) {
      await c.query(
        'UPDATE oauth_clients SET name = $2 WHERE client_id = $1 AND name IS DISTINCT FROM $2',
        [clientId, appName],
      );
    }
    // Root guarantee (user design): every report re-points level-0 org roles'
    // app default at the catalog's TOP role — a new app grants it on the
    // first fetch, a moved top follows automatically, and everything
    // downstream (guards, permissions, display, login claim) rides the
    // ordinary chain. Runs LAST so it wins over the removed-role updates.
    // The push signal is the stored VALUE changing (row missing counts) —
    // not the catalog top moving — so the first write over an already-known
    // catalog still notifies members without personal overrides.
    const rootTop = topOf(roles);
    if (rootTop != null) {
      const { rows: changedRoots } = await c.query<{ slug: string }>(
        `SELECT r.slug FROM org_roles r
           LEFT JOIN org_role_app_defaults d ON d.role_slug = r.slug AND d.client_id = $1
          WHERE r.level = 0 AND (d.role_slug IS NULL OR d.app_role_id IS DISTINCT FROM $2)`,
        [clientId, rootTop],
      );
      if (changedRoots.length) {
        const { rows: members } = await c.query<{ user_sub: string }>(
          `SELECT ur.user_sub FROM user_org_roles ur
            WHERE ur.org_role_slug = ANY($1)
              AND NOT EXISTS (SELECT 1 FROM user_app_role_overrides o
                               WHERE o.user_sub = ur.user_sub AND o.client_id = $2)`,
          [changedRoots.map((x) => x.slug), clientId],
        );
        affected.push(...members.map((x) => x.user_sub));
      }
      await c.query(
        `INSERT INTO org_role_app_defaults (role_slug, client_id, app_role_id, updated_at)
           SELECT slug, $1, $2, now() FROM org_roles WHERE level = 0
         ON CONFLICT (role_slug, client_id) DO UPDATE SET app_role_id = $2, updated_at = now()`,
        [clientId, rootTop],
      );
    }
    await c.query('COMMIT');
  } catch (e) {
    await c.query('ROLLBACK');
    throw e;
  } finally {
    c.release();
  }

  // Post-commit: tell the app about every reconciled user's NEW effective
  // role (rides the same channel back), and leave a system audit row.
  const uniq = [...new Set(affected)];
  if (uniq.length) {
    for (const sub of uniq) {
      const eff = await effectiveAppRole(sub, clientId);
      await enqueueEvents(clientId, [{ type: 'account.roles_change', payload: { sub, role_id: eff.role_id } }]);
    }
    audit({
      actorSub: undefined, actorLabel: 'system (roles.sync)',
      action: 'roles.reconcile', detail: { client: clientId, affected: uniq.length },
    });
  }
}
