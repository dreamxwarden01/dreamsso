import { createHash } from 'node:crypto';
import type pg from 'pg';

export const MAX_EVENTS = 100;
export const MAX_ROLES = 500;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const MAX_REVISION = 9223372036854775807n;
const int32 = (value: unknown): value is number => typeof value === 'number'
  && Number.isInteger(value) && value >= -2147483648 && value <= 2147483647;
const object = (value: unknown): value is Record<string, unknown> => !!value && typeof value === 'object' && !Array.isArray(value);
const validText = (value: string): boolean => !value.includes('\0')
  && [...value].every(character => { const point = character.codePointAt(0)!;return point < 0xd800 || point > 0xdfff; });
const trimName = (value: string): string => [...value.trim()].slice(0, 100).join('');

export class EventError extends Error {
  constructor(readonly code: string, readonly status: 400 | 401 | 409 = 400) { super(code); }
}
export interface CatalogRole { role_id: number; name: string; level: number; is_system: boolean }
export interface RoleCatalog {
  roles: CatalogRole[];
  default_role: number | null;
  site_name: string | null;
  catalog_epoch?: string;
  catalog_revision?: string;
}
export interface IncomingEvent { id: string; type: string; payload: unknown; catalog?: RoleCatalog }
export interface CatalogSyncState {
  catalog_mode: 'legacy' | 'revisioned';
  catalog_epoch: string | null;
  catalog_revision: string | null;
  catalog_digest: Buffer | null;
  last_sync_iat: string | number;
}
export interface CatalogDependencies {
  ensureRoleSyncState(db: pg.PoolClient, clientId: string): Promise<CatalogSyncState>;
  publishRoleChanges(db: pg.PoolClient, clientIds: string[], subjects?: readonly string[] | null,
    options?: { force?: boolean; forceSubjects?: readonly string[] }): Promise<number>;
}
export interface EnvelopeTime { iat: number; exp: number }

/** A catalog is typed JSON: null, booleans and numeric strings are never numbers. */
export function normalizeRoleCatalog(payload: unknown): RoleCatalog {
  if (!object(payload) || !Array.isArray(payload.roles) || payload.roles.length > MAX_ROLES) throw new EventError('invalid_roles');
  const ids = new Set<number>();
  const roles = payload.roles.map(value => {
    if (!object(value) || !int32(value.role_id) || !int32(value.level)
      || typeof value.name !== 'string' || !value.name.trim() || !validText(value.name)
      || (value.is_system !== undefined && typeof value.is_system !== 'boolean')) throw new EventError('invalid_role_row');
    if (ids.has(value.role_id)) throw new EventError('duplicate_role_id');
    ids.add(value.role_id);
    return { role_id: value.role_id, level: value.level, name: trimName(value.name), is_system: value.is_system === true };
  }).sort((a, b) => a.role_id - b.role_id);
  if (typeof payload.site_name === 'string' && !validText(payload.site_name)) throw new EventError('invalid_site_name');
  if (Object.hasOwn(payload, 'default_role') && payload.default_role !== null && !int32(payload.default_role)) {
    throw new EventError('invalid_default_role');
  }
  const result: RoleCatalog = { roles,
    default_role: int32(payload.default_role) && ids.has(payload.default_role) ? payload.default_role : null,
    site_name: typeof payload.site_name === 'string' && payload.site_name.trim() ? trimName(payload.site_name) : null };
  const epochPresent = Object.hasOwn(payload, 'catalog_epoch'), revisionPresent = Object.hasOwn(payload, 'catalog_revision');
  if (epochPresent !== revisionPresent) throw new EventError('invalid_catalog_version');
  if (epochPresent) {
    if (typeof payload.catalog_epoch !== 'string' || !UUID.test(payload.catalog_epoch)
      || typeof payload.catalog_revision !== 'string' || !/^[1-9][0-9]{0,18}$/.test(payload.catalog_revision)
      || BigInt(payload.catalog_revision) > MAX_REVISION) throw new EventError('invalid_catalog_version');
    result.catalog_epoch = payload.catalog_epoch.toLowerCase();result.catalog_revision = payload.catalog_revision;
  }
  return result;
}

export function canonicalJson(value: unknown, depth = 0): string {
  if (depth > 64) throw new EventError('invalid_event_payload');
  if (Array.isArray(value)) return '[' + value.map(child => canonicalJson(child, depth + 1)).join(',') + ']';
  if (object(value)) return '{' + Object.keys(value).sort().map(key => JSON.stringify(key) + ':' + canonicalJson(value[key], depth + 1)).join(',') + '}';
  const serialized = JSON.stringify(value);
  if (serialized === undefined) throw new EventError('invalid_event_payload');
  return serialized;
}
const digest = (value: unknown): Buffer => createHash('sha256').update(canonicalJson(value)).digest();
/** State identity deliberately excludes the sender's epoch/revision. */
export function catalogDigest(catalog: RoleCatalog): Buffer {
  return digest({ roles: catalog.roles, default_role: catalog.default_role, site_name: catalog.site_name });
}
export function inboxDigest(event: IncomingEvent): Buffer {
  return digest({ type: event.type, payload: event.catalog ?? event.payload });
}

export function validateIncomingEvents(raw: unknown): IncomingEvent[] {
  if (!Array.isArray(raw) || raw.length === 0 || raw.length > MAX_EVENTS) throw new EventError('invalid_events');
  const events = raw.map(value => {
    if (!object(value) || typeof value.id !== 'string' || !UUID.test(value.id)) throw new EventError('invalid_event_id');
    if (typeof value.type !== 'string' || !value.type || value.type.length > 100) throw new EventError('invalid_event_type');
    const payload = value.payload ?? {};
    const event: IncomingEvent = { id: value.id.toLowerCase(), type: value.type, payload };
    if (event.type === 'roles.sync') event.catalog = normalizeRoleCatalog(value.payload);
    // Validate digestability before a transaction can mutate any event in this batch.
    inboxDigest(event);return event;
  });
  return events;
}

export function catalogOrder(state: CatalogSyncState, catalog: RoleCatalog, iat: number, hasCatalog: boolean): 'apply' | 'same' | 'stale' {
  const same = state.catalog_digest?.equals(catalogDigest(catalog)) === true;
  if (state.catalog_mode === 'revisioned') {
    if (!catalog.catalog_epoch) throw new EventError('catalog_revision_required', 409);
    if (catalog.catalog_epoch !== state.catalog_epoch) throw new EventError('catalog_epoch_conflict', 409);
    if (!state.catalog_revision) throw new Error('Missing stored catalog revision.');
    const incoming = BigInt(catalog.catalog_revision!), current = BigInt(state.catalog_revision);
    if (incoming < current) return 'stale';
    if (incoming === current) {
      if (!same) throw new EventError('catalog_revision_conflict', 409);
      return 'same';
    }
    return 'apply';
  }
  if (catalog.catalog_epoch || !hasCatalog) return 'apply';
  const previous = BigInt(state.last_sync_iat);
  if (BigInt(iat) < previous) return 'stale';
  if (BigInt(iat) === previous) {
    if (!same) throw new EventError('catalog_order_ambiguous', 409);
    return 'same';
  }
  return 'apply';
}

export function assertEnvelopeCurrent(time: EnvelopeTime, now = Date.now()): void {
  const seconds = Math.floor(now / 1000);
  if (!Number.isSafeInteger(time.iat) || !Number.isSafeInteger(time.exp) || time.iat < 0 || time.exp <= time.iat
    || time.iat > seconds + 10 || seconds - time.iat > 310 || time.exp <= seconds - 10) throw new EventError('invalid_token', 401);
}

/** The caller holds the shared role-writer transaction lock until this completes. */
export async function processIncomingEvents(db: pg.PoolClient, clientId: string, time: EnvelopeTime,
  events: readonly IncomingEvent[], deps: CatalogDependencies, now: () => number = Date.now): Promise<void> {
  assertEnvelopeCurrent(time, now());
  // Fence client disable/delete while remaining compatible with outbox FK KEY SHARE.
  const enabled = await db.query('SELECT 1 FROM oauth_clients WHERE client_id = $1 AND disabled_at IS NULL FOR NO KEY UPDATE', [clientId]);
  if (!enabled.rowCount) throw new EventError('unknown_client', 401);
  for (const event of events) {
    assertEnvelopeCurrent(time, now());
    const completeDigest = inboxDigest(event);
    const { rows: [prior] } = await db.query<{ event_type: string | null; payload_digest: Buffer | null }>(
      'SELECT event_type, payload_digest FROM processed_events WHERE source = $1 AND id = $2 FOR UPDATE', [clientId, event.id]);
    let state: CatalogSyncState | undefined;
    if (event.catalog) {
      state = await deps.ensureRoleSyncState(db, clientId);
      if (state.catalog_mode === 'revisioned') {
        if (!event.catalog.catalog_epoch) throw new EventError('catalog_revision_required', 409);
        if (event.catalog.catalog_epoch !== state.catalog_epoch) throw new EventError('catalog_epoch_conflict', 409);
      }
    }
    // A migration-seeded catalog still needs one current-state repair, even if
    // an earlier stale legacy envelope already populated its inbox digest.
    if (prior?.payload_digest?.equals(completeDigest) && !(event.catalog && state?.catalog_digest === null)) continue;
    // Pre-upgrade receipts bound only source/id, not content. They may contain a
    // revisioned report already accepted by an older SSO during a rolling upgrade.
    // Treat only BOTH-null metadata as unbound, and run full catalog ordering
    // before binding it. A stale historical report leaves the receipt unbound.
    const historicalUnknown = prior?.event_type === null && prior.payload_digest === null;
    const legacyMutable = event.catalog && !event.catalog.catalog_epoch
      && prior?.event_type === 'roles.sync' && prior.payload_digest !== null;
    if (prior && !historicalUnknown && !legacyMutable) throw new EventError('event_identity_conflict', 409);
    if (event.catalog) {
      const order = await applyCatalog(db, clientId, time.iat, event.catalog, state!, deps);
      if (historicalUnknown && order === 'stale') continue;
    }
    // Unknown event types are acknowledged, but their identity is still immutable.
    // Legacy roles.sync senders recomposed payloads under a stable ID: only those
    // may replace an inbox digest after passing the normal catalog ordering guard.
    await db.query(`INSERT INTO processed_events (source, id, event_type, payload_digest)
      VALUES ($1, $2, $3, $4) ON CONFLICT (source, id) DO UPDATE
      SET event_type = EXCLUDED.event_type, payload_digest = EXCLUDED.payload_digest, processed_at = now()`,
    [clientId, event.id, event.type, completeDigest]);
  }
  assertEnvelopeCurrent(time, now());
}

async function applyCatalog(db: pg.PoolClient, clientId: string, iat: number, catalog: RoleCatalog,
  state: CatalogSyncState, deps: CatalogDependencies): Promise<'apply' | 'same' | 'stale'> {
  const { rows: [existing] } = await db.query<{ default_role_id: number | null; name: string }>(
    `SELECT cat.default_role_id, client.name FROM app_role_catalogs cat
      JOIN oauth_clients client ON client.client_id = cat.client_id WHERE cat.client_id = $1`, [clientId]);
  // The migration baseline records SSO truth, not proof that every RP received
  // the old Redis-only notifications. Repair from current state exactly once
  // on initial reconciliation and once when a legacy sender adopts revisions.
  const forceCurrent = state.catalog_digest === null || (state.catalog_mode === 'legacy' && !!catalog.catalog_epoch);
  // A migration cannot know whether the last legacy report omitted site_name.
  // Compare its stored state using the incoming report's optional-name semantics.
  if (existing && !state.catalog_digest && state.catalog_mode === 'legacy') {
    const { rows } = await db.query<CatalogRole>('SELECT role_id, name, level, is_system FROM app_roles WHERE client_id = $1 ORDER BY role_id', [clientId]);
    state = { ...state, catalog_digest: catalogDigest({ roles: rows, default_role: existing.default_role_id,
      site_name: catalog.site_name === null ? null : existing.name }) };
  }
  const order = catalogOrder(state, catalog, iat, !!existing);
  if (order === 'stale' || (order === 'same' && !forceCurrent)) return order;
  const { rows: oldRoles } = await db.query<{ role_id: number; level: number }>(
    'SELECT role_id, level FROM app_roles WHERE client_id = $1', [clientId]);
  const newIds = new Set(catalog.roles.map(role => role.role_id));
  const defaultLevel = catalog.default_role === null ? null : catalog.roles.find(role => role.role_id === catalog.default_role)!.level;
  for (const removed of oldRoles.filter(role => !newIds.has(role.role_id))) {
    // Preserve the established deletion policy: move only to a less privileged
    // default; otherwise persist explicit denial at the original layer.
    const moveTo = defaultLevel !== null && removed.level < defaultLevel ? catalog.default_role : null;
    await db.query(`UPDATE user_app_role_overrides SET app_role_id = $3, updated_at = now()
      WHERE client_id = $1 AND app_role_id = $2`, [clientId, removed.role_id, moveTo]);
    await db.query(`UPDATE org_role_app_defaults SET app_role_id = $3, updated_at = now()
      WHERE client_id = $1 AND app_role_id = $2`, [clientId, removed.role_id, moveTo]);
  }
  for (const role of catalog.roles) {
    await db.query(`INSERT INTO app_roles (client_id, role_id, name, level, is_system, updated_at)
      VALUES ($1, $2, $3, $4, $5, now()) ON CONFLICT (client_id, role_id) DO UPDATE
      SET name = EXCLUDED.name, level = EXCLUDED.level, is_system = EXCLUDED.is_system, updated_at = now()`,
    [clientId, role.role_id, role.name, role.level, role.is_system]);
  }
  await db.query('DELETE FROM app_roles WHERE client_id = $1 AND NOT (role_id = ANY($2::int[]))', [clientId, [...newIds]]);
  await db.query(`INSERT INTO app_role_catalogs (client_id, default_role_id, synced_at, last_sync_iat)
    VALUES ($1, $2, now(), $3) ON CONFLICT (client_id) DO UPDATE
    SET default_role_id = EXCLUDED.default_role_id, synced_at = now(), last_sync_iat = EXCLUDED.last_sync_iat`, [clientId, catalog.default_role, iat]);
  await db.query(`UPDATE app_role_sync_state SET catalog_mode = $2, catalog_epoch = $3,
    catalog_revision = $4, catalog_digest = $5, last_sync_iat = $6 WHERE client_id = $1`,
  [clientId, catalog.catalog_epoch ? 'revisioned' : 'legacy', catalog.catalog_epoch ?? null,
    catalog.catalog_revision ?? null, catalogDigest(catalog), iat]);
  if (catalog.site_name !== null) {
    await db.query('UPDATE oauth_clients SET name = $2 WHERE client_id = $1 AND name IS DISTINCT FROM $2', [clientId, catalog.site_name]);
  }
  // Bootstrap exception remains ordinary stored org defaults. A personal NULL
  // override still wins; no resolution shortcut grants a denied user access.
  const top = catalog.roles.reduce<CatalogRole | null>((best, role) => !best || role.level < best.level
    || (role.level === best.level && role.role_id < best.role_id) ? role : best, null);
  let rootSubjects: string[] = [];
  if (top) {
    // A newly stored root default is also a bootstrap signal when the previous
    // catalog fallback happened to have the same value. Personal overrides win.
    const { rows } = await db.query<{ user_sub: string }>(`SELECT ur.user_sub FROM org_roles r
      JOIN user_org_roles ur ON ur.org_role_slug=r.slug
      LEFT JOIN org_role_app_defaults d ON d.role_slug=r.slug AND d.client_id=$1
      WHERE r.level=0 AND (d.role_slug IS NULL OR d.app_role_id IS DISTINCT FROM $2)
        AND NOT EXISTS(SELECT 1 FROM user_app_role_overrides o WHERE o.user_sub=ur.user_sub AND o.client_id=$1)`, [clientId, top.role_id]);
    rootSubjects = rows.map(row => row.user_sub);
    await db.query(`INSERT INTO org_role_app_defaults (role_slug, client_id, app_role_id, updated_at)
      SELECT slug, $1, $2, now() FROM org_roles WHERE level = 0
      ON CONFLICT (role_slug, client_id) DO UPDATE SET app_role_id = EXCLUDED.app_role_id, updated_at = now()`, [clientId, top.role_id]);
  }
  const changed = await deps.publishRoleChanges(db, [clientId], null, { force: forceCurrent, forceSubjects: rootSubjects });
  if (changed) await db.query(`INSERT INTO org_audit_log(actor_label, action, detail)
    VALUES ('system (roles.sync)', 'roles.reconcile', $1::jsonb)`, [JSON.stringify({ client: clientId, affected: changed })]);
  return order;
}
