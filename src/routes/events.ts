import type pg from 'pg';
import { pool } from '../db.js';
import { config } from '../config.js';
import { clientKeySet } from '../clientKeys.js';
import { kickDrain } from '../events.js';
import { createEventReceiver, type EventClient } from '../backchannel/eventReceiver.js';
import { processIncomingEvents } from '../backchannel/rolesSync.js';
import { withRoleTransaction, ensureRoleSyncState, publishRoleChanges } from '../rbac/roleChanges.js';

// Inbound IDs, catalog effects, authority revisions and notifications share one
// PostgreSQL commit. The shared role lock also serializes the first catalog
// against org-membership and assignment changes; delivery happens after commit.
type RegisteredEventClient = EventClient & Parameters<typeof clientKeySet>[0];
export const eventsRouter = createEventReceiver<RegisteredEventClient>({
  issuer: () => config.issuer,
  loadClient: async clientId => {
    const { rows } = await pool.query<RegisteredEventClient>(
      'SELECT client_id, jwks, jwks_uri, disabled_at FROM oauth_clients WHERE client_id = $1', [clientId]);
    return rows[0] ?? null;
  },
  keySet: clientKeySet,
  process: (clientId, time, events) => withRoleTransaction((db: pg.PoolClient) => processIncomingEvents(db, clientId, time, events,
    { ensureRoleSyncState, publishRoleChanges })),
  afterCommit: kickDrain,
});
