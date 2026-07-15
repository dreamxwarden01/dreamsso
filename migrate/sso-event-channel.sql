-- Event channel (RP <-> SSO): app-role mirror + catalog metadata, and the
-- registry column rename backchannel_logout_uri -> events_uri (the endpoint
-- now receives the generic signed-envelope events, logout included).
-- event_outbox / processed_events already exist (schema.sql): the outbox is
-- reused as the delivered/dead ARCHIVE (pending events live in Redis);
-- processed_events is the inbound dedupe.

BEGIN;

-- Mirror of each RP's role catalog (pushed via roles.sync, full-state).
CREATE TABLE IF NOT EXISTS app_roles (
    client_id  text NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    role_id    int  NOT NULL,
    name       text NOT NULL,
    level      int  NOT NULL,                     -- smaller = higher privilege
    is_system  boolean NOT NULL DEFAULT false,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (client_id, role_id)
);

-- One row per client: catalog-level metadata. default_role_id is SINGULAR by
-- design (a per-row boolean could encode zero or two defaults); the composite
-- FK proves the default exists in the catalog, and deleting that role nulls
-- only the default (deny-safe until the next sync sets a new one).
CREATE TABLE IF NOT EXISTS app_role_catalogs (
    client_id       text PRIMARY KEY REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    default_role_id int,
    synced_at       timestamptz NOT NULL DEFAULT now(),
    last_sync_iat   bigint NOT NULL DEFAULT 0,    -- ordering guard: older envelopes ignored
    FOREIGN KEY (client_id, default_role_id)
      REFERENCES app_roles(client_id, role_id) ON DELETE SET NULL (default_role_id)
);

ALTER TABLE oauth_clients RENAME COLUMN backchannel_logout_uri TO events_uri;

-- Unified path decision: every app serves POST /backchannel/events.
UPDATE oauth_clients
   SET events_uri = regexp_replace(events_uri, '^(https?://[^/]+).*$', '\1/backchannel/events')
 WHERE events_uri IS NOT NULL;

COMMIT;
