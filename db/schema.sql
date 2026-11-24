-- DreamSSO — SSO database schema (PostgreSQL)
--
-- This is the SSO's OWN database. App-side tables (role->permission mapping,
-- per-user permission overrides, the credential-less shadow user row) live in
-- each app's own database and are NOT modeled here.
--
-- Ephemeral state lives in Redis, not here: login transactions, authorization
-- codes, MFA/step-up challenges, rate-limit counters, and the hot session cache.
-- Durable records are below.
--
-- Conventions: UUIDv7 supplied by the app for `sub`; gen_random_uuid() for internal
-- surrogate ids; timestamptz everywhere; secrets stored only as hashes/ciphertext.

CREATE EXTENSION IF NOT EXISTS citext;
CREATE EXTENSION IF NOT EXISTS pgcrypto;   -- gen_random_uuid()

CREATE OR REPLACE FUNCTION set_updated_at() RETURNS trigger
  LANGUAGE plpgsql AS $$
BEGIN NEW.updated_at = now(); RETURN NEW; END $$;

-- ---------------------------------------------------------------------------
-- Identity & credentials
-- ---------------------------------------------------------------------------

CREATE TABLE identities (
    sub                 uuid PRIMARY KEY,                 -- app-supplied UUIDv7; also the OIDC `sub`
    username            citext NOT NULL,
    display_name        text   NOT NULL,
    email               citext,
    email_verified      boolean NOT NULL DEFAULT false,
    password_hash       text,                             -- argon2id PHC string; nullable (passkey-only later)
    password_changed_at timestamptz,
    mfa_enabled         boolean NOT NULL DEFAULT false,   -- the account MFA toggle: challenge at login only when ON (method = what the user owns)
    avatar              text,                             -- profile picture file name ({sub}-{16hex}.webp under data/avatars/)
    status              text NOT NULL DEFAULT 'active'
                          CHECK (status IN ('active','disabled','locked')),
    disabled_reason     text,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    deleted_at          timestamptz
);
CREATE UNIQUE INDEX uq_identities_username ON identities (username) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX uq_identities_email    ON identities (email)
    WHERE deleted_at IS NULL AND email IS NOT NULL;
CREATE TRIGGER trg_identities_updated BEFORE UPDATE ON identities
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE webauthn_credentials (              -- passkeys
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_sub        uuid NOT NULL REFERENCES identities(sub) ON DELETE CASCADE,
    credential_id   bytea NOT NULL,
    public_key      bytea NOT NULL,
    sign_count      bigint NOT NULL DEFAULT 0,
    transports      text[],
    aaguid          uuid,
    backup_eligible boolean,
    backup_state    boolean,
    label           text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    last_used_at    timestamptz
);
CREATE UNIQUE INDEX uq_webauthn_credential_id ON webauthn_credentials (credential_id);
CREATE INDEX idx_webauthn_user ON webauthn_credentials (user_sub);

CREATE TABLE totp_credentials (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_sub      uuid NOT NULL REFERENCES identities(sub) ON DELETE CASCADE,
    secret_enc    bytea NOT NULL,                  -- AES-256-GCM (enc:v1:iv:tag:ct), key in KMS/env
    label         text,
    confirmed_at  timestamptz,                     -- NULL until first successful verify
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_used_at  timestamptz
);
CREATE INDEX idx_totp_user ON totp_credentials (user_sub);

-- ---------------------------------------------------------------------------
-- Relying parties (OAuth/OIDC clients) & token signing
-- ---------------------------------------------------------------------------

CREATE TABLE oauth_clients (
    client_id                  text PRIMARY KEY,            -- e.g. 'videosite'
    name                       text NOT NULL,
    is_first_party             boolean NOT NULL DEFAULT true,
    entry_policy               text NOT NULL DEFAULT 'opt_in'
                                 CHECK (entry_policy IN ('opt_in','baseline')),
    redirect_uris              text[] NOT NULL,
    post_logout_redirect_uris  text[] NOT NULL DEFAULT '{}',
    events_uri                 text,          -- POST /backchannel/events receiver (logout + role events)
    token_endpoint_auth_method text NOT NULL DEFAULT 'private_key_jwt',
    jwks_uri                   text,                        -- client public keys (private_key_jwt)
    jwks                       jsonb,                       -- or inline
    allowed_scopes             text[] NOT NULL DEFAULT '{openid,profile,email}',
    is_system                  boolean NOT NULL DEFAULT false, -- built-in (account portal): no disable/delete
    disabled_at                timestamptz,                 -- disabled clients rejected at /authorize + /token; delete only from disabled
    created_at                 timestamptz NOT NULL DEFAULT now(),
    updated_at                 timestamptz NOT NULL DEFAULT now()
);
CREATE TRIGGER trg_clients_updated BEFORE UPDATE ON oauth_clients
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE signing_keys (                       -- JWKS for SSO-issued tokens
    kid             text PRIMARY KEY,
    alg             text NOT NULL DEFAULT 'EdDSA',
    public_jwk      jsonb NOT NULL,
    private_key_enc bytea NOT NULL,                -- encrypted at rest
    status          text NOT NULL DEFAULT 'next'
                      CHECK (status IN ('current','next','retired')),
    created_at      timestamptz NOT NULL DEFAULT now(),
    activated_at    timestamptz,
    retired_at      timestamptz,
    rotation_id     uuid,
    published_at    timestamptz,
    activate_after  timestamptz,
    CONSTRAINT signing_keys_publication_window CHECK (
      (published_at IS NULL AND activate_after IS NULL)
      OR (published_at IS NOT NULL AND activate_after IS NOT NULL
          AND activate_after >= published_at + interval '300 seconds')
    ),
    CONSTRAINT signing_keys_pending_identity CHECK (
      status <> 'next' OR (rotation_id IS NOT NULL AND activated_at IS NULL AND retired_at IS NULL)
    )
);
CREATE UNIQUE INDEX signing_keys_one_current ON signing_keys ((1)) WHERE status='current';
CREATE UNIQUE INDEX signing_keys_one_next ON signing_keys ((1)) WHERE status='next';
CREATE UNIQUE INDEX signing_keys_rotation_id ON signing_keys(rotation_id) WHERE rotation_id IS NOT NULL;

-- ---------------------------------------------------------------------------
-- Devices & sessions
-- ---------------------------------------------------------------------------

CREATE TABLE devices (                            -- remembered-MFA / device management
    device_id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_sub             uuid NOT NULL REFERENCES identities(sub) ON DELETE CASCADE,
    cookie_hash          bytea NOT NULL,           -- sha-256 of the device cookie secret
    label                text,
    user_agent           text,
    mfa_trust_expires_at timestamptz,              -- remembered-MFA window; NULL = not trusted
    created_at           timestamptz NOT NULL DEFAULT now(),
    last_seen            timestamptz NOT NULL DEFAULT now(),
    revoked_at           timestamptz
);
CREATE UNIQUE INDEX uq_devices_cookie ON devices (cookie_hash);
CREATE INDEX idx_devices_user ON devices (user_sub);

CREATE TABLE sessions (                           -- the SSO master (browser) session
    sid          uuid PRIMARY KEY DEFAULT gen_random_uuid(),  -- public OIDC session id (in tokens/logout)
    user_sub     uuid NOT NULL REFERENCES identities(sub) ON DELETE CASCADE,
    token_hash   bytea NOT NULL,                  -- sha-256 of the cookie secret (rotated on privilege change)
    device_id    uuid REFERENCES devices(device_id) ON DELETE SET NULL,
    amr          text[] NOT NULL DEFAULT '{}',    -- e.g. {pwd,otp} / {passkey}
    acr          text,
    auth_time    timestamptz NOT NULL DEFAULT now(),
    ip           inet,
    user_agent   text,
    country      text,                            -- cf-ipcountry at login (null = Unknown; T1 = Tor)
    city         text,                            -- cf-ipcity  \ both need the "Add visitor location
    region       text,                            -- cf-region  / headers" transform on the zone; null = show country only
    clients      text[] NOT NULL DEFAULT '{}',     -- client_ids that redeemed a code under this session (apps-accessed + scoped fan-out)
    stepup_at    timestamptz,                     -- sudo window: last verification (login pre-clearance or step-up challenge)
    stepup_method text,                            -- method of that verification: passkey|totp|email|password (tiered step-up: scenarios demand a tier)
    persistent   boolean NOT NULL DEFAULT false,  -- KMSI "Yes": expiring cookie + full absolute window (transient = session cookie + short window)
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_seen    timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL
);
CREATE UNIQUE INDEX uq_sessions_token ON sessions (token_hash);
CREATE INDEX idx_sessions_user ON sessions (user_sub);

CREATE TABLE refresh_tokens (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_sub     uuid NOT NULL REFERENCES identities(sub) ON DELETE CASCADE,
    client_id    text NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    sid          uuid REFERENCES sessions(sid) ON DELETE CASCADE,
    token_hash   bytea NOT NULL,
    rotated_from uuid REFERENCES refresh_tokens(id),
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL,
    revoked_at   timestamptz
);
CREATE UNIQUE INDEX uq_refresh_token ON refresh_tokens (token_hash);
CREATE INDEX idx_refresh_user_client ON refresh_tokens (user_sub, client_id);

-- ---------------------------------------------------------------------------
-- Authorization: org roles, per-app catalog, assignments
--   SSO owns assignment + org-level defaults. Apps own role->permission meaning.
-- ---------------------------------------------------------------------------

CREATE TABLE org_roles (
    slug       text PRIMARY KEY,                  -- 'org:member','org:staff','org:admin'
    label      text NOT NULL,
    level      int  NOT NULL DEFAULT 100,         -- precedence / display ordering
    is_system  boolean NOT NULL DEFAULT false,    -- built-in (superadmin/admin/standard_user): no disable/delete
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE app_role_catalog (                   -- reported by each app: {name, level}
    client_id  text NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    slug       text NOT NULL,                     -- prefixed, e.g. 'videosite:instructor'
    label      text,
    level      int NOT NULL DEFAULT 100,          -- app-declared rank; LOWER = more privileged
                                                  --   (SSO ranks by this; it never infers permissions from it)
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (client_id, slug)
);

CREATE TABLE org_role_app_defaults (              -- org-role layer of: override ?? org default ?? catalog default
    role_slug   text NOT NULL REFERENCES org_roles(slug) ON DELETE CASCADE,
    client_id   text NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    app_role_id int,                              -- NULL = No access; no row = inherit catalog default
    updated_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (role_slug, client_id)
);

CREATE TABLE user_org_roles (
    user_sub      uuid NOT NULL REFERENCES identities(sub) ON DELETE CASCADE,
    org_role_slug text NOT NULL REFERENCES org_roles(slug) ON DELETE CASCADE,
    granted_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_sub, org_role_slug),
    CONSTRAINT uq_user_org_role UNIQUE (user_sub)  -- one org role per user (tier-based)
);

CREATE TABLE user_app_role_overrides (            -- user-override layer of: override ?? org default ?? catalog default
    user_sub    uuid NOT NULL REFERENCES identities(sub) ON DELETE CASCADE,
    client_id   text NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    app_role_id int,                              -- NULL = No access; no row = inherit downward
    updated_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_sub, client_id)
);

-- Org audit log. Labels are SNAPSHOTS (display name at the time) so the log stays
-- readable after renames/deletions; no FKs — log rows outlive users. actor_sub is
-- NULL for system-originated entries (roles.sync). "Clear" is soft.
CREATE TABLE org_audit_log (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_sub    uuid,                            -- NULL = system-originated (roles.sync)
    actor_label  text NOT NULL,
    target_sub   uuid,
    target_label text,
    action       text NOT NULL,                   -- user.role_change | user.password_set | logs.clear | ...
    detail       jsonb NOT NULL DEFAULT '{}',
    created_at   timestamptz NOT NULL DEFAULT now(),
    cleared_at   timestamptz,
    cleared_by   uuid
);
CREATE INDEX idx_org_audit_page ON org_audit_log (created_at DESC, id DESC);

-- SSO/account-portal permissions (Phase A): per-role defaults (seeded from the
-- code catalog src/rbac/catalog.ts) + per-user overrides. Resolution per (user,key):
--   user override (grant/deny) -> role default (grant/deny) -> deny.
CREATE TABLE role_permissions (
    role_slug text NOT NULL REFERENCES org_roles(slug) ON DELETE CASCADE,
    perm_key  text NOT NULL,                          -- validated against the code catalog
    effect    text NOT NULL CHECK (effect IN ('grant','deny')),
    PRIMARY KEY (role_slug, perm_key)
);
CREATE TABLE user_permission_overrides (
    user_sub uuid NOT NULL REFERENCES identities(sub) ON DELETE CASCADE,
    perm_key text NOT NULL,
    effect   text NOT NULL CHECK (effect IN ('grant','deny')),  -- ABSENCE = inherit from role
    PRIMARY KEY (user_sub, perm_key)
);

CREATE TABLE user_app_roles (                     -- explicit per-app role (overrides org default)
    user_sub   uuid NOT NULL REFERENCES identities(sub) ON DELETE CASCADE,
    client_id  text NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    role_slug  text NOT NULL,
    granted_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_sub, client_id),            -- one explicit role per (user, app)
    FOREIGN KEY (client_id, role_slug)
        REFERENCES app_role_catalog(client_id, slug)
);

CREATE TABLE user_app_denials (                   -- hard per-user ban from an app (separate from fallback)
    user_sub   uuid NOT NULL REFERENCES identities(sub) ON DELETE CASCADE,
    client_id  text NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    reason     text,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_sub, client_id)
);

-- Entry resolution at /authorize, per (user, client):
--   1. row in user_app_denials                          -> NO ENTRY
--   2. row in user_app_roles (explicit override)         -> that role
--   3. else map EACH of the user's org roles through org_role_app_defaults
--      (grants_entry = true) and take the most-privileged result by
--      app_role_catalog.level (LOWER = more privileged; ties broken by slug)  -> that role
--   4. else                                               -> NO ENTRY  (opt_in apps)
-- Org-level and app-level rankings are INDEPENDENT: a "lower" org role may map to a
-- "higher" app role, so resolution always ranks candidates by the APP's level.

-- Emailed OTPs (login challenge floor; later step-up/reset). One live code per
-- (user, purpose), sealed like TOTP secrets; resend-in-window returns the SAME
-- code; 5 failed attempts kill it. See src/emailOtp.ts.
CREATE TABLE email_otps (
    user_sub     uuid NOT NULL REFERENCES identities(sub) ON DELETE CASCADE,
    purpose      text NOT NULL DEFAULT 'login',
    code_enc     bytea NOT NULL,
    generated_at timestamptz NOT NULL DEFAULT now(),
    sent_at      timestamptz NOT NULL DEFAULT now(),
    attempts     int NOT NULL DEFAULT 0,
    PRIMARY KEY (user_sub, purpose)
);
CREATE TABLE email_otp_limits (                   -- rolling 24h send caps (60s cooldown, 20/day)
    user_sub   uuid PRIMARY KEY REFERENCES identities(sub) ON DELETE CASCADE,
    first_sent timestamptz NOT NULL,
    last_sent  timestamptz NOT NULL,
    total_sent int NOT NULL
);

-- Admin-editable site settings. Secret values sealed with KEY_ENCRYPTION_KEY
-- ('enc:v1:<base64>'); plain values as-is. See src/settings.ts.
CREATE TABLE settings (
    key        text PRIMARY KEY,
    value      text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- Reliable cross-service signalling (transactional outbox + idempotent inbox)
-- ---------------------------------------------------------------------------

CREATE TABLE event_outbox (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),  -- == jti / idempotency key
    kind             text NOT NULL,                 -- backchannel_logout | token_claims_change | ...
    target_client_id text REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    payload          jsonb NOT NULL,
    version          bigint NOT NULL DEFAULT 0,      -- guards stale claim updates
    status           text NOT NULL DEFAULT 'pending'
                       CHECK (status IN ('pending','delivered','dead')),
    attempts         int NOT NULL DEFAULT 0,
    next_attempt_at  timestamptz NOT NULL DEFAULT now(),
    created_at       timestamptz NOT NULL DEFAULT now(),
    delivered_at     timestamptz,
    sequence         bigint GENERATED BY DEFAULT AS IDENTITY,
    last_error_code  text,
    legacy_redis_member text,
    legacy_redis_score double precision
);
CREATE UNIQUE INDEX event_outbox_sequence ON event_outbox(sequence);
CREATE INDEX event_outbox_client_pending ON event_outbox(target_client_id,sequence) WHERE status='pending';
CREATE TABLE event_destinations (
    client_id text PRIMARY KEY REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    lease_token uuid,
    lease_until timestamptz,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    failures integer NOT NULL DEFAULT 0 CHECK(failures>=0),
    last_outcome_code text,
    last_outcome_at timestamptz,
    last_recovered_at timestamptz,
    CHECK ((lease_token IS NULL) = (lease_until IS NULL))
);
CREATE INDEX idx_outbox_due ON event_outbox (next_attempt_at) WHERE status = 'pending';
CREATE INDEX event_outbox_client_status ON event_outbox(target_client_id,status);
CREATE TABLE event_recoveries (
    client_id text NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    request_id uuid NOT NULL,
    requested_by uuid NOT NULL,
    result jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY(client_id,request_id)
);

-- Mirror of each RP's role catalog (pushed via roles.sync, full-state).
CREATE TABLE app_roles (
    client_id  text NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    role_id    int  NOT NULL,
    name       text NOT NULL,
    level      int  NOT NULL,                     -- smaller = higher privilege
    is_system  boolean NOT NULL DEFAULT false,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (client_id, role_id)
);

-- Catalog-level metadata: SINGULAR default role + sync freshness + the
-- ordering guard (older envelopes ignored).
CREATE TABLE app_role_catalogs (
    client_id       text PRIMARY KEY REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    default_role_id int,
    synced_at       timestamptz NOT NULL DEFAULT now(),
    last_sync_iat   bigint NOT NULL DEFAULT 0,
    FOREIGN KEY (client_id, default_role_id)
      REFERENCES app_roles(client_id, role_id) ON DELETE SET NULL (default_role_id)
);

CREATE TABLE processed_events (                   -- inbox dedupe: at-least-once -> idempotent
    id           uuid NOT NULL,
    source       text NOT NULL,
    processed_at timestamptz NOT NULL DEFAULT now(),
    event_type   text,
    payload_digest bytea CHECK(payload_digest IS NULL OR octet_length(payload_digest)=32),
    PRIMARY KEY(source,id)
);

-- Durable catalog ordering and per-client authority lineage. Revisions are counters,
-- not timestamps; restore the matching state instead of resetting a known lineage.
CREATE TABLE app_role_sync_state (
    client_id text PRIMARY KEY REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    catalog_mode text NOT NULL DEFAULT 'legacy' CHECK(catalog_mode IN('legacy','revisioned')),
    catalog_epoch uuid,
    catalog_revision bigint,
    catalog_digest bytea CHECK(catalog_digest IS NULL OR octet_length(catalog_digest)=32),
    last_sync_iat bigint NOT NULL DEFAULT 0,
    authority_epoch uuid NOT NULL DEFAULT gen_random_uuid(),
    authority_revision bigint NOT NULL DEFAULT 0 CHECK(authority_revision>=0),
    CHECK ((catalog_mode='legacy' AND catalog_epoch IS NULL AND catalog_revision IS NULL)
        OR (catalog_mode='revisioned' AND catalog_epoch IS NOT NULL AND catalog_revision IS NOT NULL AND catalog_revision>0))
);
CREATE TABLE app_role_effective (
    client_id text NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    user_sub uuid NOT NULL REFERENCES identities(sub) ON DELETE CASCADE,
    role_id integer,
    managed boolean NOT NULL,
    account_status text CONSTRAINT app_role_effective_account_status_check
      CHECK(account_status IS NULL OR account_status IN('active','disabled','locked','deleted')),
    authority_revision bigint NOT NULL DEFAULT 0 CHECK(authority_revision>=0),
    PRIMARY KEY(client_id,user_sub)
);

-- ---------------------------------------------------------------------------
-- Account-lifecycle tokens & audit
-- ---------------------------------------------------------------------------

CREATE TABLE password_reset_tokens (
    token_hash bytea PRIMARY KEY,                 -- sha-256; token e-mailed once
    user_sub   uuid NOT NULL REFERENCES identities(sub) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    used_at    timestamptz
);
CREATE INDEX idx_pwreset_user ON password_reset_tokens (user_sub);

CREATE TABLE email_verification_tokens (
    token_hash bytea PRIMARY KEY,
    user_sub   uuid NOT NULL REFERENCES identities(sub) ON DELETE CASCADE,
    new_email  citext NOT NULL,                   -- verify before switching; notify old address
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    used_at    timestamptz
);

SET LOCAL lock_timeout='5s';
-- Per-account verification state; targets are deliberately NOT globally reserved.
ALTER TABLE identities ADD COLUMN IF NOT EXISTS email_change_revision bigint NOT NULL DEFAULT 0;
CREATE TABLE IF NOT EXISTS email_change_operations (
  user_sub uuid PRIMARY KEY REFERENCES identities(sub) ON DELETE CASCADE,
  request_id uuid NOT NULL,
  revision bigint NOT NULL,
  kind text NOT NULL CHECK(kind IN ('change','confirm')),
  new_email citext NOT NULL,
  token_hash bytea NOT NULL UNIQUE CHECK(octet_length(token_hash)=32),
  token_enc bytea,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at timestamptz NOT NULL,
  last_sent_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  completed_at timestamptz,
  CHECK(expires_at>created_at),
  CHECK((completed_at IS NULL AND token_enc IS NOT NULL) OR (completed_at IS NOT NULL AND token_enc IS NULL))
);
-- Fence every writer, including an admin change followed by restoring the old
-- address, and password recovery. No old token is imported from Redis.
CREATE OR REPLACE FUNCTION invalidate_email_change_operation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.email IS DISTINCT FROM OLD.email
     OR NEW.email_verified IS DISTINCT FROM OLD.email_verified
     OR NEW.status IS DISTINCT FROM OLD.status
     OR NEW.deleted_at IS DISTINCT FROM OLD.deleted_at
     OR NEW.password_hash IS DISTINCT FROM OLD.password_hash THEN
    NEW.email_change_revision := OLD.email_change_revision + 1;
    DELETE FROM email_change_operations WHERE user_sub=OLD.sub;
  END IF;
  RETURN NEW;
END $$;
DO $email_operation_trigger$
BEGIN
  IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='identities'::regclass AND tgname='trg_identity_email_operation') THEN
    EXECUTE 'CREATE TRIGGER trg_identity_email_operation BEFORE UPDATE OF email,email_verified,status,deleted_at,password_hash ON identities FOR EACH ROW EXECUTE FUNCTION invalidate_email_change_operation()';
  END IF;
END $email_operation_trigger$;

CREATE TABLE audit_log (                          -- append-only
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    occurred_at timestamptz NOT NULL DEFAULT now(),
    event_type  text NOT NULL,                    -- login | mfa_change | step_up | role_change | ...
    actor_sub   uuid REFERENCES identities(sub) ON DELETE SET NULL,
    subject_sub uuid REFERENCES identities(sub) ON DELETE SET NULL,
    client_id   text,
    ip          inet,
    user_agent  text,
    request_id  uuid,
    details     jsonb NOT NULL DEFAULT '{}'
);
CREATE INDEX idx_audit_subject ON audit_log (subject_sub, occurred_at DESC);
CREATE INDEX idx_audit_type    ON audit_log (event_type, occurred_at DESC);
-- Registration invitations retain all terminal records permanently. A displayed
-- code identifies eligibility; mailbox ownership proofs live in separate storage.
CREATE TABLE IF NOT EXISTS invitation_codes (
    code text PRIMARY KEY CHECK(code ~ '^[A-Z0-9]{12}$'),
    created_by uuid REFERENCES identities(sub) ON DELETE SET NULL,
    created_by_label text NOT NULL,
    invited_role_slug text REFERENCES org_roles(slug) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    use_count integer NOT NULL DEFAULT 0,
    pending_email citext,
    pending_at timestamptz,
    used_by uuid REFERENCES identities(sub) ON DELETE SET NULL,
    used_at timestamptz,
    voided_at timestamptz,
    clear_at timestamptz
);
CREATE INDEX IF NOT EXISTS idx_invitation_codes_expiry ON invitation_codes(expires_at) WHERE used_by IS NULL;
-- Single-use invitations: permanent history and actor-bound management receipts.
ALTER TABLE invitation_codes ADD COLUMN IF NOT EXISTS id uuid NOT NULL DEFAULT gen_random_uuid();
CREATE UNIQUE INDEX IF NOT EXISTS invitation_codes_id ON invitation_codes(id);
ALTER TABLE invitation_codes ADD COLUMN IF NOT EXISTS bound_email citext;
ALTER TABLE invitation_codes ADD COLUMN IF NOT EXISTS bound_at timestamptz;
ALTER TABLE invitation_codes ADD COLUMN IF NOT EXISTS binding_source text CHECK(binding_source IN ('creation','first_request'));
ALTER TABLE invitation_codes ADD COLUMN IF NOT EXISTS delivery text NOT NULL DEFAULT 'link' CHECK(delivery IN ('link','email'));
ALTER TABLE invitation_codes ADD COLUMN IF NOT EXISTS note text NOT NULL DEFAULT '' CHECK(char_length(note)<=60);
ALTER TABLE invitation_codes ADD COLUMN IF NOT EXISTS invited_role_slug_snapshot text;
ALTER TABLE invitation_codes ADD COLUMN IF NOT EXISTS invited_role_label text;
ALTER TABLE invitation_codes ADD COLUMN IF NOT EXISTS invalidated_at timestamptz;
ALTER TABLE invitation_codes ADD COLUMN IF NOT EXISTS invalid_reason text;
ALTER TABLE invitation_codes ADD COLUMN IF NOT EXISTS revoked_by uuid;
ALTER TABLE invitation_codes ADD COLUMN IF NOT EXISTS revoked_by_label text;
ALTER TABLE invitation_codes ADD COLUMN IF NOT EXISTS used_username_snapshot text;
ALTER TABLE invitation_codes ADD COLUMN IF NOT EXISTS used_display_name_snapshot text;
ALTER TABLE invitation_codes ADD COLUMN IF NOT EXISTS mail_state text NOT NULL DEFAULT 'none' CHECK(mail_state IN ('none','queued','sending','sent','failed','unknown'));
ALTER TABLE invitation_codes ADD COLUMN IF NOT EXISTS mail_attempts integer NOT NULL DEFAULT 0 CHECK(mail_attempts>=0);
ALTER TABLE invitation_codes ADD COLUMN IF NOT EXISTS mail_last_at timestamptz;
ALTER TABLE invitation_codes ADD COLUMN IF NOT EXISTS mail_error_code text;
ALTER TABLE invitation_codes ADD COLUMN IF NOT EXISTS mail_next_retry_at timestamptz;
-- Preserve an already-selected legacy mailbox, never reopen it to a new holder.
UPDATE invitation_codes SET bound_email=pending_email,bound_at=COALESCE(pending_at,created_at),binding_source='first_request'
 WHERE bound_email IS NULL AND pending_email IS NOT NULL;
UPDATE invitation_codes ic SET invited_role_slug_snapshot=COALESCE(ic.invited_role_slug,'deleted'),
 invited_role_label=COALESCE((SELECT r.label FROM org_roles r WHERE r.slug=ic.invited_role_slug),'Deleted role')
 WHERE invited_role_slug_snapshot IS NULL;
UPDATE invitation_codes ic SET used_username_snapshot=u.username,used_display_name_snapshot=u.display_name
 FROM identities u WHERE ic.used_by=u.sub AND ic.used_at IS NOT NULL AND ic.used_username_snapshot IS NULL;
UPDATE invitation_codes SET invalidated_at=clock_timestamp(),invalid_reason='role_deleted'
 WHERE used_at IS NULL AND invited_role_slug IS NULL AND invalidated_at IS NULL;
UPDATE invitation_codes SET clear_at=NULL WHERE clear_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS invitation_codes_page ON invitation_codes(created_at DESC,id DESC);
CREATE INDEX IF NOT EXISTS invitation_codes_active ON invitation_codes(created_by,expires_at)
 WHERE used_at IS NULL AND voided_at IS NULL AND invalidated_at IS NULL;
CREATE TABLE IF NOT EXISTS invitation_requests (
 actor_sub uuid NOT NULL,
 request_id uuid NOT NULL,
 operation text NOT NULL CHECK(operation IN ('create','resend','revoke')),
 invitation_id uuid NOT NULL REFERENCES invitation_codes(id) ON DELETE RESTRICT,
 input jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(actor_sub,request_id)
);
-- Invitation email proofs are private; invitation codes remain ordinary audit identifiers.
CREATE TABLE IF NOT EXISTS invitation_mail_jobs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    invitation_id uuid NOT NULL REFERENCES invitation_codes(id),
    request_id uuid NOT NULL,
    actor_key text NOT NULL,
    email citext NOT NULL,
    proof_hash bytea NOT NULL UNIQUE,
    payload_enc bytea,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    state text NOT NULL DEFAULT 'queued' CHECK (state IN ('queued','sending','sent','failed','unknown')),
    lease_id uuid,
    lease_until timestamptz,
    finished_at timestamptz,
    error_code text,
    UNIQUE (actor_key,request_id)
);
CREATE INDEX IF NOT EXISTS invitation_mail_queue ON invitation_mail_jobs(created_at,id) WHERE state='queued';
CREATE INDEX IF NOT EXISTS invitation_mail_by_invite ON invitation_mail_jobs(invitation_id,created_at DESC);
-- A committed account can be recovered after a lost HTTP response, without creating another account.
CREATE TABLE IF NOT EXISTS registration_completions (
    proof_hash bytea PRIMARY KEY,
    user_sub uuid NOT NULL REFERENCES identities(sub),
    request_hash bytea NOT NULL,
    completed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    retry_until timestamptz NOT NULL
);

-- Public retries can coalesce onto an existing queued job without losing their idempotency receipt.
CREATE TABLE IF NOT EXISTS invitation_mail_requests (
    actor_key text NOT NULL,
    request_id uuid NOT NULL,
    invitation_id uuid NOT NULL REFERENCES invitation_codes(id),
    email citext NOT NULL,
    job_id uuid NOT NULL REFERENCES invitation_mail_jobs(id),
    PRIMARY KEY(actor_key,request_id)
);
