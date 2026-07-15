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
    retired_at      timestamptz
);

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
    delivered_at     timestamptz
);
CREATE INDEX idx_outbox_due ON event_outbox (next_attempt_at) WHERE status = 'pending';

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
    id           uuid PRIMARY KEY,                -- the inbound event's jti
    source       text NOT NULL,
    processed_at timestamptz NOT NULL DEFAULT now()
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
-- Registration: invitation codes (user design, 2026-07-08)
-- Lifecycle: live -> CONSUMED (row kept forever: used_by uuid, username via
-- join at read) | VOIDED (row deleted) | EXPIRED-unused (deleted by sweeper).
-- use_count counts EMAIL SWITCHES at /register/start (first use included;
-- same-email resends are free) — a 4th switch voids the code.
-- invited_role_slug: org role picked at creation (strictly below creator);
-- NULL (or role deleted -> FK sets NULL) falls back to default_org_role.
CREATE TABLE IF NOT EXISTS invitation_codes (
    code             text PRIMARY KEY CHECK (code ~ '^[A-Z0-9]{12}$'),
    created_by       uuid REFERENCES identities(sub) ON DELETE SET NULL,
    created_by_label text NOT NULL,          -- snapshot, survives creator deletion
    invited_role_slug text REFERENCES org_roles(slug) ON DELETE SET NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    expires_at       timestamptz NOT NULL,
    use_count        integer NOT NULL DEFAULT 0,
    pending_email    citext,                 -- the one in-flight registration
    pending_at       timestamptz,            -- stamp for the stale-pending sweep
    used_by          uuid REFERENCES identities(sub) ON DELETE SET NULL,
    used_at          timestamptz,
    voided_at        timestamptz,            -- distinguishes Voided from Expired
    clear_at         timestamptz             -- deletion due; NULL = consumed, keep forever
);
CREATE INDEX IF NOT EXISTS idx_invitation_codes_expiry ON invitation_codes (expires_at) WHERE used_by IS NULL;
