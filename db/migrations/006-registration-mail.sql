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
