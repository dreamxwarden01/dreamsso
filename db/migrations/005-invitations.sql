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
