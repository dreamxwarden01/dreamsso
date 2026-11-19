ALTER TABLE event_destinations ADD COLUMN IF NOT EXISTS last_outcome_code text;
ALTER TABLE event_destinations ADD COLUMN IF NOT EXISTS last_outcome_at timestamptz;
ALTER TABLE event_destinations ADD COLUMN IF NOT EXISTS last_recovered_at timestamptz;
CREATE INDEX IF NOT EXISTS event_outbox_client_status ON event_outbox(target_client_id,status);
CREATE TABLE IF NOT EXISTS event_recoveries (
  client_id text NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
  request_id uuid NOT NULL,
  requested_by uuid NOT NULL,
  result jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(client_id,request_id)
);
