-- DreamSSO: back the account-console Devices pane.
--   country  — cf-ipcountry captured at login (null = Unknown, T1 = Tor network).
--   clients  — set of client_ids that redeemed a code under this session. Drives
--              the "apps accessed" list AND scopes back-channel logout fan-out to
--              only the apps the user actually used in this browser (append-if-absent
--              at /token). No junction table: the UI shows no per-app timestamps.
ALTER TABLE sessions
  ADD COLUMN IF NOT EXISTS country text,
  ADD COLUMN IF NOT EXISTS clients text[] NOT NULL DEFAULT '{}';
