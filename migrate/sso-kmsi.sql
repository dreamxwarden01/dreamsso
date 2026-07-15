-- "Stay signed in?" (KMSI): sessions are born TRANSIENT (browser-session cookie,
-- short absolute window); answering Yes marks them persistent (expiring cookie,
-- full absolute window). Server-side windows matter even for transient sessions —
-- browsers restore session cookies ("continue where you left off").
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS persistent boolean NOT NULL DEFAULT false;
