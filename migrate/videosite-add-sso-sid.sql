-- videosite: bind app sessions to the SSO master session (id_token `sid`) so we
-- can rotate-on-login (one app session per SSO session) and honor OIDC
-- back-channel logout. Apply alongside the OIDC cutover (MariaDB).
ALTER TABLE sessions
  ADD COLUMN sso_sid varchar(64) DEFAULT NULL,
  ADD KEY idx_sso_sid (sso_sid);
