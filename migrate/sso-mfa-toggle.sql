-- MFA is challenged at login only when the ACCOUNT TOGGLE is on — owning factors
-- alone does not challenge. The old email_mfa_enabled placeholder becomes THE
-- toggle (one toggle per account; which METHOD is challenged is computed from
-- what the user owns: totp/passkey preferred, email only when neither exists).
ALTER TABLE identities RENAME COLUMN email_mfa_enabled TO mfa_enabled;
