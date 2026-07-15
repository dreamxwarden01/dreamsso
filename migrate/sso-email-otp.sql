-- Emailed OTP storage (videosite semantics): one live code per (user, purpose),
-- sealed with KEY_ENCRYPTION_KEY like TOTP secrets. Resend within the validity
-- window returns the SAME code (sent_at refreshes the verify window; generated_at
-- governs regeneration); 5 failed attempts kill the code (must resend).
CREATE TABLE IF NOT EXISTS email_otps (
    user_sub     uuid NOT NULL REFERENCES identities(sub) ON DELETE CASCADE,
    purpose      text NOT NULL DEFAULT 'login',            -- later: step-up, reset
    code_enc     bytea NOT NULL,                           -- sealed [iv|tag|ct]
    generated_at timestamptz NOT NULL DEFAULT now(),
    sent_at      timestamptz NOT NULL DEFAULT now(),
    attempts     int NOT NULL DEFAULT 0,
    PRIMARY KEY (user_sub, purpose)
);

-- Rolling 24h send limits per user (cooldown 60s, cap 20/day — mirrors videosite,
-- well under the Cloudflare Email Sending daily cap).
CREATE TABLE IF NOT EXISTS email_otp_limits (
    user_sub   uuid PRIMARY KEY REFERENCES identities(sub) ON DELETE CASCADE,
    first_sent timestamptz NOT NULL,
    last_sent  timestamptz NOT NULL,
    total_sent int NOT NULL
);
