-- videosite -> SSO event channel: delivered/dead archive for outbound events
-- (pending events live in Redis, sso:events:out). MariaDB twin of the SSO's
-- event_outbox usage.
CREATE TABLE IF NOT EXISTS sso_event_outbox (
    id           CHAR(36) PRIMARY KEY,
    kind         VARCHAR(64) NOT NULL,
    payload      LONGTEXT NOT NULL,
    status       ENUM('delivered','dead') NOT NULL,
    attempts     INT NOT NULL DEFAULT 0,
    created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    delivered_at TIMESTAMP NULL DEFAULT NULL
);
