# DreamSSO

A self-hosted **OpenID Connect identity provider** with a companion **account portal** and **admin
console**, built for a single-organization, role-based deployment. It is the identity layer that the
[videosite](https://github.com/dreamxwarden01/videosite) relying party (and future apps) authenticate
against.

## What's here

| Path | Component | Stack |
|---|---|---|
| `src/` | **SSO** — the OIDC IdP. Owns the database (Postgres) and the session/challenge cache (Redis). | TypeScript, Express, [jose](https://github.com/panva/jose) |
| `admin-ui/` | **Admin console** — clients, keys, mTLS, settings, org management. | React SPA |
| `account/` | **Account portal (BFF)** — the end-user self-service app the SSO points users to. A *thin* proxy: no database, no KEK. | TypeScript server + React SPA |
| `migrate/` | **Identity migration** — imports an existing app's local users into the SSO (`sub` = UUIDv7). | Node + SQL |
| `db/` | SSO database schema. | SQL |
| `docs/` | Architecture, security (OpenAPI/API-Shield, S2S/mTLS map), and the production migration plan. | Markdown |
| `scripts/` | End-to-end test suites (setup, admin/org, MFA, step-up, key rotation, …). | tsx / node |

## Architecture

- **Single org, role-based RBAC** (not multi-tenant): `superadmin` / `admin` / `standard_user`, plus
  per-user permission overrides and per-app role catalogs.
- **The SSO owns identity and effective app-role assignments.** Each relying party owns its role
  catalog, defines what those roles permit, and enforces access in its application.
- **Registration is `jwks_uri`, never a key handoff.** Each RP (and the portal BFF) self-mints an
  Ed25519 client key and serves the public half at `/.well-known/jwks.json`; the SSO stores only the
  URL and fetches it lazily. Client-key rotation needs no re-registration.
- **Two-key auth split.** The RP/BFF private key does client authentication (`private_key_jwt`) and
  the signed back-channel event envelope; a separate per-user access token authorizes the portal's
  `/account/*` resource API. These resources require a token issued to the configured account
  client; other RPs continue to use `/userinfo` for profile claims. Registered scope limits apply
  during authorization and code exchange.
- **Session-bound access tokens.** Account resources and `/userinfo` check the current identity,
  client and original SSO session on every request. Logout invalidates that session's bearer
  access; inactive accounts and disabled clients are denied even before token expiry.
- **The account portal is a thin BFF** — a Redis session cache plus an HTTP proxy to the SSO. It holds
  no database and no key-encryption key; its only persistent state is a few local files.
- **Step-up MFA** (TOTP / passkey) is tiered and enforced server-side per surface; sensitive
  operations demand a fresh sudo window.
- **First-run installers.** Each app boots unconfigured behind a token-locked `/setup` (or `/install`)
  wizard and adopts its configuration in-process — no hand-edited `.env` required.

## Getting started (local dev)

```bash
cp .env.example .env            # or leave it out and let the /setup wizard write it
docker compose up -d postgres redis   # infra
npm install && npm run dev            # SSO on :3000 (tsx watch)
```

Then open the SSO, which boots into its first-run `/setup` wizard (the token is printed to the
console). The account portal (`account/server`, `PORT=4001`) and its own `/setup` wizard follow.
The S2S API schemas (for Cloudflare API Shield) live in [`docs/security/`](docs/security/).
Redis 6.2 or newer is required for atomic authorization-code consumption. The account portal's
public URL must match its browser origin; authenticated writes enforce that origin, including
for binary uploads. When no public URL is set, the registered redirect URI supplies the origin.

## Tests

```bash
npm run typecheck
npm run test:events              # Synthetic role/event and HTTP regressions
npm run test:auth-security       # Resource boundaries, code redemption and BFF regressions
npm run test:events:db           # Disposable local PostgreSQL and Redis integration tests
```

Database tests use the `orbstack` Docker context by default. Set
`DREAMSSO_TEST_DOCKER_CONTEXT` to select another context. The runner creates its
own database and credentials and removes the container afterward. Feature scripts
under `scripts/` may require a separately configured test instance.

## Role synchronization

Relying parties publish persistent, versioned catalog snapshots. Role updates and
their outbound notifications share a PostgreSQL transaction, so delivery can
resume after a worker restart or temporary receiver outage. Retries preserve the
event ID and payload while refreshing the signed envelope.
Receivers acknowledge processed or duplicate batches with exactly `204 No Content`.
Other responses, including `200` HTML from an intermediary, remain retryable failures.

Disabling a client or removing its events endpoint pauses delivery without consuming
retry attempts. Re-enabling a configured client, changing its endpoint, or selecting
**Resync access** in its admin page retries valid sign-outs and publishes current
access state. Previously exhausted sign-outs receive three retry attempts per recovery,
limiting how long a rejected notification can delay newer access updates.
Older role notifications are superseded rather than replayed. Unknown
failed notifications remain visible for investigation. The delivery card shows
queued, paused, failed and delivered counts; a successful resync means work was queued,
not that the receiving application has applied it. An uncertain response can be retried
with the same recovery request ID.

`account.roles_change` carries `sub`, `role_id`, `authority_epoch`,
`authority_revision` and the current `account_status`. Status changes advance the
same authority revision even when the role stays unchanged. The revision is a decimal string; receivers track it per
subject within its epoch. ID tokens carry the corresponding `app_role_epoch` and
`app_role_revision` claims. Signed access-state queries return the same metadata
in response headers without changing the JSON body. See the
[service-to-service API](docs/security/openapi-sso-s2s.yaml).

Initial adoption of versioned catalogs requires the SSO schema first. For the
account-status extension, update receiving applications before enabling the new
publisher. Update client-assertion issuers before enforcing signed operation claims. Preserve
catalog and authority metadata with database backups; a foreign epoch requires
explicit recovery. The migration requests a fresh catalog and republishes current
roles during reconciliation. It does not reconstruct previously lost history.
After receivers adopt versioned authority, rolling back the SSO alone can prevent
sign-in; coordinate rollback across the identity provider and its relying parties.

## Session revocation and client assertions

Session deletion and its logout outbox entries commit together. Receivers acknowledge
logout only after effects complete and retain terminal SSO-session markers, so a late
callback cannot reopen a revoked session. Normal local-session replacement remains
separate. These revocation records belong with the application's session state in backups.

Current-session step-up and retention parameters must match the authenticated
access token's SSO session ID. A different session owned by the same account cannot
supply its proof or be substituted as the current session. Explicitly targeted session
administration remains separate from this check.

Client assertions include `iss = sub = client_id`, integral `iat` and `exp` within a
120-second lifetime, a fresh `jti`, and signed `method` / `path` claims matching the
request. Existing issuer or token-endpoint audiences remain supported. A nonce is
single-use across authentication endpoints; callers create a new assertion for each
attempt. Key or replay-storage failures return an unavailable response rather than
accepting the request.

## Security

Secrets (`.env`, private keys, certs, client keys, installer tokens) and real user data
(`users.ndjson`, DB dumps) are git-ignored and must never be committed. Report anything sensitive that
slips through by rotating the affected secret first.
