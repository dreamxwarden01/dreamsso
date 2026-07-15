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
- **The SSO owns identity; relying parties own authorization.** Each RP keeps its own roles and
  re-checks them; the SSO federates *who you are*, not *what you can do* in each app.
- **Registration is `jwks_uri`, never a key handoff.** Each RP (and the portal BFF) self-mints an
  Ed25519 client key and serves the public half at `/.well-known/jwks.json`; the SSO stores only the
  URL and fetches it lazily. Client-key rotation needs no re-registration.
- **Two-key auth split.** The RP/BFF private key does client authentication (`private_key_jwt`) and
  the signed back-channel event envelope; a separate per-user access token authorizes the portal's
  `/account/*` resource API. They are never collapsed.
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

## Tests

```bash
npm test                        # SSO installer + mTLS suites
node scripts/sso-org-admin-test.ts     # org-management / RBAC guard matrix
# …plus the per-feature suites in scripts/ (reset, registration, email-change, step-up, …)
```

## Security

Secrets (`.env`, private keys, certs, client keys, installer tokens) and real user data
(`users.ndjson`, DB dumps) are git-ignored and must never be committed. Report anything sensitive that
slips through by rotating the affected secret first.
