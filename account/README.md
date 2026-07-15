# DreamSSO account console (`account-dev.dreamxwarden.ca`)

Self-service identity management for DreamSSO users. **BFF + SPA**: an Express
backend-for-frontend (`server/`) that holds the OIDC tokens server-side and
exposes a thin JSON API, plus a Vite/React SPA (`client/`). The SSO's own
auth/login pages stay server-rendered; only this console is a SPA.

Runs **natively on the host** (like the SSO), behind Caddy:
`https://account-dev.dreamxwarden.ca` → `host.docker.internal:4001`.

## First-time setup

```sh
# 1. Register the `account` OIDC client + mint its private_key_jwt key.
#    (writes server/.account-client-key.json — gitignored)
set -a; source .env; set +a            # PG* for the SSO Postgres
node scripts/seed-account-client.mjs

# 2. Install deps.
npm --prefix account/server install
npm --prefix account/client install

# 3. Build the SPA (the BFF serves client/dist).
npm --prefix account/client run build
```

Add a local DNS record (router or hosts) so `account-dev.dreamxwarden.ca`
resolves to this Mac, then reload Caddy (`docker compose restart caddy`).

## Run (canonical: account-dev via Caddy)

```sh
npm --prefix account/server run dev     # BFF on :4001
npm --prefix account/client run watch    # rebuild dist on change (manual refresh)
```

Open `https://account-dev.dreamxwarden.ca`. Unauthenticated requests bounce
through the SSO and back.

## Run (SPA HMR alternative)

```sh
npm --prefix account/server run dev      # BFF on :4001
npm --prefix account/client run dev      # Vite on :5173, proxies /api + /auth -> :4001
```

Open `http://localhost:5173` (the `localhost:5173/auth/callback` redirect URI is
pre-registered). Cookies are non-secure here (plain http) — handled automatically.

## Layout

- `server/src/oidc.ts` — RP plumbing (PKCE, private_key_jwt, id_token verify, userinfo).
- `server/src/session.ts` — Redis-backed server session (`acct:sess:*`); tokens never reach the browser.
- `server/src/routes/auth.ts` — `/auth/login|callback|error|logout`.
- `server/src/routes/api.ts` — `/api/me`, `PATCH /api/profile` (proxied to the SSO `/account/profile`).
- `client/` — React SPA. IA: Profile / Security / Devices / Organization (admin).

## Status

Profile pane is live (read + edit display_name/email). Security (password + MFA
+ step-up), Devices (sessions), and Organization (org-admin) are stubbed —
next in the SSO build-out. Global SSO logout (`end_session`) lands with the SSO
session milestone; logout is BFF-local for now.
