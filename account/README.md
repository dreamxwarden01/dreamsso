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

## Invitations

Organization → Invitations supports direct email invitations and shareable links or
codes, with an offered role, optional email and a note of up to 60 characters.
The default validity is 72 hours, with 24-hour, 3-day and 7-day presets.
An optional creation email is fixed; an unbound invitation binds to the address
used for its first accepted registration-email request. The form displays a bound address
as read-only, and the SSO rejects a different address.

Invitations are single-use. Resends keep the original expiry; revoked, expired or
ineligible invitations cannot finish registration. Deleting the offered role or
removing the creator's invitation authority invalidates unused invitations without
changing completed accounts. All, Current and History views retain records, with
server-side search, sorting and 10/25/100-row pages.

Mail status is independent: **Queued**, **Sending**, **Sent** (provider accepted),
**Failed** or **Unknown**. Retrying an uncertain request uses the same request ID;
an explicit resend is a new operation. The share link contains the invitation code;
the mailbox-verification link is sent only to the bound address. Opening a link or
previewing an invitation does not send mail or consume it.

The BFF gates anonymous email requests/resends and final sign-up with Turnstile.
Invitation preview and token-gated username checks do not require an extra challenge.
The SSO atomically creates the account, assigns its role and consumes the invitation.
After completion, the browser follows the returned sign-in URL; a confirmed retry
can use normal sign-in without creating another account.
