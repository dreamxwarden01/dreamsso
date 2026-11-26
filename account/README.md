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

Email changes keep the current address active until verification succeeds. Each
account has one current verification request, with a fixed 30-minute deadline;
resending does not extend it. Starting a newer request, cancellation, or changing
the account’s email or security state invalidates earlier links. A successful
confirmation can be retried without applying the change twice.

Organization → Invitations supports direct email invitations and shareable links or
codes, with an offered role, optional email and a note of up to 60 characters.
The default validity is 72 hours, with 24-hour, 3-day and 7-day presets.
An address already registered to an account is rejected before a new invitation
is created or sent. Multiple invitations may target an unregistered address;
they do not reserve it against registration or account email changes.
An optional creation email is fixed; an unbound invitation binds to the address
used for its first accepted registration-email request. A different address is rejected
on that form. The emailed verification link then opens a read-only address field.

Invitations are single-use. Resends keep the original expiry; revoked, expired or
ineligible invitations cannot finish registration. Deleting the offered role or
removing the creator's invitation authority invalidates unused invitations without
changing completed accounts. All, Current and History views retain records, with
server-side search, sorting and 10/25/100-row pages.

Mail status is independent: **Queued**, **Sending**, **Sent** (provider accepted),
**Failed** or **Unknown**. Retrying an uncertain request uses the same request ID;
an explicit resend is a new operation. The share link contains the invitation code;
the mailbox-verification link is sent only to the bound address. Opening a share link
only prefills its code; recipient details are available after email-proof validation.

Registration email requests wait for the provider response. A confirmed send opens
the result page immediately; an unconfirmed request retains its ID for a safe retry.
Turnstile loads alongside the form, independently of input validity. Its completed
widget stays in place while sending, resets after a retryable rejection, and returns
after the resend cooldown.

The first registration form collects an email address. When invitation-only
registration is enabled, it also requires a code; when disabled, supplied codes are
ignored. After human verification, the SSO checks the invitation before validating
the email. There is no separate code-preflight screen.

The BFF gates anonymous email requests/resends and final sign-up with Turnstile.
Email-proof validation and token-gated username checks do not require an extra challenge.
The SSO atomically creates the account, assigns its role and consumes the invitation.
After completion, the browser follows the returned sign-in URL; a confirmed retry
can use normal sign-in without creating another account.
The success screen no longer holds a button for two seconds before navigating.
SSO tolerates a repeated welcome hop only with the same already-authenticated
session and a short-lived, session-bound receipt; genuinely unusable links are
still rejected.

Invitation and registration emails use distinct subjects and actions. Their short
validity hint is relative to sending time, with the remaining lifetime recalculated
on resend. It is an approximation for the reader, not a change to the strict
server-side expiration. The shared email layout also covers verification, reset
and security notifications, without duplicate footer notices or remote assets.
