# Public signing keys

DreamSSO publishes verification keys at `/jwks`. The account portal publishes
client assertion keys at `/.well-known/jwks.json`. Both endpoints accept only
`GET`; other methods, including `HEAD`, return `405` with `Allow: GET` once the
service is configured. Successful JSON responses use
`Cache-Control: public, max-age=120, must-revalidate`. Errors and responses from
an unfinished installation use `Cache-Control: no-store`.

JWKS is public. It contains verification material, never private keys, and must
remain reachable without a session, client certificate or browser challenge.
OpenID discovery has a separate cache policy.

## Scheduling a rotation

The admin action publishes a new key while the existing key continues signing.
The response is `202` with `state: pending`, the current `kid`, and a `rotation`
object containing the pending key ID and its activation window. Repeating the
action while a rotation is pending returns that same operation.

Publication and arming the window are separate durable writes. If a process
stops between them, the next status or signing request recovers the same pending
key and starts a fresh window. The key becomes eligible after five minutes;
the next status or signing request then activates it atomically. An idle service
may activate later. The old public key remains available for 24 hours from the
actual switch, including when another rotation happens during that overlap.

The UI refreshes status with GET. After a timeout or lost response, read status
before trying another schedule; do not automatically replay POST. The account
portal's status operation uses a separately signed GET on
`/internal/rotate-client-key`, whereas POST schedules rotation. Older portal
versions do not support that GET and must be upgraded first.

The overlap covers current first-party signed artifacts: access tokens last up
to 15 minutes, ID tokens 10 minutes, and events/assertions at most two minutes.
It is not a global key-revocation deadline. Verifiers can retain their own key
caches longer than an HTTP response stays fresh.

## Cache and rollout requirements

The five-minute window covers the SSO's 60-second origin cache, 120-second HTTP
freshness, a 30-second unknown-key resolver cooldown, and a margin for requests.
Origin cache age uses a monotonic clock; a failed or excessively delayed read
does not serve an expired cache entry. All signing selections consult current
persistent state; only parsed key objects cache by key ID.

Before enabling rotation:

- Upgrade every serving/writing process to the staged implementation. Mixed old
  writers and rollback to an immediate-rotation build are unsupported.
- Apply the schema migration and inspect any existing `next` key or duplicate
  `current` key first. Ambiguous legacy rows are rejected without destructive
  repair. Back up the database and its matching encryption key.
- Ensure proxy caches respect origin freshness, `Age` and `must-revalidate`;
  do not force longer TTLs or stale responses. Drain or explicitly invalidate
  older cache policies before relying on the five-minute window.
- Keep system/database clocks synchronized. Configure relying parties to use
  the JWKS URL. A pinned inline key set requires separate registration updates.

Account key mutations require a writable, owner-protected directory mount for
`/config`, a regular owner-only key file, and the runtime's `flock` utility.
Single-file bind mounts cannot safely support atomic replacement and are refused
for rotation. Preserve the complete key-state file in backups; it contains the
current identity and any pending operation. Existing file-mode signing continues
before the first explicit schedule.

For Linux development with `tsx`, the worker resolves the installed locked
`tsx` loader from its source module and starts the TypeScript entry point. The
compiled runtime uses the JavaScript worker directly and has no `tsx` dependency.
Both paths require `flock`; native macOS/Windows rotation writes are unsupported.
Public JWKS reads do not invoke `flock`. Signing may request background activation;
a failed activation does not block signing with a valid, freshly read durable
current key. Both paths enforce the same file-permission and key-integrity checks.
