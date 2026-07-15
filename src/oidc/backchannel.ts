import { enqueueEvents } from '../events.js';

// Back-channel logout — now an event TYPE on the generic channel (see
// src/events.ts) instead of a bespoke fan-out: enqueued per client, batched
// into the signed envelope, delivered by the pump (2s debounce), retried by
// the 60s sweep. Same signature as the old direct fan-out so every call site
// (logout, devices terminate, password reset revoke-all) is unchanged; the
// scoping rule also is: only the clients the session actually touched.
export async function fanOutLogout(sub: string, sid: string, clients: string[]): Promise<void> {
  await Promise.allSettled(
    clients.map((c) => enqueueEvents(c, [{ type: 'logout', payload: { sub, sid } }])),
  );
}
