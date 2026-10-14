import { Router } from 'express';
import { decodeJwt, jwtVerify, errors, type JWTVerifyGetKey } from 'jose';
import type { ClientKeyContext } from '../clientKeys.js';
import { EVENT_PATH, eventToken } from './eventForm.js';
import { EventError, assertEnvelopeCurrent, validateIncomingEvents, type EnvelopeTime, type IncomingEvent } from './rolesSync.js';

export interface EventClient { client_id: string; disabled_at: string | Date | null }
export interface EventReceiverDependencies<Client extends EventClient> {
  issuer: () => string;
  loadClient(id: string): Promise<Client | null>;
  keySet(client: Client, context?: ClientKeyContext): JWTVerifyGetKey | null;
  process(clientId: string, time: EnvelopeTime, events: readonly IncomingEvent[]): Promise<void>;
  afterCommit?: () => void;
  now?: () => number;
}

/** Verification never imports runtime configuration or opens a database connection. */
export function createEventReceiver<Client extends EventClient>(deps: EventReceiverDependencies<Client>) {
  const router = Router();
  router.post(EVENT_PATH, async (req, res) => {
    res.set('Cache-Control', 'no-store');
    const token = eventToken(req.body);
    if (!token) return res.status(400).json({ error: 'invalid_event_token' });
    let clientId: string;
    try {
      const untrusted = decodeJwt(token);
      if (typeof untrusted.iss !== 'string' || !untrusted.iss || untrusted.iss.length > 200) throw new Error();
      clientId = untrusted.iss;
    } catch { return res.status(400).json({ error: 'malformed_token' }); }
    let client: Client | null;
    try { client = await deps.loadClient(clientId); }
    catch { return res.status(503).json({ error: 'events_unavailable' }); }
    if (!client || client.disabled_at) return res.status(401).json({ error: 'unknown_client' });
    let keys: JWTVerifyGetKey | null;
    try { keys = deps.keySet(client, { operation: 'events' }); }
    catch { return res.status(503).json({ error: 'events_unavailable' }); }
    if (!keys) return res.status(401).json({ error: 'no_registered_key' });
    let time: EnvelopeTime, events: IncomingEvent[], keyUnavailable = false;
    try {
      const resolveKeys: JWTVerifyGetKey = async (header, flattened) => {
        try { return await keys!(header, flattened); }
        catch (error) {
          if (!(error instanceof errors.JWKSNoMatchingKey) && !(error instanceof errors.JWKSMultipleMatchingKeys)) keyUnavailable = true;
          throw error;
        }
      };
      const { payload } = await jwtVerify(token, resolveKeys, {
        issuer: client.client_id, audience: deps.issuer(), typ: 'events+jwt',
        requiredClaims: ['iss', 'aud', 'iat', 'exp'], clockTolerance: 10, maxTokenAge: '5 minutes',
        currentDate: new Date(deps.now?.() ?? Date.now()),
      });
      time = { iat: payload.iat!, exp: payload.exp! };
      assertEnvelopeCurrent(time, deps.now?.() ?? Date.now());
      events = validateIncomingEvents(payload.events);
    } catch (error) {
      if (error instanceof EventError) return res.status(error.status).json({ error: error.code });
      return res.status(keyUnavailable ? 503 : 401).json({ error: keyUnavailable ? 'events_unavailable' : 'invalid_token' });
    }
    try {
      await deps.process(client.client_id, time, events);
    } catch (error) {
      if (error instanceof EventError) return res.status(error.status).json({ error: error.code });
      // No SQL, signed payload, source-controlled name or remote error text in logs.
      console.warn('events: transaction unavailable');
      return res.status(503).json({ error: 'events_unavailable' });
    }
    try { deps.afterCommit?.(); } catch { /* SQL owns pending delivery; wakeup is optional. */ }
    return res.status(204).end();
  });
  return router;
}
