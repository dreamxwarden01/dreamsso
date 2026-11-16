import { Router } from 'express';
import { jwtVerify, createRemoteJWKSet } from 'jose';
import { config } from '../config.js';
import { redis } from '../redis.js';
import { revokeBySsoSid } from '../session.js';

// Generic back-channel event receiver (SSO -> this RP): POST /backchannel/events
// with a signed envelope {iss=SSO, aud=our client_id, iat, jti, events:[{id,
// type, payload}...]}. Logout is now an event TYPE on this channel (was the
// bespoke OIDC logout token). At-least-once safe: per-event dedupe by id;
// unknown types are ACKED so the SSO can add types without wedging us.
export const backchannelRouter = Router();

let _jwks: ReturnType<typeof createRemoteJWKSet> | undefined;
const jwks = () => (_jwks ??= createRemoteJWKSet(new URL(config.internal + '/jwks')));

const SEEN_TTL = 7 * 24 * 3600;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

backchannelRouter.post('/backchannel/events', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  const token = (req.body ?? {}).event_token;
  if (typeof token !== 'string') {
    res.status(400).json({ error: 'missing_event_token' });
    return;
  }
  let payload;
  try {
    ({ payload } = await jwtVerify(token, jwks(), {
      issuer: config.issuer,
      audience: config.clientId,
      clockTolerance: 10,
      maxTokenAge: '5 minutes',
    }));
  } catch {
    res.status(401).json({ error: 'invalid_token' });
    return;
  }
  const events = payload.events;
  if (!Array.isArray(events) || events.length === 0 || events.length > 100) {
    res.status(400).json({ error: 'invalid_events' });
    return;
  }
  // Validate the entire logout batch before any member has effects.
  for (const raw of events) {
    if (!raw || typeof raw !== 'object' || typeof raw.id !== 'string' || !raw.id) {
      res.status(400).json({ error: 'invalid_event_id' }); return;
    }
    if (raw.type === 'logout' && (!UUID.test(raw.id) || typeof raw.payload?.sid !== 'string'
      || !UUID.test(raw.payload.sid) || typeof raw.payload?.sub !== 'string' || !UUID.test(raw.payload.sub))) {
      res.status(400).json({ error: 'invalid_logout_event' }); return;
    }
  }

  for (const raw of events as { id?: unknown; type?: unknown; payload?: unknown }[]) {
    const id = typeof raw.id === 'string' ? raw.id : null;
    const type = typeof raw.type === 'string' ? raw.type : '';
    if (!id) {
      res.status(400).json({ error: 'invalid_event_id' });
      return;
    }
    try {
      // Pre-effect seen keys from earlier releases are not proof of completion.
      // A duplicate repeats the idempotent effect until one delivery completes;
      // it must not acknowledge simply because another delivery is in progress.
      const completed = `evt:completed:v2:${UUID.test(id) ? id.toLowerCase() : id}`;
      if (await redis.get(completed)) continue;
      if (type === 'logout') {
        const p = raw.payload as { sid: string; sub: string };
        await revokeBySsoSid(p.sid, p.sub);
      } else {
        console.log(`events: acked unknown type '${type}'`);
      }
      await redis.set(completed, '1', 'EX', SEEN_TTL);
    } catch (e) {
      console.error(`events: ${type} failed:`, (e as Error).message);
      res.status(500).json({ error: 'processing_failed' });
      return;
    }
  }
  res.status(204).end();
});
