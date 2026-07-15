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

  for (const raw of events as { id?: unknown; type?: unknown; payload?: unknown }[]) {
    const id = typeof raw.id === 'string' ? raw.id : null;
    const type = typeof raw.type === 'string' ? raw.type : '';
    if (!id) {
      res.status(400).json({ error: 'invalid_event_id' });
      return;
    }
    const fresh = await redis.set(`evt:seen:${id}`, '1', 'EX', SEEN_TTL, 'NX');
    if (!fresh) continue; // already processed (retry redelivery)

    try {
      if (type === 'logout') {
        const p = (raw.payload ?? {}) as { sid?: unknown };
        if (typeof p.sid === 'string') await revokeBySsoSid(p.sid);
      } else {
        console.log(`events: acked unknown type '${type}'`);
      }
    } catch (e) {
      console.error(`events: ${type} failed:`, (e as Error).message);
      await redis.del(`evt:seen:${id}`).catch(() => { /* let the retry reprocess */ });
      res.status(500).json({ error: 'processing_failed' });
      return;
    }
  }
  res.status(204).end();
});
