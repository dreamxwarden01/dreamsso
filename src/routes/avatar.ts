import { Router, raw, type Request, type Response } from 'express';
import { jwtVerify } from 'jose';
import { pool } from '../db.js';
import { config } from '../config.js';
import { requireScope, type AuthedRequest } from '../resourceAuth.js';
import { requirePerm } from '../rbac/index.js';
import { clientKeySet } from './token.js';
import { enqueueEvents } from '../events.js';
import {
  processAndStoreAvatar, readAvatar, deleteAvatarFile, MAX_AVATAR_BYTES,
} from '../avatars.js';

// Profile pictures.
//   POST   /account/avatar   raw image bytes -> processed, stored, identities.avatar updated
//   DELETE /account/avatar   remove the picture
//   GET    /avatar/:file     capability URL (the random suffix IS the secret) —
//                            used by the SSO's own pages (KMSI/step-up chips),
//                            where no session exists yet mid-login
//   POST   /internal/avatar  S2S fetch for app backends (client assertion) —
//                            apps cache the file locally and serve it to their
//                            clients session-gated
export const avatarRouter = Router();
const scoped = requireScope('profile');

// Fan the change out to every event-connected app; the portal reads the DB and
// local files directly (its backchannel ignores this type). Exported for the
// org-management remove action (org.ts), which must announce the same way.
export function pushAvatarChange(sub: string, avatar: string | null): void {
  pool
    .query(
      `SELECT client_id FROM oauth_clients
        WHERE events_uri IS NOT NULL AND disabled_at IS NULL AND client_id <> $1`,
      [config.accountClientId],
    )
    .then(({ rows }) => {
      for (const r of rows) {
        enqueueEvents(r.client_id, [{ type: 'account.profile_change', payload: { sub, avatar } }])
          .catch((e) => console.warn('profile_change enqueue failed:', (e as Error).message));
      }
    })
    .catch((e) => console.warn('profile_change fanout failed:', (e as Error).message));
}

avatarRouter.post(
  '/account/avatar',
  raw({ type: ['image/png', 'image/jpeg', 'image/webp'], limit: MAX_AVATAR_BYTES }),
  scoped,
  requirePerm('profile.picture.set'),
  async (req: AuthedRequest, res: Response) => {
    const sub = req.auth!.sub;
    if (!Buffer.isBuffer(req.body) || req.body.length === 0) {
      return res.status(422).json({ error: 'unprocessable_image' });
    }
    const r = await processAndStoreAvatar(sub, req.body);
    if ('error' in r) return res.status(422).json({ error: r.error });

    const { rows: [cur] } = await pool.query<{ avatar: string | null }>(
      'SELECT avatar FROM identities WHERE sub = $1 AND deleted_at IS NULL',
      [sub],
    );
    if (!cur) {
      await deleteAvatarFile(r.file);
      return res.status(404).json({ error: 'not_found' });
    }
    await pool.query('UPDATE identities SET avatar = $2 WHERE sub = $1', [sub, r.file]);
    await deleteAvatarFile(cur.avatar);
    pushAvatarChange(sub, r.file);
    res.json({ avatar: r.file, size: r.size });
  },
);

avatarRouter.delete('/account/avatar', scoped, requirePerm('profile.picture.set'), async (req: AuthedRequest, res: Response) => {
  const sub = req.auth!.sub;
  const { rows: [cur] } = await pool.query<{ avatar: string | null }>(
    'SELECT avatar FROM identities WHERE sub = $1 AND deleted_at IS NULL',
    [sub],
  );
  if (!cur) return res.status(404).json({ error: 'not_found' });
  if (cur.avatar) {
    await pool.query('UPDATE identities SET avatar = NULL WHERE sub = $1', [sub]);
    await deleteAvatarFile(cur.avatar);
    pushAvatarChange(sub, null);
  }
  res.status(204).end();
});

avatarRouter.get('/avatar/:file', async (req: Request, res: Response) => {
  const buf = await readAvatar(String(req.params.file));
  if (!buf) return res.status(404).json({ error: 'not_found' });
  // The name changes with the content, so a year of immutable is safe; private
  // keeps shared caches out of it.
  res.setHeader('Cache-Control', 'private, max-age=31536000, immutable');
  res.type('image/webp').send(buf);
});

// Generic client-assertion check (any enabled client, not just the portal):
// the assertion's iss names the client; verified against its registered keys.
async function assertedClient(body: Record<string, unknown>): Promise<string | null> {
  if (
    body.client_assertion_type !== 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer' ||
    typeof body.client_assertion !== 'string'
  ) {
    return null;
  }
  let iss = '';
  try {
    iss = String(JSON.parse(Buffer.from(body.client_assertion.split('.')[1], 'base64url').toString()).iss ?? '');
  } catch {
    return null;
  }
  if (!iss) return null;
  const { rows } = await pool.query(
    'SELECT client_id, jwks, jwks_uri, disabled_at FROM oauth_clients WHERE client_id = $1',
    [iss],
  );
  const client = rows[0];
  if (!client || client.disabled_at) return null;
  const keySet = clientKeySet(client);
  if (!keySet) return null;
  try {
    await jwtVerify(body.client_assertion, keySet, {
      issuer: client.client_id,
      subject: client.client_id,
      audience: [config.issuer, `${config.issuer}/token`],
    });
    return client.client_id;
  } catch {
    return null;
  }
}

avatarRouter.post('/internal/avatar', async (req: Request, res: Response) => {
  const body = (req.body ?? {}) as Record<string, unknown>;
  if (!(await assertedClient(body))) return res.status(401).json({ error: 'invalid_client' });
  const buf = await readAvatar(String(body.file ?? ''));
  if (!buf) return res.status(404).json({ error: 'not_found' });
  res.setHeader('Cache-Control', 'no-store'); // apps persist it themselves
  res.type('image/webp').send(buf);
});
