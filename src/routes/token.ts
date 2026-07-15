import { Router, type Request, type Response } from 'express';
import crypto from 'node:crypto';
import { jwtVerify, createLocalJWKSet, createRemoteJWKSet } from 'jose';
import { pool } from '../db.js';
import { consumeCode } from '../oidc/codes.js';
import { getSessionWindows } from '../oidc/sessions.js';
import { mintIdToken, mintAccessToken } from '../oidc/tokens.js';
import { effectiveAppRole, hasAppCatalog } from '../rbac/appRoles.js';
import { getJwks } from '../keys.js';
import { config } from '../config.js';
import { getSetting } from '../settings.js';

export const tokenRouter = Router();

const s256 = (verifier: string) => crypto.createHash('sha256').update(verifier).digest('base64url');
const fail = (res: Response, status: number, error: string, desc?: string) =>
  res.status(status).json(desc ? { error, error_description: desc } : { error });

// Client-key resolution: jwks_uri (preferred in prod — rotation without re-registration)
// falls back to inline jwks. Remote sets are cached per (client, url); jose handles
// HTTP caching/cooldown internally, and a changed jwks_uri gets a fresh instance.
const remoteJwks = new Map<string, ReturnType<typeof createRemoteJWKSet>>();
// Exported: the password-reset internal API authenticates the account portal
// with the same private_key_jwt assertion + key resolution.
export function clientKeySet(client: { client_id: string; jwks_uri: string | null; jwks: Parameters<typeof createLocalJWKSet>[0] | null }) {
  if (client.jwks_uri) {
    const cacheKey = `${client.client_id}|${client.jwks_uri}`;
    let set = remoteJwks.get(cacheKey);
    if (!set) {
      set = createRemoteJWKSet(new URL(client.jwks_uri), { timeoutDuration: 3000 });
      remoteJwks.set(cacheKey, set);
    }
    return set;
  }
  if (client.jwks) return createLocalJWKSet(client.jwks);
  return null;
}

tokenRouter.post('/token', async (req: Request, res: Response) => {
  res.setHeader('Cache-Control', 'no-store');
  const b = (req.body ?? {}) as Record<string, string>;
  if (b.grant_type !== 'authorization_code') return fail(res, 400, 'unsupported_grant_type');

  // --- client authentication: private_key_jwt (RFC 7523) ---
  if (
    b.client_assertion_type !== 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer' ||
    !b.client_assertion
  ) {
    return fail(res, 401, 'invalid_client', 'private_key_jwt required');
  }
  let claimedClient: string;
  try {
    claimedClient = JSON.parse(Buffer.from(b.client_assertion.split('.')[1], 'base64url').toString()).iss;
  } catch {
    return fail(res, 401, 'invalid_client', 'malformed assertion');
  }
  const { rows } = await pool.query(
    'SELECT client_id, jwks, jwks_uri, disabled_at FROM oauth_clients WHERE client_id = $1',
    [claimedClient],
  );
  const client = rows[0];
  if (!client) return fail(res, 401, 'invalid_client', 'unknown client');
  if (client.disabled_at) return fail(res, 401, 'invalid_client', 'client disabled');
  const keySet = clientKeySet(client);
  if (!keySet) return fail(res, 401, 'invalid_client', 'no registered key');
  try {
    await jwtVerify(b.client_assertion, keySet, {
      issuer: client.client_id,
      subject: client.client_id,
      audience: [config.issuer, `${config.issuer}/token`],
    });
  } catch {
    return fail(res, 401, 'invalid_client', 'assertion verification failed');
  }

  // --- redeem the authorization code (single use) ---
  const ac = await consumeCode(b.code ?? '');
  if (!ac) return fail(res, 400, 'invalid_grant', 'code invalid or expired');
  if (ac.clientId !== client.client_id) return fail(res, 400, 'invalid_grant', 'client mismatch');
  if (ac.redirectUri !== b.redirect_uri) return fail(res, 400, 'invalid_grant', 'redirect_uri mismatch');

  // --- PKCE ---
  if (!b.code_verifier || s256(b.code_verifier) !== ac.codeChallenge) {
    return fail(res, 400, 'invalid_grant', 'PKCE verification failed');
  }

  // --- claims by scope ---
  const scopes = ac.scope.split(' ');
  const extra: Record<string, unknown> = {};
  if (scopes.includes('profile') || scopes.includes('email')) {
    const { rows: [id] } = await pool.query(
      'SELECT username, display_name, email, email_verified, avatar FROM identities WHERE sub = $1',
      [ac.userSub],
    );
    if (id) {
      if (scopes.includes('profile')) {
        extra.name = id.display_name;
        extra.preferred_username = id.username;
        // picture = the avatar FILE NAME (not a URL): each app serves its own
        // session-gated copy and fetches the bytes S2S when the name changes.
        if (id.avatar) extra.picture = id.avatar;
      }
      if (scopes.includes('email')) { extra.email = id.email; extra.email_verified = id.email_verified; }
    }
  }
  // Org name handover: every app learns the SSO's site_name at login and keeps
  // it fresh via the org.settings event.
  extra.site_name = (await getSetting('site_name', 'DreamSSO'))!;

  // Record that this client redeemed a code under the session (append-if-absent).
  // Drives the Devices pane's apps-accessed list and scopes back-channel logout
  // fan-out to apps actually used. Best-effort: log, don't fail the token response.
  if (ac.sid) {
    pool
      .query(
        `UPDATE sessions SET clients = array_append(clients, $2)
           WHERE sid = $1 AND NOT ($2 = ANY(clients))`,
        [ac.sid, client.client_id],
      )
      .catch((e) => console.warn('session_clients upsert failed:', (e as Error).message));

    // Tell the RP how durable the SSO session behind this login is: persistence
    // (KMSI answer) + the absolute expiry under the applicable window. RPs issue
    // a session cookie for transient, an expiring cookie capped at
    // min(own window, sess_exp) for persistent — RP sessions never outlive ours.
    const { rows: [sess] } = await pool.query<{ persistent: boolean; created_at: string }>(
      'SELECT persistent, EXTRACT(EPOCH FROM created_at)::bigint AS created_at FROM sessions WHERE sid = $1',
      [ac.sid],
    );
    if (sess) {
      const { maxHours, transientMaxHours } = await getSessionWindows();
      extra.sess_persistent = sess.persistent;
      extra.sess_exp = Number(sess.created_at) + (sess.persistent ? maxHours : transientMaxHours) * 3600;
    }
  }

  // The SSO defines the app role AT LOGIN (user decision): catalog clients get
  // the caller's effective role in the id_token — `app_role` carries the APP'S
  // OWN role_id (the ids it reported in roles.sync). The RP applies it at the
  // callback like an event report: update + cache purge when it differs.
  // Absent for catalog-less clients (the account portal has no role model).
  if (await hasAppCatalog(client.client_id)) {
    const eff = await effectiveAppRole(ac.userSub, client.client_id);
    if (eff.role_id != null) extra.app_role = eff.role_id;
  }

  const id_token = await mintIdToken({
    sub: ac.userSub, clientId: client.client_id, nonce: ac.nonce, acr: ac.acr, amr: ac.amr, authTime: ac.authTime, sid: ac.sid, extra,
  });
  const access_token = await mintAccessToken({ sub: ac.userSub, clientId: client.client_id, scope: ac.scope });
  res.json({ access_token, token_type: 'Bearer', expires_in: 900, id_token, scope: ac.scope });
});

tokenRouter.get('/userinfo', async (req: Request, res: Response) => {
  res.setHeader('Cache-Control', 'no-store');
  const m = /^Bearer (.+)$/.exec(req.headers.authorization ?? '');
  if (!m) return res.status(401).set('WWW-Authenticate', 'Bearer').json({ error: 'invalid_token' });
  try {
    const jwks = createLocalJWKSet(await getJwks());
    const { payload } = await jwtVerify(m[1], jwks, { issuer: config.issuer, audience: config.issuer });
    const { rows: [id] } = await pool.query(
      'SELECT sub, username, display_name, email, email_verified, avatar FROM identities WHERE sub = $1',
      [payload.sub],
    );
    if (!id) return res.status(401).set('WWW-Authenticate', 'Bearer error="invalid_token"').json({ error: 'invalid_token' });
    const scopes = String(payload.scope ?? '').split(' ');
    const out: Record<string, unknown> = { sub: id.sub };
    if (scopes.includes('profile')) { out.name = id.display_name; out.preferred_username = id.username; if (id.avatar) out.picture = id.avatar; }
    if (scopes.includes('email')) { out.email = id.email; out.email_verified = id.email_verified; }
    res.json(out);
  } catch {
    res.status(401).set('WWW-Authenticate', 'Bearer error="invalid_token"').json({ error: 'invalid_token' });
  }
});
