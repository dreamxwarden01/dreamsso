import { Router, type Request, type Response } from 'express';
import { config } from '../config.js';
import { mintAccessToken } from '../oidc/tokens.js';
import { loadSessionBySid } from '../oidc/sessions.js';
import { isPortalAssertion } from './reset.js';

// Session-bound access-token renewal for the account portal's BFF. The BFF's
// tokens live 15 minutes; instead of bouncing the SPA through /authorize every
// expiry, the BFF presents its client assertion + the user's master-session
// sid and gets a fresh token — the LIVE SSO SESSION is the refresh credential.
// Logout/termination/suspension all kill the session row, so renewal dies with
// it (no separate refresh-token lifetime to reconcile). Portal-only by design:
// other RPs run their own sessions and don't hold long-lived bearer tokens.
export const portalTokenRouter = Router();

portalTokenRouter.post('/internal/token/renew', async (req: Request, res: Response) => {
  const body = (req.body ?? {}) as Record<string, unknown>;
  if (!(await isPortalAssertion(body))) return res.status(401).json({ error: 'invalid_client' });

  const sid = typeof body.sid === 'string' ? body.sid : '';
  const sub = typeof body.sub === 'string' ? body.sub : '';
  if (!sid || !sub) return res.status(400).json({ error: 'invalid_request' });

  // Full liveness check (idle + absolute windows, identity active) — and the
  // sid must belong to the sub the BFF thinks it's renewing for.
  const sess = await loadSessionBySid(sid);
  if (!sess || sess.userSub !== sub) return res.status(401).json({ error: 'session_gone' });

  const access_token = await mintAccessToken({
    sub, clientId: config.accountClientId, scope: 'openid profile email',
  });
  res.json({ access_token, token_type: 'Bearer', expires_in: 900 });
});
