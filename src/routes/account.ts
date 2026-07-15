import { Router, type Response } from 'express';
import { pool } from '../db.js';
import { requireScope, type AuthedRequest } from '../resourceAuth.js';
import { resolveAuthz, hasPerm, permissionDenied } from '../rbac/index.js';

// Self-service account resource API, protected by the SSO's own access token
// (aud = issuer), the way the account-console BFF calls it on the user's behalf.
// First-party identity management lives here; the videosite profile is read-only.
export const accountRouter = Router();


// GET /account/permissions — the caller's GRANTED permission keys (the client
// treats anything absent as denied). Drives the console's UI gating.
accountRouter.get('/account/permissions', requireScope('profile'), async (req: AuthedRequest, res: Response) => {
  const { granted } = await resolveAuthz(req.auth!.sub);
  res.json({ permissions: [...granted] });
});

// PATCH /account/profile — edit display_name for the caller. Email is NO
// LONGER accepted here: address changes go through the verify-then-commit
// flow (/account/email-change/*) — nothing swaps without a clicked link.
accountRouter.patch('/account/profile', requireScope('profile'), async (req: AuthedRequest, res: Response) => {
  const auth = req.auth!;

  const body = (req.body ?? {}) as { display_name?: unknown; email?: unknown };
  if (body.email !== undefined) {
    return res.status(400).json({ error: 'use_email_change_flow' });
  }

  // Validate the provided fields.
  let displayName: string | undefined;
  if (body.display_name !== undefined) {
    if (typeof body.display_name !== 'string' || !body.display_name.trim()) {
      return res.status(400).json({ error: 'invalid_display_name' });
    }
    displayName = body.display_name.trim();
    if (displayName.length > 100) return res.status(400).json({ error: 'invalid_display_name', error_description: 'too long' });
  }
  if (displayName === undefined) {
    return res.status(400).json({ error: 'no_fields', error_description: 'display_name required' });
  }

  // Current values — to decide whether the email actually changed (resets
  // verification) and which email permission applies (add vs change).
  const { rows: cur } = await pool.query(
    'SELECT display_name, email FROM identities WHERE sub = $1 AND deleted_at IS NULL',
    [auth.sub],
  );
  if (!cur[0]) return res.status(404).json({ error: 'not_found' });

  // Per-field self-service permission gating (RBAC profile.* keys).
  if (!(await hasPerm(auth.sub, 'profile.displayname.change'))) {
    return permissionDenied(res, 'profile.displayname.change');
  }

  const { rows } = await pool.query(
    `UPDATE identities SET display_name = $1 WHERE sub = $2 AND deleted_at IS NULL
     RETURNING sub, username, display_name, email, email_verified`,
    [displayName, auth.sub],
  );
  return res.json({ identity: rows[0] });
});
