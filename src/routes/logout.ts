import crypto from 'node:crypto';
import { Router, type Request, type Response } from 'express';
import { pool } from '../db.js';
import { loadSession, SESSION_COOKIE } from '../oidc/sessions.js';
import { fanOutLogout } from '../oidc/backchannel.js';
import { renderSignedOutPage } from '../views.js';
import { getSetting } from '../settings.js';

// RP-initiated (front-channel) logout — the end_session_endpoint. Ends THIS
// browser's master session (identified by the cookie), back-channel fans out to
// the other apps, then shows a terminal confirmation. post_logout_redirect_uri
// is accepted per spec but intentionally NOT honored (the confirmation page is
// the terminal state — see the sessions/logout design).
export const logoutRouter = Router();

logoutRouter.get('/logout', async (req: Request, res: Response) => {
  const session = await loadSession(req);
  res.clearCookie(SESSION_COOKIE, { path: '/' });
  if (session) {
    // Delete-and-capture: grab the session's app set in the same statement that
    // removes the row, then fan out only to those apps (see fanOutLogout).
    const { rows } = await pool.query<{ clients: string[] }>(
      'DELETE FROM sessions WHERE sid = $1 RETURNING clients',
      [session.sid],
    );
    await fanOutLogout(session.userSub, session.sid, rows[0]?.clients ?? []);
  }
  const nonce = crypto.randomBytes(16).toString('base64');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader(
    'Content-Security-Policy',
    `default-src 'none'; style-src 'nonce-${nonce}'; base-uri 'none'; frame-ancestors 'none'`,
  );
  res.status(200).type('html').send(renderSignedOutPage(nonce, (await getSetting('site_name', 'DreamSSO'))!));
});
