import { Router, type Response } from 'express';
import argon2 from 'argon2';
import { pool } from '../db.js';
import { redis } from '../redis.js';
import { requireScope, type AuthedRequest } from '../resourceAuth.js';
import { getStepupValidityMinutes, stampStepup, type StepupMethod } from '../oidc/sessions.js';
import { acceptedStepupMethods, type StepupMode } from '../oidc/stepupPolicy.js';
import { getSetting } from '../settings.js';
import { verifyLoginTotp } from '../mfa.js';
import { countPasskeys, loginAuthOptions, verifyLoginAssertion } from '../webauthn.js';
import { issueEmailOtp, verifyEmailOtp, maskEmail, otpValidityMinutes } from '../emailOtp.js';
import { sendEmail } from '../email.js';
import { renderOtpEmail } from '../emailTemplates.js';

// Step-up (sudo window) resource API — consumed by the account portal through
// the BFF (which supplies the caller's master-session `sid`). Solving a challenge
// STAMPS the session (`stepup_at` + `stepup_method`); the ceremony itself is
// ephemeral (Redis). The TIERED model: verify proves ANY factor and records which
// one; each protected scenario's gate decides whether that method is enough (org
// and admin accept passkey/totp only; the personal-security pages fall back to
// email/password). So verify is method-generic; the accepted set is the gate's job.
export const stepupRouter = Router();
const scoped = requireScope('profile');

const PK_KEY = (sid: string) => `stepup:pk:${sid}`;
// Failure limiter keyed by USER (not sid — else a fresh login would reset it):
// at most MAX_FAILS failed step-up attempts per FAIL_WINDOW seconds, the window
// FIXED from the first failure (no refresh) so it can't be extended, auto-resetting
// when it lapses. Counts FAILURES only; cleared on a successful verify.
const FAIL_KEY = (sub: string) => `stepup:fail:${sub}`;
const CHALLENGE_TTL = 600; // passkey-challenge lifetime (PK_KEY), matching the login txn
const MAX_FAILS = 5;
const FAIL_WINDOW = 120; // seconds
const STEPUP_OTP_PURPOSE = 'stepup'; // isolates the step-up email OTP from login/email-change codes
const siteName = async () => (await getSetting('site_name', 'DreamSSO'))!;

const modeOf = (q: unknown): StepupMode =>
  q === 'fallback' ? 'fallback' : q === 'email-change' ? 'email-change' : 'strong-mandatory';

// The sid comes from the BFF, not the access token — verify it's a live session
// belonging to the token's subject before doing anything with it.
async function ownSession(req: AuthedRequest, sid: string) {
  if (!/^[0-9a-f-]{36}$/i.test(sid)) return null;
  const { rows: [row] } = await pool.query<{ user_sub: string; stepup_at: Date | null; stepup_method: string | null }>(
    'SELECT user_sub, stepup_at, stepup_method FROM sessions WHERE sid = $1',
    [sid],
  );
  return row && row.user_sub === req.auth!.sub ? row : null;
}

// GET /account/stepup/status?sid=&mode= — everything the portal gate/modal needs.
// `mode` picks the acceptance rule: strong-mandatory (org/admin, default) vs
// fallback (personal security). `verified` = fresh AND the recorded method is in
// the mode's accepted set, so a below-bar login (e.g. password-only) reports
// unverified and the client challenges for the right tier.
stepupRouter.get('/account/stepup/status', scoped, async (req: AuthedRequest, res: Response) => {
  const sid = String(req.query.sid ?? '');
  const session = await ownSession(req, sid);
  if (!session) return res.status(404).json({ error: 'not_found' });

  const [required, minutes, acc] = await Promise.all([
    getSetting('stepup_portal_required', 'false'), // off by default — an admin turns it on
    getStepupValidityMinutes(),
    acceptedStepupMethods(req.auth!.sub, modeOf(req.query.mode)),
  ]);
  const stampMs = session.stepup_at ? new Date(session.stepup_at).getTime() : null;
  const fresh = stampMs != null && Date.now() - stampMs < minutes * 60_000;
  const methodOk = session.stepup_method != null && acc.accepted.includes(session.stepup_method);
  const verified = fresh && methodOk;
  const expiresAt = verified ? new Date(stampMs! + minutes * 60_000) : null;
  res.json({
    required: required === 'true',
    verified,
    expires_at: expiresAt ? expiresAt.toISOString() : null,
    // Raw stamp age — the factor-management pages apply a stricter 10-minute
    // reuse cap client-side (challenge on entry when <3 min of it remain).
    age_seconds: stampMs ? Math.floor((Date.now() - stampMs) / 1000) : null,
    methods: acc.accepted,
    enroll_required: acc.enroll_required,
    masked_email: acc.masked_email ?? null,
  });
});

// POST /account/stepup/passkey-options { sid } — assertion options; the challenge
// lives in Redis keyed by sid (reused across sheet-reopens, consumed per attempt).
stepupRouter.post('/account/stepup/passkey-options', scoped, async (req: AuthedRequest, res: Response) => {
  const sid = String((req.body ?? {}).sid ?? '');
  if (!(await ownSession(req, sid))) return res.status(404).json({ error: 'not_found' });
  if ((await countPasskeys(req.auth!.sub)) === 0) return res.status(422).json({ error: 'no_passkeys' });
  const options = await loginAuthOptions(req.auth!.sub);
  await redis.set(PK_KEY(sid), options.challenge, 'EX', CHALLENGE_TTL);
  res.json(options);
});

// POST /account/stepup/send-email { sid } — issue + mail a step-up OTP (the email
// fallback tier). Only for a VERIFIED address; cooldown/daily caps live in emailOtp.
stepupRouter.post('/account/stepup/send-email', scoped, async (req: AuthedRequest, res: Response) => {
  const sid = String((req.body ?? {}).sid ?? '');
  if (!(await ownSession(req, sid))) return res.status(404).json({ error: 'not_found' });
  const { rows: [id] } = await pool.query<{ email: string | null; email_verified: boolean }>(
    'SELECT email, email_verified FROM identities WHERE sub = $1 AND deleted_at IS NULL',
    [req.auth!.sub],
  );
  if (!id?.email || !id.email_verified) return res.status(422).json({ error: 'no_verified_email' });

  const issued = await issueEmailOtp(req.auth!.sub, STEPUP_OTP_PURPOSE);
  if (!issued.ok) {
    return res.status(429).json({ error: issued.reason, retry_after: issued.retryAfter });
  }
  const sent = await sendEmail({
    to: id.email,
    ...renderOtpEmail({ siteName: await siteName(), code: issued.code, minutes: otpValidityMinutes }),
  });
  if (!sent.ok) return res.status(502).json({ error: 'send_failed' });
  res.json({ sent: true, masked_email: maskEmail(id.email), minutes: otpValidityMinutes });
});

// POST /account/stepup/verify { sid, method, code|credential|password } — prove a
// factor and stamp the session's sudo window with WHICH method was proven. 204 on
// success. Verify is method-generic: a user can only stamp a method they can
// actually prove (totp/passkey need the enrolled factor; email needs a verified
// address + issued code; password checks the hash), and the scenario gate decides
// whether that method suffices — so stamping a below-bar method never bypasses.
stepupRouter.post('/account/stepup/verify', scoped, async (req: AuthedRequest, res: Response) => {
  const b = (req.body ?? {}) as {
    sid?: unknown; method?: unknown; code?: unknown; credential?: unknown; password?: unknown;
  };
  const sid = String(b.sid ?? '');
  if (!(await ownSession(req, sid))) return res.status(404).json({ error: 'not_found' });

  const sub = req.auth!.sub;
  // Atomic reserve BEFORE verifying — an incr-then-check (NOT get-then-check), so
  // concurrent bursts can't all pass a stale read and run N guesses in one window.
  // The window is fixed from the first reservation (expire only when created); a
  // success clears the whole window, so only non-succeeding attempts accumulate.
  const attempt = await redis.incr(FAIL_KEY(sub));
  if (attempt === 1) await redis.expire(FAIL_KEY(sub), FAIL_WINDOW);
  if (attempt > MAX_FAILS) {
    const ttl = await redis.ttl(FAIL_KEY(sub));
    return res.status(429).json({ error: 'too_many_attempts', retry_after: ttl > 0 ? ttl : FAIL_WINDOW });
  }
  let verified = false;
  let method: StepupMethod | null = null;
  let reason = 'invalid';

  if (b.method === 'totp') {
    method = 'totp';
    verified = await verifyLoginTotp(sub, String(b.code ?? '').trim());
    reason = 'invalid_code';
  } else if (b.method === 'passkey') {
    method = 'passkey';
    // Consume the challenge on ANY attempt; a retry fetches fresh options.
    const challenge = await redis.getdel(PK_KEY(sid));
    if (!challenge) return res.status(422).json({ error: 'challenge_expired' });
    if (typeof b.credential !== 'object' || b.credential === null) {
      return res.status(422).json({ error: 'credential_required' });
    }
    const v = await verifyLoginAssertion(
      b.credential as Parameters<typeof verifyLoginAssertion>[0],
      challenge,
      sub,
    );
    verified = v.ok;
    reason = v.ok ? '' : v.reason;
  } else if (b.method === 'password') {
    method = 'password';
    const { rows: [id] } = await pool.query<{ password_hash: string | null }>(
      'SELECT password_hash FROM identities WHERE sub = $1 AND deleted_at IS NULL',
      [sub],
    );
    if (id?.password_hash) {
      try {
        verified = await argon2.verify(id.password_hash, String(b.password ?? ''));
      } catch {
        verified = false;
      }
    }
    reason = 'invalid_password';
  } else if (b.method === 'email') {
    method = 'email';
    const { rows: [id] } = await pool.query<{ email_verified: boolean }>(
      'SELECT email_verified FROM identities WHERE sub = $1 AND deleted_at IS NULL',
      [sub],
    );
    if (!id?.email_verified) return res.status(422).json({ error: 'no_verified_email' });
    const r = await verifyEmailOtp(sub, STEPUP_OTP_PURPOSE, String(b.code ?? '').trim());
    verified = r.valid;
    reason = 'invalid_code';
  } else {
    return res.status(422).json({ error: 'unsupported_method' });
  }

  // Failure: the slot reserved above stands (counts toward the cap).
  if (!verified) return res.status(403).json({ error: 'verification_failed', detail: reason });

  await stampStepup(sid, method);
  await redis.del(FAIL_KEY(sub), PK_KEY(sid)); // success clears the window
  res.status(204).end();
});
