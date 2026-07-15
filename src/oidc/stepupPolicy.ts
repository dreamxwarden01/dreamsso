import { pool } from '../db.js';
import { countPasskeys } from '../webauthn.js';
import { countAuthenticators } from '../mfa.js';
import { maskEmail } from '../emailOtp.js';

// The tiered step-up policy — ONE place that decides which methods a scenario
// will accept for a given user, so the enforcement gates, the /status probe, and
// the challenge modal all agree. Strength order: passkey > totp > email > password.
export type StepupMode = 'strong-mandatory' | 'fallback' | 'email-change';

export interface AcceptedStepup {
  accepted: string[]; // methods the scenario will take, priority order (the modal opens on accepted[0])
  enroll_required: boolean; // true = owns none of the required factors (strong-mandatory with no strong factor)
  masked_email?: string; // present iff 'email' is an accepted method
}

// Compute the accepted set for `sub`:
// - strong-mandatory (org endpoints, SSO admin console): passkey if the user owns
//   one, ELSE totp if owned, ELSE none -> enroll. Passkey PREEMPTS totp (own both
//   => passkey only, no switch, no downgrade); there is NEVER a weak fallback.
// - fallback (personal security: factor management, password change, MFA toggle):
//   the owned strong factors {passkey,totp} if any (both => switchable); ELSE a
//   SINGLE fallback — email only when the MFA toggle is ON and the address is
//   verified, otherwise password (the floor, always available).
export async function acceptedStepupMethods(sub: string, mode: StepupMode): Promise<AcceptedStepup> {
  const [passkeys, totp] = await Promise.all([countPasskeys(sub), countAuthenticators(sub)]);

  if (mode === 'strong-mandatory') {
    const accepted = passkeys > 0 ? ['passkey'] : totp > 0 ? ['totp'] : [];
    return { accepted, enroll_required: accepted.length === 0 };
  }

  const strong: string[] = [];
  if (passkeys > 0) strong.push('passkey');
  if (totp > 0) strong.push('totp');
  if (strong.length) return { accepted: strong, enroll_required: false };

  // No strong factor -> a single fallback: EMAIL (an OTP to the current address)
  // else PASSWORD. Whether email counts differs by scenario:
  //  - fallback (factor mgmt / password change): email only when the MFA toggle is
  //    ON and verified ("email isn't a factor when MFA is off").
  //  - email-change: email whenever the CURRENT address is verified, regardless of
  //    the toggle — the OTP to the current inbox proves control before it's
  //    replaced, so a password-only compromise can't take over the recovery channel.
  const { rows: [id] } = await pool.query<{ mfa_enabled: boolean; email_verified: boolean; email: string | null }>(
    'SELECT mfa_enabled, email_verified, email FROM identities WHERE sub = $1 AND deleted_at IS NULL',
    [sub],
  );
  const emailOk = !!id?.email && id.email_verified && (mode === 'email-change' || id.mfa_enabled);
  if (emailOk) {
    return { accepted: ['email'], enroll_required: false, masked_email: maskEmail(id!.email!) };
  }
  return { accepted: ['password'], enroll_required: false };
}

// A session's recorded step-up satisfies a scenario iff it is fresh AND its method
// is in the accepted set. A null/unknown method never satisfies — the safe default
// that forces one re-verification (e.g. legacy rows, or a login below the bar).
export function stepupSatisfies(accepted: string[], method: string | null, fresh: boolean): boolean {
  return fresh && method != null && accepted.includes(method);
}
