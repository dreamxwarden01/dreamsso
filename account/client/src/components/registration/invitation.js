export const INVITATION_CODE_RE = /^[A-Z0-9]{12}$/;
export const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
export const emailValid = (value) => EMAIL_RE.test(value) && value.length <= 254;
export const normalizeCode = (value) => value.toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 12);

export function invitationStatus(invitation, now = Date.now()) {
  if (!invitation) return null;
  if (['used', 'expired', 'revoked', 'unavailable'].includes(invitation.status)) return invitation.status;
  if (invitation.status !== 'unused') return 'unavailable';
  const expiry = Date.parse(invitation.expires_at);
  if (!Number.isFinite(expiry)) return 'unavailable';
  return now >= expiry ? 'expired' : 'unused';
}

export function formatInvitationTime(value) {
  const at = new Date(value);
  if (!value || !Number.isFinite(at.getTime())) return 'Deadline unavailable';
  const parts = new Intl.DateTimeFormat('en-US', { year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', hour12: true, timeZoneName: 'short' }).formatToParts(at);
  const part = (type) => parts.find((item) => item.type === type)?.value || '';
  return `${part('year')}/${part('month')}/${part('day')} ${part('hour')}:${part('minute')} ${part('dayPeriod')} ${part('timeZoneName')}`;
}

export function invitationErrorStatus(error) {
  const status = error?.data?.invitation?.status;
  if (['used', 'expired', 'revoked', 'unavailable'].includes(status)) return status;
  return ({ invitation_expired: 'expired', invitation_used: 'used', invitation_revoked: 'revoked',
    invitation_unavailable: 'unavailable', invitation_gone: 'unavailable', already_used: 'used',
    invalid_invitation: 'invalid' })[error?.code] || null;
}

export function registrationMessage(error) {
  if (['email_bound', 'email_mismatch'].includes(error?.code)) return 'This invitation is reserved for its bound address. The recipient cannot be changed.';
  if (error?.code === 'turnstile_failed') return 'Human verification failed. Please try again.';
  if (error?.code === 'registration_closed') return 'Registration is currently closed.';
  if (error?.code === 'send_failed') return 'We could not send the email. Please try again.';
  if (['mail_failed', 'email_send_failed'].includes(error?.code)) return 'We could not send the email. Try sending again to the same address.';
  if (error?.code === 'email_not_configured') return 'Email sending is not set up. Contact your administrator.';
  if (error?.status === 429) {
    const seconds = Math.max(1, Math.ceil(Number(error.data?.retry_after) || 60));
    return error.data?.can_retry ? `Please wait ${seconds} seconds before sending again.`
      : `Too many emails for this address. Try again in about ${Math.ceil(seconds / 60)} minutes.`;
  }
  if (error?.code === 'timeout' || error?.code === 'network') return 'The request could not be confirmed. Check its status or retry the same request.';
  return 'The request could not be completed. Please try again.';
}

// Only an opaque request UUID is retained. Email proof tokens and passwords are
// never stored here. Keeping this UUID lets uncertain submissions retry safely.
export function registrationRequestId(code, email, renew = false) {
  const key = 'registration-request:' + code + ':' + email.toLowerCase();
  let previous;
  try { previous = sessionStorage.getItem(key); } catch { /* storage may be unavailable */ }
  if (!renew && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(previous || '')) return previous;
  const id = crypto.randomUUID();
  try { sessionStorage.setItem(key, id); } catch { /* in-memory caller still retains it */ }
  return id;
}
