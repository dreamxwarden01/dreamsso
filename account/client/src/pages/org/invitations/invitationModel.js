export const PAGE_SIZES = [10, 25, 100];
export const invitationNoteWithinLimit = (value) => typeof value === 'string' && [...value].length <= 60;
export const limitInvitationNote = (value) => [...value].slice(0, 60).join('');
export const VALIDITY = [{ value: '24', label: '24 hours' }, { value: '72', label: '72 hours', desc: 'Default' }, { value: '168', label: '7 days' }];
export const DEFAULT_QUERY = { page: 1, pageSize: 10, query: '', status: 'all', sort: 'created_at', order: 'desc' };
const statuses = new Set(['active', 'used', 'expired', 'revoked', 'invalid']);
const mailStates = new Set(['none', 'queued', 'sending', 'sent', 'failed', 'unknown']);
const object = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const integer = (v, min = 0) => Number.isSafeInteger(v) && v >= min;
const text = (v, max = 500) => typeof v === 'string' && v.length <= max;
export function invalidResponse() { return Object.assign(new Error('invalid_response'), { code: 'invalid_response' }); }
function timestamp(value, required = false) {
  if (value == null && !required) return null;
  const n = typeof value === 'string' ? Date.parse(value) : NaN;
  if (!Number.isFinite(n)) throw invalidResponse();
  return n;
}
export function invitationFromDto(v) {
  if (!object(v) || !text(v.id, 128) || !v.id || !text(v.code, 128) || !v.code || !statuses.has(v.status)
    || !invitationNoteWithinLimit(v.note ?? '') || !(v.email === null || text(v.email, 254)) || !object(v.mail)
    || !mailStates.has(v.mail.state) || !integer(v.mail.attempts) || !['email', 'link'].includes(v.delivery)
    || typeof v.can_revoke !== 'boolean' || typeof v.can_resend !== 'boolean') throw invalidResponse();
  const role = object(v.invited_role) ? { slug: String(v.invited_role.slug ?? ''), label: String(v.invited_role.label ?? 'Deleted role') } : { slug: '', label: 'Deleted role' };
  return { id: v.id, code: v.code, status: v.status, note: v.note ?? '', email: v.email, delivery: v.delivery,
    bindingSource: ['creation', 'first_request'].includes(v.binding_source) ? v.binding_source : null,
    boundAt: timestamp(v.bound_at), createdAt: timestamp(v.created_at, true), expiresAt: timestamp(v.expires_at, true),
    endedAt: timestamp(v.ended_at), createdBy: text(v.created_by_label, 200) ? v.created_by_label : 'Former administrator', role,
    mail: { state: v.mail.state, at: timestamp(v.mail.at), attempts: v.mail.attempts },
    usedBy: object(v.used_by) ? { username: String(v.used_by.username ?? ''), displayName: String(v.used_by.display_name ?? '') } : null,
    revokedBy: text(v.revoked_by_label, 200) ? v.revoked_by_label : null,
    invalidReason: v.invalid_reason === 'role_deleted' ? 'The invited role was deleted before this invitation was used.'
      : v.invalid_reason === 'creator_unauthorized' ? 'The invitation creator no longer has the required authorization.' : null,
    canRevoke: v.can_revoke, canResend: v.can_resend };
}
export function invitationPageFromDto(v) {
  if (!object(v) || !Array.isArray(v.items) || !PAGE_SIZES.includes(v.page_size) || v.items.length > v.page_size
    || !integer(v.page, 1) || !integer(v.pages, 1) || v.page > v.pages || !integer(v.total)
    || !object(v.counts) || !['all', 'current', 'history'].every((k) => integer(v.counts[k]))) throw invalidResponse();
  return { items: v.items.map(invitationFromDto), page: v.page, pageSize: v.page_size, pages: v.pages, total: v.total,
    counts: { all: v.counts.all, current: v.counts.current, history: v.counts.history } };
}
export function invitationMutationFromDto(value) {
  try { return invitationFromDto(object(value) ? value.invitation : undefined); }
  catch (error) { if (error?.code === 'invalid_response') error.uncertain = true; throw error; }
}
export const queryKey = (q) => JSON.stringify([q.status, q.query, q.sort, q.order, q.pageSize, q.page]);
export const cohortKey = (q) => JSON.stringify([q.status, q.query, q.sort, q.order, q.pageSize]);
export function queryParams(q) {
  return new URLSearchParams({ page: String(q.page), page_size: String(q.pageSize), query: q.query, status: q.status, sort: q.sort, order: q.order }).toString();
}
export function pageSlots(page, pages) {
  if (pages <= 7) return Array.from({ length: pages }, (_, i) => i + 1);
  if (page <= 4) return [1, 2, 3, 4, 5, null, pages];
  if (page >= pages - 3) return [1, null, pages - 4, pages - 3, pages - 2, pages - 1, pages];
  return [1, null, page - 1, page, page + 1, null, pages];
}
export function manualPage(value, wanted, pages) {
  const digits = String(value).replace(/\D/g, ''), parsed = Number(digits);
  return !digits || !Number.isFinite(parsed) || parsed < 1 ? wanted : Math.min(pages, parsed);
}
export function formatInvitationTime(value) {
  const parts = Object.fromEntries(new Intl.DateTimeFormat('en-US', { year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', hour12: true, timeZoneName: 'short' }).formatToParts(new Date(value)).map((p) => [p.type, p.value]));
  return `${parts.year.padStart(4, '0')}/${parts.month}/${parts.day} ${parts.hour.padStart(2, '0')}:${parts.minute} ${parts.dayPeriod} ${parts.timeZoneName}`;
}
export function relativeInvitationTime(value, now = Date.now()) {
  if (!Number.isFinite(value) || !Number.isFinite(now)) return '—';
  const future = value > now, seconds = Math.abs(value - now) / 1000;
  if (seconds < 60) return future ? 'in less than a minute' : 'just now';
  const [size, unit] = seconds < 3600 ? [60, 'minute'] : seconds < 86400 ? [3600, 'hour']
    : seconds < 30 * 86400 ? [86400, 'day'] : seconds < 365 * 86400 ? [30 * 86400, 'month'] : [365 * 86400, 'year'];
  const n = Math.floor(seconds / size), label = `${n} ${unit}${n === 1 ? '' : 's'}`;
  return future ? `in ${label}` : `${label} ago`;
}
export function invitationError(error) {
  if (error?.code === 'invalid_response' && error.uncertain) return 'The response could not be confirmed. The action may already have been saved. Check current invitations before retrying the same request.';
  if ((error?.code === 'rate_limited' || error?.code === 'mail_rate_limited') && Number.isSafeInteger(error?.data?.retry_after)
    && error.data.retry_after > 0 && error.data.retry_after <= 86400) return `Please wait ${error.data.retry_after} second${error.data.retry_after === 1 ? '' : 's'} before sending another email.`;
  const messages = { unauthenticated: 'Your session has expired. Returning to sign in…',
    step_up_required: 'Complete identity verification, then submit again.', permission_denied: 'You no longer have permission for this action.',
    invalid_email: 'Enter a valid email address.', invalid_input: 'Review the invitation fields and try again.',
    invitation_gone: 'This invitation has ended or is no longer eligible. Its final record has been kept.', already_used: 'This invitation was already used. The existing account is unaffected.',
    invitation_used: 'This invitation was already used. The existing account is unaffected.', invitation_revoked: 'This invitation was already revoked. Its record has been kept.',
    invitation_expired: 'This invitation has reached its deadline. It cannot be extended.', invitation_unavailable: 'This invitation is no longer eligible or is temporarily unavailable. Check its current record.',
    invalid_role: 'Choose an available role below your own.', invalid_validity: 'Choose a valid invitation lifetime.', invalid_note: 'Keep the note within 60 characters.',
    email_bound: 'This invitation is bound to another address and cannot be transferred.', email_mismatch: 'This invitation is bound to another address.',
    no_bound_email: 'This invitation has no recipient address. Share its link or code instead.',
    rate_limited: 'Please wait before sending another email.', mail_rate_limited: 'Please wait before sending another email.',
    invalid_response: 'The server returned an unexpected response. Check the current invitations before retrying.',
    request_timeout: 'The request timed out. Its result may already have been saved. Check the list or retry the same request.',
    network_error: 'The connection failed. The action may already have been saved. Check the invitation before retrying the same request.' };
  const code = error?.code || error?.message;
  return messages[code] || (error?.status >= 500 ? 'The service is temporarily unavailable. Check the invitation before retrying.' : 'The action could not be completed. Review the current invitation and try again.');
}
export const authInterruption = (e) => ['unauthenticated', 'step_up_required'].includes(e?.code || e?.message);
export const uncertainMutation = (e) => authInterruption(e) || e?.uncertain === true || !(e?.status >= 400 && e?.status < 500);
export function invitationLink(code) { return window.location.origin + '/register/start?code=' + encodeURIComponent(code); }
