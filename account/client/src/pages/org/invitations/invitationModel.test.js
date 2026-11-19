import test from 'node:test';
import assert from 'node:assert/strict';
import { formatInvitationTime, invitationError, invitationFromDto, invitationMutationFromDto, invitationNoteWithinLimit, invitationPageFromDto, limitInvitationNote, manualPage, pageSlots, relativeInvitationTime } from './invitationModel.js';

export const dto = () => ({ id: '11111111-1111-4111-8111-111111111111', code: 'DISPLAYCODE12', status: 'active', note: 'Fictional note', email: 'fiction@example.invalid', delivery: 'email',
  binding_source: 'creation', bound_at: '2026-11-18T12:00:00.000Z', created_at: '2026-11-18T12:00:00.000Z', expires_at: '2026-11-21T12:00:00.000Z', ended_at: null,
  created_by_label: 'Fictional administrator', invited_role: { slug: 'member', label: 'Member' }, mail: { state: 'queued', at: null, attempts: 1 }, can_revoke: true, can_resend: true });

test('invitation DTO keeps allowed code/ID metadata and never forwards proof/token/unknown fields', () => {
  const v = dto(); v.mail.proof = 'private-mail-proof'; v.password = 'private-password'; v.login_ticket = 'private-login-ticket'; v.invited_role.internal = 'private';
  const normalized = invitationFromDto(v), serialized = JSON.stringify(normalized);
  assert.equal(normalized.code, 'DISPLAYCODE12'); assert.equal(normalized.id, v.id); assert.equal(normalized.mail.state, 'queued');
  assert.ok(Number.isFinite(normalized.expiresAt)); assert.doesNotMatch(serialized, /private|proof|password|ticket/);
  for (const status of ['active', 'used', 'expired', 'revoked', 'invalid']) assert.equal(invitationFromDto({ ...dto(), status }).status, status);
  for (const state of ['none', 'queued', 'sending', 'sent', 'failed', 'unknown']) assert.equal(invitationFromDto({ ...dto(), mail: { ...dto().mail, state } }).mail.state, state);
  assert.match(invitationFromDto({ ...dto(), invalid_reason: 'role_deleted' }).invalidReason, /deleted/);
});
test('malformed DTO/date/page fields fail closed instead of inventing status or totals', () => {
  for (const change of [{ id: '' }, { status: 'opened' }, { email: [] }, { expires_at: 'bad' }, { created_at: null }, { can_revoke: undefined }, { mail: { state: 'delivered', attempts: 1 } }]) assert.throws(() => invitationFromDto({ ...dto(), ...change }), /invalid_response/);
  const page = { items: [dto()], page: 1, page_size: 10, pages: 1, total: 1, counts: { all: 1, current: 1, history: 0 } };
  assert.equal(invitationPageFromDto(page).items.length, 1);
  for (const change of [{ total: -1 }, { page: 0 }, { page_size: 50 }, { pages: '1' }, { counts: { all: '1' } }]) assert.throws(() => invitationPageFromDto({ ...page, ...change }), /invalid_response/);
});
test('notes count Unicode code points like the server, including a whole page containing 60 emoji', () => {
  const note = '😀'.repeat(60); assert.equal(note.length, 120); assert.equal(invitationNoteWithinLimit(note), true);
  assert.equal(invitationFromDto({ ...dto(), note }).note, note);
  const page = { items: [{ ...dto(), note }], page: 1, page_size: 10, pages: 1, total: 1, counts: { all: 1, current: 1, history: 0 } };
  assert.equal(invitationPageFromDto(page).items[0].note, note);
  assert.equal(invitationNoteWithinLimit(note + '😀'), false); assert.throws(() => invitationFromDto({ ...dto(), note: note + '😀' }), /invalid_response/);
  assert.equal(limitInvitationNote(note + '😀'), note);
  assert.equal(limitInvitationNote('a' + note), 'a' + '😀'.repeat(59));
});
test('missing or malformed mutation bodies are typed uncertain responses with explicit unknown-outcome copy', () => {
  for (const response of [null, undefined, {}, { invitation: null }, { invitation: {} }]) assert.throws(() => invitationMutationFromDto(response), (error) => {
    assert.equal(error.code, 'invalid_response'); assert.equal(error.uncertain, true); assert.match(invitationError(error), /may already have been saved/); return true;
  });
  assert.equal(invitationMutationFromDto({ invitation: dto() }).code, dto().code);
  for (const code of ['request_timeout', 'network_error']) assert.match(invitationError({ code, uncertain: true }), /may already have been saved/);
});
test('fixed page windows include all valid current pages and never hide just one page behind ellipsis', () => {
  for (let n = 1; n <= 1000; n++) for (let p = 1; p <= n; p++) {
    const slots = pageSlots(p, n); assert.equal(slots.length, Math.min(7, n)); assert.equal(slots[0], 1); assert.equal(slots.at(-1), n); assert.ok(slots.includes(p));
    const numbers = slots.filter((x) => x !== null); assert.equal(new Set(numbers).size, numbers.length);
    for (let i = 0; i < slots.length; i++) if (slots[i] === null) assert.ok(slots[i + 1] - slots[i - 1] >= 3);
  }
});
test('manual page input sanitizes text, clamps and retains the requested target for empty input', () => {
  assert.equal(manualPage('a1-0b0', 9, 1000), 100); assert.equal(manualPage('999', 1, 5), 5);
  assert.equal(manualPage('', 4, 5), 4); assert.equal(manualPage('0', 4, 5), 4);
});
test('relative and exact times keep strict boundaries and the actual timezone', () => {
  const now = 1000000000000;
  for (const [delta, expected] of [[0, 'just now'], [-60000, '1 minute ago'], [3600000, 'in 1 hour'], [-86400000, '1 day ago'], [-30 * 86400000, '1 month ago'], [365 * 86400000, 'in 1 year']]) assert.equal(relativeInvitationTime(now + delta, now), expected);
  assert.match(formatInvitationTime(now), /^\d{4}\/\d{2}\/\d{2} \d{2}:\d{2} (AM|PM) .+$/);
  assert.equal(invitationError({ code: 'rate_limited', data: { retry_after: 37 } }), 'Please wait 37 seconds before sending another email.');
  assert.doesNotMatch(invitationError({ code: 'rate_limited', data: { retry_after: 'private-token' } }), /private-token/);
});
