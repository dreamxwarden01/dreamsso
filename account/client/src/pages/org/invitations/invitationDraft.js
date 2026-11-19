import { invitationNoteWithinLimit } from './invitationModel.js';
const DAY = 86400000;
export const invitationDraftKey = (actor) => 'acct:invite-draft:v1:' + encodeURIComponent(actor);
export const DEFAULT_INVITATION_FORM = { delivery: 'email', email: '', role_slug: '', note: '', validity_hours: 72 };
function formValue(value) {
  if (!value || typeof value !== 'object' || !['email', 'link'].includes(value.delivery)
    || typeof value.email !== 'string' || value.email.length > 254 || typeof value.role_slug !== 'string' || value.role_slug.length > 100
    || !invitationNoteWithinLimit(value.note) || ![24, 72, 168].includes(value.validity_hours)) return null;
  return { delivery: value.delivery, email: value.email, role_slug: value.role_slug, note: value.note, validity_hours: value.validity_hours };
}
function record(storage, actor, now) {
  const key = invitationDraftKey(actor); let data;
  try { const raw = storage.getItem(key); if (!raw) return null; if (raw.length <= 4096) data = JSON.parse(raw); } catch { try { storage.removeItem(key); } catch { /* best effort */ } return null; }
  const form = formValue(data?.form);
  if (!data || data.version !== 1 || data.owner !== actor || !Number.isSafeInteger(data.at) || data.at < 0 || data.at > now || now - data.at >= DAY || !form) {
    try { storage.removeItem(key); } catch { /* best effort */ } return null;
  }
  return { form, at: data.at };
}
export function readInvitationDraft(storage, actor, now = Date.now()) { return record(storage, actor, now)?.form ?? null; }
export function writeInvitationDraft(storage, actor, form, now = Date.now()) {
  const clean = formValue(form); if (!clean) return false;
  try { const previous = record(storage, actor, now), key = invitationDraftKey(actor), body = JSON.stringify({ version: 1, owner: actor, at: previous?.at ?? now, form: clean }); storage.setItem(key, body); return storage.getItem(key) === body; }
  catch { return false; }
}
export function clearInvitationDraft(storage, actor) { try { storage.removeItem(invitationDraftKey(actor)); } catch { /* editing/sign-in must remain possible */ } }
