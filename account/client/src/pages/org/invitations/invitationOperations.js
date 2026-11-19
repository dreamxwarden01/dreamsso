import { uncertainMutation } from './invitationModel.js';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const DAY = 86400000;
export function operationKey(actor, kind, id) { return `acct:invite-operation:v1:${encodeURIComponent(actor)}:${kind}:${encodeURIComponent(id || 'new')}`; }
export function requestForOperation(storage, key, fingerprint, now = Date.now(), random = () => crypto.randomUUID()) {
  let old;
  try { const raw = storage.getItem(key); if (raw?.length < 2048) old = JSON.parse(raw); } catch { /* unavailable storage is handled by persistence below */ }
  if (old && UUID.test(old.id || '') && old.fingerprint === fingerprint && Number.isSafeInteger(old.at)
    && old.at >= 0 && old.at <= now && now - old.at < DAY) return old.id;
  const id = random(); if (!UUID.test(id)) throw new Error('request_storage_unavailable');
  const record = JSON.stringify({ id, fingerprint, at: now });
  storage.setItem(key, record);
  if (storage.getItem(key) !== record) throw new Error('request_storage_unavailable');
  return id;
}
export async function mutationRequest(actor, kind, id, body) {
  const bytes = new TextEncoder().encode(JSON.stringify(body));
  const hash = await crypto.subtle.digest('SHA-256', bytes);
  const fingerprint = Array.from(new Uint8Array(hash), (n) => n.toString(16).padStart(2, '0')).join('');
  const key = operationKey(actor, kind, id);
  try { return { key, id: requestForOperation(sessionStorage, key, fingerprint) }; }
  catch { throw Object.assign(new Error('request_storage_unavailable'), { code: 'request_storage_unavailable' }); }
}
export function settleOperation(operation, error = null) {
  if (!operation || error && uncertainMutation(error)) return;
  try { sessionStorage.removeItem(operation.key); } catch { /* replay remains safe if a settled receipt cannot be removed */ }
}
