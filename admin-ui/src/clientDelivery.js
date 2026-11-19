const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const MAX_AGE = 24 * 60 * 60 * 1000;
const count = (value) => Number.isSafeInteger(value) && value >= 0;
const knownOutcomes = new Set(['delivered', 'http_rejected', 'delivery_failed', 'signing_failed',
  'event_too_large', 'destination_unavailable', 'paused', 'recovered']);

// Copy only public summary fields. Never pass an arbitrary response/payload to
// the view, even when a server response contains extra diagnostic properties.
export function deliverySummary(value) {
  if (!value || !['ready', 'paused', 'unconfigured'].includes(value.state) || typeof value.can_recover !== 'boolean') return null;
  const counts = {};
  for (const key of ['pending', 'paused', 'dead', 'delivered']) {
    if (!count(value.counts?.[key])) return null;
    counts[key] = value.counts[key];
  }
  if (value.state === 'ready' ? counts.paused !== 0 : counts.pending !== 0 || value.can_recover) return null;
  let last = null;
  if (value.last_outcome !== null) {
    if (!value.last_outcome || typeof value.last_outcome.code !== 'string') return null;
    const at = value.last_outcome.at;
    if (at !== null && (typeof at !== 'string' || !Number.isFinite(Date.parse(at)) || new Date(at).toISOString() !== at)) return null;
    last = { code: knownOutcomes.has(value.last_outcome.code) ? value.last_outcome.code : 'unknown_error', at };
  }
  return { state: value.state, counts, last_outcome: last, can_recover: value.can_recover };
}

export function recoverySummary(value) {
  if (!value || typeof value !== 'object') return null;
  const result = {};
  for (const key of ['logout_requeued', 'role_snapshots', 'role_superseded', 'other_retained']) {
    if (!count(value[key])) return null;
    result[key] = value[key];
  }
  return result;
}

export function deliveryOutcome(code) {
  const messages = { delivered: 'Notification delivered.', http_rejected: 'The app rejected a delivery.',
    delivery_failed: 'A delivery could not reach the app.', signing_failed: 'A notification could not be signed.',
    event_too_large: 'A notification needs attention before delivery.', destination_unavailable: 'The delivery destination was unavailable.',
    paused: 'Notification delivery paused.', recovered: 'Access resynchronization queued.' };
  return Object.hasOwn(messages, code) ? messages[code] : 'A delivery outcome needs attention.';
}

export function recoveryMessage(result) {
  const notices = result.logout_requeued + result.role_snapshots;
  const queued = notices ? 'This recovery request queued sign-out retries and current access synchronization.' : 'This recovery request completed without additional access notices.';
  return result.other_retained ? `${queued} ${result.other_retained.toLocaleString()} failed notification${result.other_retained === 1 ? ' still needs' : 's still need'} attention.` : queued;
}

function storageKey(owner, clientId) {
  return 'sso-admin-delivery:v1:' + encodeURIComponent(owner) + ':' + encodeURIComponent(clientId);
}
function storedRecord(storage, owner, clientId, now) {
  const key = storageKey(owner, clientId), raw = storage.getItem(key);
  if (!raw) return null;
  let record;
  try { if (raw.length <= 2048) record = JSON.parse(raw); } catch { /* discard malformed recovery metadata */ }
  if (!record || !UUID.test(record.requestId || '') || !Number.isSafeInteger(record.createdAt) || record.createdAt < 0
    || record.createdAt > now || now - record.createdAt >= MAX_AGE) {
    storage.removeItem(key); return null;
  }
  return { requestId: record.requestId.toLowerCase(), createdAt: record.createdAt };
}
export function pendingRecovery(storage, owner, clientId, now = Date.now()) {
  return storedRecord(storage, owner, clientId, now)?.requestId ?? null;
}
export function recoveryRequest(storage, owner, clientId, now = Date.now(), uuid = () => crypto.randomUUID()) {
  const previous = storedRecord(storage, owner, clientId, now);
  if (previous) return previous.requestId;
  const requestId = uuid();
  if (!UUID.test(requestId)) throw new Error('recovery_storage_unavailable');
  storage.setItem(storageKey(owner, clientId), JSON.stringify({ requestId, createdAt: now }));
  // Do not send a mutation if this tab cannot retain its idempotency key.
  if (storedRecord(storage, owner, clientId, now)?.requestId !== requestId.toLowerCase()) throw new Error('recovery_storage_unavailable');
  return requestId.toLowerCase();
}
export function clearRecovery(storage, owner, clientId) {
  storage.removeItem(storageKey(owner, clientId));
}
export function retainRecovery(error) {
  return ['unauthenticated', 'step_up_required'].includes(error?.code)
    || error?.uncertain === true || !(error?.status >= 400 && error?.status < 500);
}
