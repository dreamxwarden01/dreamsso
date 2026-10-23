// One RP draft per browser tab. No credentials, auth tokens, lifecycle actions,
// or arbitrary JSON are retained. This is recovery only; it never sends requests.
// savedAt is the original creation time, never extended by later writes.
export const DRAFT_KEY = 'sso:rp-draft:v1';
export const DRAFT_TTL = 2 * 60 * 60_000;
export const DRAFT_MAX = 64 * 1024;
const fields = ['client_id', 'name', 'hostname', 'redirect_paths', 'events_path', 'key_mode',
  'jwks_path', 'jwks_text', 'allowed_scopes', 'is_first_party', 'entry_policy'];
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const object = (v) => v && typeof v === 'object' && !Array.isArray(v);
const oversized = (raw) => raw.length > DRAFT_MAX || new TextEncoder().encode(raw).length > DRAFT_MAX;
const short = (v) => typeof v === 'string' && v.length <= 4096;
const publicPart = (v) => typeof v === 'string' && /^[A-Za-z0-9_-]+$/.test(v) && v.length <= 16384;

export function publicJwks(text) {
  if (text === '') return '';
  if (typeof text !== 'string' || text.length > DRAFT_MAX) return null;
  try {
    const j = JSON.parse(text);
    if (!object(j) || Object.keys(j).some((k) => k !== 'keys') || !Array.isArray(j.keys) || !j.keys.length || j.keys.length > 20) return null;
    for (const key of j.keys) {
      if (!object(key)) return null;
      const parts = key.kty === 'RSA' ? ['n', 'e'] : key.kty === 'EC' ? ['x', 'y'] : key.kty === 'OKP' ? ['x'] : null;
      if (!parts || !parts.every((p) => publicPart(key[p]))) return null;
      const allowed = ['kty', 'kid', 'use', 'alg', 'key_ops', ...parts, ...(key.kty === 'RSA' ? [] : ['crv'])];
      if (Object.keys(key).some((k) => !allowed.includes(k))) return null;
      if (key.kid !== undefined && (!short(key.kid) || key.kid.length > 256)) return null;
      if (key.use !== undefined && key.use !== 'sig') return null;
      if (key.alg !== undefined && !['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512', 'EdDSA'].includes(key.alg)) return null;
      if (key.key_ops !== undefined && (!Array.isArray(key.key_ops) || key.key_ops.length !== 1 || key.key_ops[0] !== 'verify')) return null;
      if (key.kty === 'EC' && !['P-256', 'P-384', 'P-521'].includes(key.crv)) return null;
      if (key.kty === 'OKP' && key.crv !== 'Ed25519') return null;
    }
    return JSON.stringify(j, null, 2);
  } catch { return null; }
}

// Query strings can legitimately contain secrets. Omit the entire value and
// explain recovery, rather than altering the entered configuration.
function safeUrlPart(v, hostname = false) {
  if (!short(v) || /[?#@\s\\\u0000-\u001f]/.test(v) || /%(?:3f|23|40)/i.test(v)) return false;
  if (!v) return true;
  if (hostname) return /^(?:https?:\/\/)?[a-z0-9.-]+\/?$/i.test(v);
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(v) || v.startsWith('//')) {
    try { const u = new URL(v.startsWith('//') ? 'https:' + v : v); return u.protocol === 'https:' && !u.username && !u.password && !u.search && !u.hash; } catch { return false; }
  }
  return /^\/?[A-Za-z0-9/._~!$&'()*+,;=:%-]*$/.test(v);
}
function sanitize(form) {
  const result = {};
  for (const key of fields) {
    const v = form?.[key];
    if (key === 'jwks_text') { const j = typeof v === 'string' ? publicJwks(v) : null; if (j !== null) result[key] = j; }
    else if (key === 'hostname' || key.endsWith('_path')) { if (safeUrlPart(v, key === 'hostname')) result[key] = v; }
    else if (key === 'redirect_paths') { if (Array.isArray(v) && v.length <= 50 && v.every((p) => safeUrlPart(p))) result[key] = v; }
    else if (key === 'allowed_scopes') { if (Array.isArray(v) && v.length <= 3 && v.every((s) => ['openid', 'profile', 'email'].includes(s))) result[key] = v; }
    else if (key === 'is_first_party') { if (typeof v === 'boolean') result[key] = v; }
    else if (key === 'key_mode') { if (['uri', 'inline'].includes(v)) result[key] = v; }
    else if (key === 'entry_policy') { if (['opt_in', 'baseline'].includes(v)) result[key] = v; }
    else if (short(v)) result[key] = v;
  }
  return result;
}
const storage = () => globalThis.sessionStorage;
export function clearClientDraft(owner, route, target) {
  try {
    const s = target ?? storage();
    const raw = s.getItem(DRAFT_KEY);
    if (!raw) return true;
    let d;
    try { d = JSON.parse(raw); } catch { s.removeItem(DRAFT_KEY); return true; }
    if (!object(d) || typeof d.owner !== 'string' || typeof d.route !== 'string') { s.removeItem(DRAFT_KEY); return true; }
    if (d.owner === owner && d.route === route) s.removeItem(DRAFT_KEY);
    return true;
  } catch { return false; }
}
export function writeClientDraft({ owner, route, form, base, externalJwksUri = null, uncertain = false, omitted: retainedOmitted = [], createdAt, operationId = null, priorUnknown = uncertain && !operationId, now = Date.now() }, target) {
  let s;
  try {
    s = target ?? storage();
    if (typeof owner !== 'string' || !owner || !short(route)) return { saved: false, omitted: [] };
    const savedAt = createdAt ?? readClientDraft({ owner, route, now }, s)?.savedAt ?? now;
    if (now < savedAt || now - savedAt >= DRAFT_TTL) {
      clearClientDraft(owner, route, s);
      return { saved: false, omitted: retainedOmitted, savedAt, reason: 'expired' };
    }
    const clean = sanitize(form), cleanBase = sanitize(base);
    const dirty = fields.filter((key) => !same(form[key], base[key]));
    const omitted = [...new Set([...retainedOmitted.filter((key) => fields.includes(key)), ...dirty.filter((key) => !Object.hasOwn(clean, key) || !Object.hasOwn(cleanBase, key) ||
      (externalJwksUri && ['key_mode', 'jwks_path', 'jwks_text'].includes(key)))])];
    const changes = Object.fromEntries(dirty.filter((key) => !omitted.includes(key)).map((key) => [key, clean[key]]));
    const d = { version: 1, owner, route, savedAt, base: cleanBase, changes, omitted, uncertain: Boolean(uncertain), operationId, priorUnknown: Boolean(priorUnknown) };
    const raw = JSON.stringify(d);
    if (oversized(raw) || !dirty.length && !uncertain && !omitted.length) { clearClientDraft(owner, route, s); return { saved: false, omitted, savedAt, reason: oversized(raw) ? 'size' : 'empty' }; }
    s.setItem(DRAFT_KEY, raw);
    return { saved: true, omitted, savedAt };
  } catch { clearClientDraft(owner, route, s); return { saved: false, omitted: retainedOmitted, reason: 'unavailable' }; }
}
export function readClientDraft({ owner, route, now = Date.now() }, target) {
  let s;
  try {
    s = target ?? storage();
    const raw = s.getItem(DRAFT_KEY);
    if (!raw) return null;
    if (oversized(raw)) throw new Error();
    const d = JSON.parse(raw);
    if (!object(d) || d.version !== 1 || d.owner !== owner || !short(d.route) || !Number.isFinite(d.savedAt) ||
        now < d.savedAt || now - d.savedAt >= DRAFT_TTL || typeof d.uncertain !== 'boolean' || typeof d.priorUnknown !== 'boolean' ||
        (d.operationId !== null && (typeof d.operationId !== 'string' || !/^[a-z0-9-]{1,80}$/i.test(d.operationId))) ||
        !object(d.base) || !object(d.changes) || !Array.isArray(d.omitted) || d.omitted.some((key) => !fields.includes(key)) ||
        !same(sanitize(d.base), d.base) || !same(sanitize(d.changes), d.changes) ||
        Object.keys(d.changes).some((key) => !Object.hasOwn(d.base, key))) throw new Error();
    return d.route === route ? d : null;
  } catch { try { s?.removeItem(DRAFT_KEY); } catch { /* unavailable storage */ } return null; }
}
export function restoreClientDraft(draft, current, { isNew = false, disabled = false } = {}) {
  if (!draft) return { form: current, restored: [], conflicts: [], omitted: [], uncertain: false, priorUnknown: false };
  if (disabled) return { form: current, restored: [], conflicts: Object.keys(draft.changes), omitted: [], uncertain: false, priorUnknown: false, discarded: true };
  const form = { ...current }, restored = [], conflicts = [], omitted = [...draft.omitted];
  const currentSafe = sanitize(current);
  for (const [key, value] of Object.entries(draft.changes)) {
    const dependencies = key.startsWith('jwks') || key === 'key_mode' ? ['hostname', 'key_mode', 'jwks_path', 'jwks_text']
      : ['redirect_paths', 'events_path'].includes(key) ? ['hostname', key] : [key];
    if (!isNew && dependencies.some((dep) => !Object.hasOwn(draft.base, dep) || !Object.hasOwn(currentSafe, dep))) omitted.push(key);
    else if (!isNew && dependencies.some((dep) => !same(draft.base[dep], currentSafe[dep]))) conflicts.push(key);
    else { form[key] = value; restored.push(key); }
  }
  return { form, restored, conflicts, omitted: [...new Set(omitted)], uncertain: draft.uncertain, priorUnknown: draft.priorUnknown };
}

// Keep edits made after the submitted snapshot, while adopting canonical values
// for untouched fields (including fetched public-key snapshots).
export function rebaseClientDraftForm(current, submitted, canonical) {
  return Object.fromEntries(fields.map((key) => [key, same(current[key], submitted[key]) ? canonical[key] : current[key]]));
}

export function clientDraftAuthUncertain(uncertain, bounce, mutationPath, priorUnknown = false) {
  const rejected = ['unauthenticated', 'step_up_required'].includes(bounce?.reason) && bounce.mutating &&
    [mutationPath, mutationPath + '/enable', mutationPath + '/disable'].includes(bounce.path);
  return Boolean(priorUnknown || (!rejected && uncertain));
}

// SPA navigation can return to a still-pending form before its old request
// settles. Notify that untouched returned view within this document only.
const settlementListeners = new Set();
export function observeClientDraftSettlement(identity, listener) {
  const entry = { ...identity, listener };
  settlementListeners.add(entry);
  return () => settlementListeners.delete(entry);
}
function notifySettlement(event) {
  for (const entry of settlementListeners) {
    if (entry.owner === event.owner && entry.route === event.route && entry.operationId === event.operationId) {
      try { entry.listener(event); } catch { /* views cannot interrupt settlement */ }
    }
  }
}

// Settle just this pending mutation. A newer edit/operation or another account
// owns a different snapshot and must never be cleared by a late response.
export function settleClientDraft({ owner, route, operationId, success = false, uncertain = false, now = Date.now() }, target) {
  try {
    const s = target ?? storage();
    const raw = s.getItem(DRAFT_KEY);
    if (!raw) return false;
    const identity = JSON.parse(raw);
    if (identity?.owner !== owner || identity?.route !== route || identity?.operationId !== operationId || !operationId) return false;
    const d = readClientDraft({ owner, route, now }, s);
    if (!d) return false;
    if (success) s.removeItem(DRAFT_KEY);
    else s.setItem(DRAFT_KEY, JSON.stringify({ ...d, operationId: null,
      uncertain: Boolean(d.priorUnknown || uncertain), priorUnknown: Boolean(d.priorUnknown || uncertain) }));
    notifySettlement({ owner, route, operationId, success, uncertain: success ? false : Boolean(d.priorUnknown || uncertain) });
    return true;
  } catch { return false; }
}
