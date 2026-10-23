// Admin API errors retain machine codes; views decide how to present them.
let csrf = null;
const authBounceListeners = new Set();
export function beforeAuthBounce(listener) {
  authBounceListeners.add(listener);
  return () => authBounceListeners.delete(listener);
}
function preserveBeforeAuthBounce(context) {
  // Storage failures must never interrupt login/verification.
  for (const listener of authBounceListeners) { try { listener(context); } catch { /* best effort */ } }
}
const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

function apiError(code, status = 0, data = null, uncertain = false) {
  const e = new Error(code);
  e.code = code;
  e.status = status;
  e.data = data ?? { error: code };
  e.uncertain = uncertain;
  return e;
}

export function apiErrorMessage(e) {
  const messages = {
    request_timeout: 'The request timed out. Check your connection and try again.',
    network_error: 'The server could not be reached. Check your connection and try again.',
    invalid_response: 'The server returned an unexpected response. Try again shortly.',
    challenge_required: 'A network verification page blocked the request. Reload this page to complete verification.',
    permission_denied: 'Your account does not have permission to manage SSO.',
    csrf_failed: 'The page security token has expired. Reload this page before trying again.',
    unauthenticated: 'Your session has expired. Returning to sign in…',
    step_up_required: 'Identity verification is required. Returning to verification…',
  };
  let message = Object.hasOwn(messages, e?.code) ? messages[e.code] : null;
  if (!message && e?.status === 403) message = 'The server denied this action. Check your access or reload this page.';
  if (!message && e?.status === 429) message = 'Too many requests. Wait a moment before trying again.';
  if (!message && e?.status >= 500) message = 'The server is temporarily unavailable. Try again shortly.';
  if (!message) {
    const code = /^[a-z][a-z0-9_]{0,63}$/i.test(e?.code || '') ? ` (${e.code})` : '';
    message = `The request failed${code}. Review your input and try again.`;
  }
  // A browser deadline cannot cancel a server commit. Never imply it did.
  if (e?.uncertain) {
    const reason = e.code === 'request_timeout' ? 'The request timed out.'
      : e.code === 'network_error' ? 'The connection failed.'
      : e.code === 'invalid_response' ? 'The server returned an unexpected response.'
      : 'The server reported an error.';
    return `${reason} The change may already have been saved. Check the current state before retrying.`;
  }
  return message;
}

async function req(path, opts = {}) {
  const { timeoutMs = 30_000, validate, expectedStatus, ...requestOptions } = opts;
  const mutating = Boolean(opts.method && opts.method !== 'GET');
  const controller = new AbortController();
  let status = 0;
  let timer;
  let settled = false;
  // Race the entire operation, including JSON parsing. Some transports do not
  // reject immediately on abort; a slow body must not hold the UI indefinitely.
  const deadline = new Promise((_, reject) => {
    timer = setTimeout(() => {
      settled = true;
      reject(apiError('request_timeout', status, null, mutating));
      controller.abort();
    }, timeoutMs);
  });
  const operation = async () => {
    const r = await fetch('/admin/api' + path, {
      credentials: 'same-origin',
      ...requestOptions,
      headers: {
        accept: 'application/json',
        ...(mutating && csrf ? { 'x-csrf-token': csrf } : {}),
        ...(opts.body ? { 'content-type': 'application/json' } : {}),
      },
      signal: controller.signal,
    });
    if (settled) throw apiError('request_timeout', status, null, mutating);
    status = r.status;
    if (status === 401) {
      preserveBeforeAuthBounce({ reason: 'unauthenticated', mutating, path });
      const next = location.pathname.startsWith('/admin') ? location.pathname : '/admin';
      location.href = '/admin/start-login?next=' + encodeURIComponent(next);
      throw apiError('unauthenticated', status);
    }
    const json = /^application\/(?:[\w.-]+\+)?json(?:\s*;|$)/i.test(r.headers.get('content-type') || '');
    let data = null;
    if (status !== 204 && json) {
      try { data = await r.json(); } catch { /* classified below */ }
    }
    if (settled) throw apiError('request_timeout', status, null, mutating);
    if (!r.ok) {
      if (status === 403 && data?.error === 'step_up_required') {
        preserveBeforeAuthBounce({ reason: 'step_up_required', mutating, path });
        location.reload();
        throw apiError('step_up_required', status, data);
      }
      const code = r.headers.get('cf-mitigated') === 'challenge' ? 'challenge_required'
        : typeof data?.error === 'string' ? data.error : 'http_' + status;
      // Server errors after a mutation can follow a committed write too.
      throw apiError(code, status, isObject(data) ? data : null, mutating && status >= 500);
    }
    if ((status !== 204 && (!json || !isObject(data))) ||
        (expectedStatus && status !== expectedStatus) || (validate && !validate(data))) {
      throw apiError('invalid_response', status, null, mutating);
    }
    return data;
  };
  try {
    return await Promise.race([operation(), deadline]);
  } catch (e) {
    if (e?.code && Number.isInteger(e.status)) throw e;
    throw apiError('network_error', status, null, mutating);
  } finally {
    settled = true;
    clearTimeout(timer);
  }
}

export async function getMe() {
  const me = await req('/me', { timeoutMs: 15_000,
    validate: (d) => isObject(d) && typeof d.csrf === 'string' && d.csrf.length > 0 && typeof d.sub === 'string' && d.sub.length > 0 });
  csrf = me.csrf;
  return me;
}
// Branding is optional and does not gate the admin UI.
export const getPublicSettings = () =>
  fetch('/api/settings/public', { headers: { accept: 'application/json' }, signal: AbortSignal.timeout(15_000) })
    .then((r) => r.ok ? r.json() : Promise.reject(apiError('http_' + r.status, r.status)));
export const listClients = () => req('/clients', { timeoutMs: 15_000,
  validate: (d) => isObject(d) && Array.isArray(d.clients) && d.clients.every((c) =>
    isObject(c) && typeof c.client_id === 'string' && typeof c.name === 'string' &&
    typeof c.hostname === 'string' && Array.isArray(c.redirect_paths) && Array.isArray(c.allowed_scopes)) });
export const createClient = (body) => req('/clients', { method: 'POST', body: JSON.stringify(body),
  timeoutMs: 15_000, expectedStatus: 201,
  validate: (d) => isObject(d?.client) && typeof d.client.client_id === 'string' && d.client.client_id.length > 0 });
export const updateClient = (id, body) =>
  req('/clients/' + encodeURIComponent(id), { method: 'PATCH', body: JSON.stringify(body) });
export const disableClient = (id) => req(`/clients/${encodeURIComponent(id)}/disable`, { method: 'POST' });
export const enableClient = (id) => req(`/clients/${encodeURIComponent(id)}/enable`, { method: 'POST' });
export const deleteClient = (id) => req('/clients/' + encodeURIComponent(id), { method: 'DELETE' });
export const getKeys = () => req('/keys');
export const rotateKeys = () => req('/keys/rotate', { method: 'POST' });
export const getMtls = () => req('/mtls');
export const mtlsCsr = (cn) => req('/mtls/csr', { method: 'POST', body: JSON.stringify({ cn }) });
export const mtlsInstall = (cert) => req('/mtls/cert', { method: 'POST', body: JSON.stringify({ cert }) });
export const mtlsEnforce = (enabled) => req('/mtls/enforce', { method: 'PUT', body: JSON.stringify({ enabled }) });
export const mtlsReset = () => req('/mtls', { method: 'DELETE' });
export const getSettings = () => req('/settings');
export const updateSettings = (body) => req('/settings', { method: 'PUT', body: JSON.stringify(body) });
export const sendTestEmail = (to) => req('/settings/test-email', { method: 'POST', body: JSON.stringify({ to }) });
export const generateGateKey = () => req('/settings/generate-gate-key', { method: 'POST' });
export const rotatePortalClientKey = () => req('/account-portal/rotate-client-key', { method: 'POST' });
export const getPortalClientKey = () => req('/account-portal/client-key');
