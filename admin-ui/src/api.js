// Thin client for the admin API. The shell is only served to authorized admins,
// but the session can expire mid-use: a 401 bounces through the local login.
// CSRF: /admin/api/me returns the synchronizer token; mutations echo it in a header.
let csrf = null;

async function req(path, opts = {}) {
  const mutating = opts.method && opts.method !== 'GET';
  const r = await fetch('/admin/api' + path, {
    credentials: 'same-origin',
    headers: {
      accept: 'application/json',
      ...(mutating && csrf ? { 'x-csrf-token': csrf } : {}),
      ...(opts.body ? { 'content-type': 'application/json' } : {}),
    },
    ...opts,
  });
  if (r.status === 401) {
    location.href = '/admin/start-login';
    throw new Error('unauthenticated');
  }
  const data = r.status === 204 ? null : await r.json().catch(() => null);
  if (!r.ok) {
    // Sudo window lapsed mid-session: reload through the shell, which routes
    // into the step-up challenge and returns to this same page.
    if (r.status === 403 && data && data.error === 'step_up_required') {
      location.reload();
      throw new Error('step_up_required');
    }
    const e = new Error((data && data.error) || 'http_' + r.status);
    e.status = r.status;
    e.data = data;
    throw e;
  }
  return data;
}

export async function getMe() {
  const me = await req('/me');
  csrf = me.csrf;
  return me;
}
// Unauthenticated branding endpoint (site name etc.) — lives outside /admin/api.
export const getPublicSettings = () =>
  fetch('/api/settings/public', { headers: { accept: 'application/json' } }).then((r) => r.json());
export const listClients = () => req('/clients');
export const createClient = (body) => req('/clients', { method: 'POST', body: JSON.stringify(body) });
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
