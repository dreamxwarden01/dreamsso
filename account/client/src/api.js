// Optional hook fired when a request is rejected for a permission reason, so the
// app can re-sync the effective permission set (AuthContext registers reload()).
let onPermissionDenied = null;
export function setPermissionDeniedHandler(fn) {
  onPermissionDenied = fn;
}

// Optional hook fired when a request is rejected because the step-up sudo window
// is expired/absent (403 step_up_required), so the app can re-open the step-up
// modal. OrgGate registers its recheck while the org area is mounted; other
// surfaces (factor pages) handle step_up_required per-call, so this stays null
// there and the hook is a no-op. Mirrors onPermissionDenied.
let onStepUpRequired = null;
export function setStepUpRequiredHandler(fn) {
  onStepUpRequired = fn;
}

// Thin client for the BFF. A 401 means "no server session" -> bounce to the
// BFF login (which round-trips the SSO and returns here).
async function req(path, opts = {}) {
  const r = await fetch(path, {
    credentials: 'same-origin',
    headers: { accept: 'application/json', ...(opts.body ? { 'content-type': 'application/json' } : {}) },
    ...opts,
  });
  if (r.status === 401) {
    const rt = encodeURIComponent(location.pathname + location.search);
    location.href = '/auth/login?returnTo=' + rt;
    throw new Error('unauthenticated');
  }
  const data = r.status === 204 ? null : await r.json().catch(() => null);
  if (!r.ok) {
    const e = new Error((data && data.error) || 'http_' + r.status);
    e.status = r.status;
    e.data = data;
    e.code = data && data.error; // 'permission_denied' | 'step_up_required' | ...
    // A rejected action may mean the user's permissions changed under them; re-sync.
    if (r.status === 403 && e.code === 'permission_denied' && onPermissionDenied) {
      try {
        onPermissionDenied();
      } catch {
        /* never let the resync hook mask the original error */
      }
    }
    // A stale sudo window: any org read/mutation now 403s step_up_required — let
    // the registered handler (OrgGate) re-open the challenge. The method lets it
    // treat a read (re-gate + refetch) differently from a mutation (overlay the
    // challenge without tearing down the pane, so staged edits survive).
    if (r.status === 403 && e.code === 'step_up_required' && onStepUpRequired) {
      try {
        onStepUpRequired((opts.method || 'GET').toUpperCase());
      } catch {
        /* never let the hook mask the original error */
      }
    }
    throw e;
  }
  return data;
}

export const getMe = () => req('/api/me');
export const updateProfile = (patch) => req('/api/profile', { method: 'PATCH', body: JSON.stringify(patch) });

// Security pane
export const getSecurity = () => req('/api/security');
export const mfaEnable = () => req('/api/security/mfa/enable', { method: 'POST' });
export const mfaDisable = () => req('/api/security/mfa/disable', { method: 'POST' });
export const changePassword = (body) => req('/api/security/password', { method: 'POST', body: JSON.stringify(body) });
export const authenticatorSetup = (body = {}) =>
  req('/api/security/authenticator/setup', { method: 'POST', body: JSON.stringify(body) });
export const authenticatorConfirm = (body) =>
  req('/api/security/authenticator/confirm', { method: 'POST', body: JSON.stringify(body) });
export const renameAuthenticator = (id, label) =>
  req('/api/security/authenticator/' + encodeURIComponent(id), { method: 'PATCH', body: JSON.stringify({ label }) });
export const removeAuthenticator = (id) =>
  req('/api/security/authenticator/' + encodeURIComponent(id), { method: 'DELETE' });

export const passkeyRegisterOptions = () =>
  req('/api/security/passkey/register-options', { method: 'POST', body: '{}' });
export const passkeyRegister = (credential, label) =>
  req('/api/security/passkey/register', { method: 'POST', body: JSON.stringify({ credential, label }) });
export const renamePasskey = (id, label) =>
  req('/api/security/passkey/' + encodeURIComponent(id), { method: 'PATCH', body: JSON.stringify({ label }) });
export const removePasskey = (id) =>
  req('/api/security/passkey/' + encodeURIComponent(id), { method: 'DELETE' });

// Step-up (sudo window)
// mode: 'strong-mandatory' (org/admin, default) | 'fallback' (personal security).
export const getStepupStatus = (mode) => req('/api/stepup/status' + (mode ? '?mode=' + encodeURIComponent(mode) : ''));
export const stepupPasskeyOptions = () => req('/api/stepup/passkey-options', { method: 'POST', body: '{}' });
export const stepupVerify = (body) => req('/api/stepup/verify', { method: 'POST', body: JSON.stringify(body) });
export const stepupSendEmail = () => req('/api/stepup/send-email', { method: 'POST', body: '{}' });

// Org management — generic helper: the BFF passes /api/org/* straight through
// to the SSO's /account/org/*.
export const orgApi = (method, path, body) =>
  req('/api/org' + path, { method, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
export const getOrgDashboard = () => req('/api/org/dashboard');
export const getOrgLogs = ({ cursor, includeCleared, limit } = {}) => {
  const u = new URLSearchParams();
  if (cursor) u.set('cursor', cursor);
  if (includeCleared) u.set('include_cleared', '1');
  if (limit) u.set('limit', String(limit));
  const q = u.toString();
  return req('/api/org/logs' + (q ? '?' + q : ''));
};
export const clearOrgLogs = (ids) => req('/api/org/logs/clear', { method: 'POST', body: JSON.stringify({ ids }) });

// Devices pane
export const getSessions = () => req('/api/sessions');
export const terminateSession = (sid) =>
  req('/api/sessions/' + encodeURIComponent(sid), { method: 'DELETE' });
export const terminateOtherSessions = () =>
  req('/api/sessions/terminate-others', { method: 'POST' });

// --- password reset (public pages — NO 401-redirect wrapper: these endpoints
// never require a session, and a visitor on /forgot must not get bounced) ---
async function reqPublic(path, body) {
  const r = await fetch(path, {
    method: 'POST',
    credentials: 'same-origin',
    headers: { accept: 'application/json', 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  const data = r.status === 204 ? null : await r.json().catch(() => null);
  if (!r.ok) {
    const e = new Error((data && data.error) || 'http_' + r.status);
    e.status = r.status;
    e.data = data;
    e.code = data && data.error;
    throw e;
  }
  return data;
}
export const resetRequest = (identifier, turnstileToken) =>
  reqPublic('/api/reset/request', { identifier, turnstile_token: turnstileToken ?? undefined });
export const resetValidate = (token) => reqPublic('/api/reset/validate', { token });
export const resetPasskeyOptions = (token) => reqPublic('/api/reset/passkey-options', { token });
// credential travels as a JSON string (the SSO parses it server-side).
export const resetConfirm = (body) => reqPublic('/api/reset/confirm', body);

// --- email verification (verify-then-commit) ---
export const emailChangeGet = () => req('/api/email-change');
export const emailChangeStart = (body) => req('/api/email-change/start', { method: 'POST', body: JSON.stringify(body) });
export const emailChangeResend = () => req('/api/email-change/resend', { method: 'POST', body: '{}' });
export const emailChangeCancel = () => req('/api/email-change', { method: 'DELETE' });
export const emailVerifySend = () => req('/api/email/verify/send', { method: 'POST', body: '{}' });
export const usernameChange = (body) => req('/api/username-change', { method: 'POST', body: JSON.stringify(body) });
export const emailChangeCheck = (newEmail) =>
  req('/api/email-change/check', { method: 'POST', body: JSON.stringify({ new_email: newEmail }) });
export const usernameChangeCheck = (newUsername) =>
  req('/api/username-change/check', { method: 'POST', body: JSON.stringify({ new_username: newUsername }) });
export const verifyEmail = (token) => reqPublic('/api/verify-email', { token });

// --- registration (public, invitation-gated upstream) ---
export const registerStart = (email, code, turnstileToken) =>
  reqPublic('/api/register/start', { email, code: code || undefined, turnstile_token: turnstileToken ?? undefined });
export const registerValidate = (email, token) => reqPublic('/api/register/validate', { email, token });
export const registerCheckUsername = (email, token, username) =>
  reqPublic('/api/register/check-username', { email, token, username });
export const registerComplete = (body) => reqPublic('/api/register/complete', body);

// --- profile picture ---
export const avatarUrl = (f) => '/api/avatar/' + encodeURIComponent(f);
export const deleteAvatar = () => req('/api/avatar', { method: 'DELETE' });
// Binary upload — bespoke (req() would JSON-ify); same 401-bounce semantics.
export async function uploadAvatar(blob) {
  const r = await fetch('/api/avatar', {
    method: 'POST',
    credentials: 'same-origin',
    headers: { accept: 'application/json', 'content-type': blob.type || 'image/webp' },
    body: blob,
  });
  if (r.status === 401) {
    const rt = encodeURIComponent(location.pathname + location.search);
    location.href = '/auth/login?returnTo=' + rt;
    throw new Error('unauthenticated');
  }
  const data = r.status === 204 ? null : await r.json().catch(() => null);
  if (!r.ok) {
    const e = new Error((data && data.error) || 'http_' + r.status);
    e.status = r.status;
    e.data = data;
    e.code = data && data.error;
    throw e;
  }
  return data;
}

export function logout() {
  // Front-channel logout: navigate to the BFF, which clears the server session
  // and redirects to the SSO end_session endpoint (-> "signed out" page).
  location.href = '/auth/logout';
}
