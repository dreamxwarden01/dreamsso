// Keep API field names aligned with the form, including its inactive key mode.
export function normalizeClientErrors(errors) {
  if (!errors || typeof errors !== 'object' || Array.isArray(errors)) return {};
  return Object.fromEntries(Object.entries(errors)
    .filter(([, message]) => typeof message === 'string' && message)
    .map(([key, message]) => [key === 'jwks_uri' ? 'jwks_path' : key, message]));
}

export function activeClientErrors(errors, keyMode) {
  return Object.fromEntries(Object.entries(errors).filter(([key, message]) => message &&
    !(key === 'jwks' && keyMode === 'uri') && !(key === 'jwks_path' && keyMode === 'inline')));
}

export function clientErrorsForDisplay(localErrors, serverErrors) {
  return { ...serverErrors, ...Object.fromEntries(Object.entries(localErrors).filter(([, message]) => message)) };
}

export function changedClientFields(current, patch) {
  return Object.fromEntries(Object.entries(patch).filter(([key, value]) => {
    const previous = current[key];
    return !(Object.is(previous, value) || (Array.isArray(previous) && Array.isArray(value) &&
      previous.length === value.length && previous.every((item, index) => Object.is(item, value[index]))));
  }));
}

export function missingClientFields(form, { isNew, externalJwksUri, hasInlineJwks } = {}) {
  const missing = [];
  if (isNew && !form?.client_id?.trim()) missing.push('Client ID');
  if (!form?.name?.trim()) missing.push('Display name');
  if (!form?.hostname?.trim()) missing.push('Hostname');
  if (!form?.redirect_paths?.some((path) => path.trim())) missing.push('Redirect path');
  if (form?.key_mode === 'uri') {
    if (!form.jwks_path?.trim() && !externalJwksUri) missing.push('JWKS URL');
  } else if (!form?.jwks_text?.trim() && !hasInlineJwks) missing.push('Public JWKS');
  return missing;
}

export function clearEditedServerErrors(errors, patch) {
  const edited = new Set(Object.keys(patch).map((key) => key === 'jwks_text' ? 'jwks' : key));
  return Object.fromEntries(Object.entries(errors).filter(([key]) => {
    if (edited.has(key)) return false;
    if (edited.has('redirect_paths') && key.startsWith('redirect_paths.')) return false;
    if (edited.has('hostname') && (key.startsWith('redirect_paths') || key === 'events_path' || key === 'jwks_path')) return false;
    if (edited.has('key_mode') && (key === 'jwks' || key === 'jwks_path')) return false;
    return true;
  }));
}

const fields = new Set(['client_id', 'name', 'hostname', 'redirect_paths', 'events_path',
  'jwks_path', 'jwks', 'allowed_scopes', 'is_first_party', 'entry_policy']);

// Only local errors on active, editable fields block submission. Server errors
// remain retryable: an external condition may have changed since the last save.
export function hasBlockingClientErrors(localErrors, keyMode) {
  return Object.keys(activeClientErrors(localErrors, keyMode))
    .some((key) => fields.has(key) || /^redirect_paths\.\d+$/.test(key));
}

export function removeRedirectErrors(errors, removedIndex) {
  return Object.fromEntries(Object.entries(errors).flatMap(([key, message]) => {
    if (key === 'redirect_paths') return [];
    const match = /^redirect_paths\.(\d+)$/.exec(key);
    if (!match) return [[key, message]];
    const index = Number(match[1]);
    if (index === removedIndex) return [];
    return [[`redirect_paths.${index > removedIndex ? index - 1 : index}`, message]];
  }));
}

export function clientErrorLabel(key) {
  const redirect = /^redirect_paths\.(\d+)$/.exec(key);
  if (redirect) return `Redirect path ${Number(redirect[1]) + 1}`;
  const labels = { client_id: 'Client ID', name: 'Display name', hostname: 'Hostname',
    redirect_paths: 'Redirect paths', events_path: 'Back-channel events path',
    jwks_path: 'JWKS URL', jwks: 'Public JWKS', allowed_scopes: 'Allowed scopes',
    is_first_party: 'First-party', entry_policy: 'Entry policy' };
  return Object.hasOwn(labels, key) ? labels[key] : key;
}
