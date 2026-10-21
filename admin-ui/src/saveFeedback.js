// A synchronous lock also protects against multiple clicks before React renders.
export function createSaveFeedback({ emit, now = () => performance.now(), schedule = setTimeout, cancel = clearTimeout }) {
  let token = 0;
  let locked = false;
  let started = 0;
  const timers = new Set();
  const later = (ms, fn, current = token) => {
    const timer = schedule(() => {
      timers.delete(timer);
      if (current === token) fn();
    }, ms);
    timers.add(timer);
  };
  const clear = () => {
    token++;
    timers.forEach(cancel);
    timers.clear();
    locked = false;
  };
  return {
    begin() {
      if (locked) return false;
      clear();
      locked = true;
      started = now();
      emit('pending');
      return true;
    },
    finish(outcome, onHoldEnd, keepSuccess = false) {
      if (!locked) return;
      later(Math.max(0, 450 - (now() - started)), () => {
        emit(outcome);
        later(2000, () => {
          if (keepSuccess) { onHoldEnd?.(); return; }
          emit('returning');
          later(220, () => { locked = false; emit('idle'); onHoldEnd?.(); });
        });
      });
    },
    reset() { clear(); emit('idle'); },
    dispose: clear,
  };
}

// Deliberately exclude server bodies, URLs, headers and arbitrary error text.
const knownCodes = new Set(['request_timeout', 'network_error', 'invalid_response', 'challenge_required',
  'permission_denied', 'csrf_failed', 'client_id_taken', 'validation_failed', 'invalid_client',
  'unauthenticated', 'step_up_required']);
export function feedbackTechnical(error) {
  if (!error) return '';
  const parts = [];
  if (Number.isInteger(error.status) && error.status >= 400 && error.status <= 599) parts.push(`HTTP ${error.status}`);
  if (knownCodes.has(error.code)) parts.push(`Code: ${error.code}`);
  if (error.uncertain) parts.push('Save outcome: unconfirmed');
  for (const key of ['jwks_uri', 'jwks_path', 'jwks']) {
    const diagnostic = keyFieldFeedback(key, error.data?.errors?.[key]).technical;
    if (diagnostic) parts.push(diagnostic);
  }
  return parts.join('\n');
}

// Match only the bounded diagnostic format emitted by safeKeyError(). Ordinary
// validation messages retain their original wording.
const keyCodes = new Set(['EACCES', 'EPERM', 'ECONNREFUSED', 'ENOTFOUND', 'EAI_AGAIN', 'ECONNRESET',
  'EHOSTUNREACH', 'ENETUNREACH', 'ETIMEDOUT', 'ERR_TLS_CERT_ALTNAME_INVALID',
  'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY', 'DEPTH_ZERO_SELF_SIGNED_CERT',
  'SELF_SIGNED_CERT_IN_CHAIN', 'CERT_HAS_EXPIRED', 'ERR_JWKS_TIMEOUT', 'ERR_JWKS_INVALID',
  'ERR_JWK_INVALID', 'ERR_JOSE_GENERIC', 'UNKNOWN']);
const keyReasons = new Set(['jwks_http_non_200', 'jwks_bad_json', 'jwks_timeout', 'invalid_key_material',
  'key_transport_or_material_failure', 'key_configuration_or_resolution_failure']);
export function keyFieldFeedback(key, message) {
  if (!['jwks', 'jwks_uri', 'jwks_path'].includes(key) || typeof message !== 'string') return { message };
  const match = /^JWKS check failed \(([A-Z_]+): ([a-z_]+)\)$/.exec(message);
  if (!match || !keyCodes.has(match[1]) || !keyReasons.has(match[2])) return { message };
  const [, code, reason] = match;
  let human = "The public keys could not be checked. Check the app's key configuration, then try again.";
  if (code === 'ECONNREFUSED') human = 'The app refused the connection. Check that it is running and serving public keys at this URL, then try again.';
  else if (code === 'ENOTFOUND' || code === 'EAI_AGAIN') human = 'The app hostname could not be resolved. Check the hostname and DNS, then try again.';
  else if (code === 'ETIMEDOUT' || code === 'ERR_JWKS_TIMEOUT' || reason === 'jwks_timeout') human = 'The public key request timed out. Check that the app and its key URL are reachable, then try again.';
  else if (reason === 'jwks_http_non_200') human = 'The public key URL did not return HTTP 200. Check the URL and app response, then try again.';
  else if (reason === 'jwks_bad_json') human = 'The public key URL did not return valid JSON. Check that it serves a public JWKS document, then try again.';
  else if (reason === 'invalid_key_material') human = 'The public keys are invalid or empty. Provide a JWKS document containing public signing keys, then try again.';
  else if (['ERR_TLS_CERT_ALTNAME_INVALID', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY',
    'DEPTH_ZERO_SELF_SIGNED_CERT', 'SELF_SIGNED_CERT_IN_CHAIN', 'CERT_HAS_EXPIRED'].includes(code)) human = 'The key URL certificate could not be verified. Check its hostname, certificate and trust chain, then try again.';
  else if (['ECONNRESET', 'EHOSTUNREACH', 'ENETUNREACH'].includes(code)) human = 'The connection to the public key URL failed. Check that the app is reachable, then try again.';
  return { message: human, technical: `${key}: ${code}: ${reason}` };
}
