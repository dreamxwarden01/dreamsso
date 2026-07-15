// Shared normalization + validation for the admin client form — imported by BOTH
// the admin API (server) and the admin SPA (Vite pulls this file into the bundle),
// so the rules can't drift. Framework-free on purpose.
//
// Model: a client is registered as ONE https hostname + relative paths; the server
// composes `https://{hostname}{path}` into the stored full URLs. Normalization
// runs on blur in the form and again on the API. Redundant decoration (scheme,
// whitespace, backslashes, a same-host prefix) is stripped silently; anything that
// would CHANGE MEANING if stripped (a port, a foreign host) is an error instead.

export interface Norm {
  value: string;
  error: string | null;
}

const strip = (s: string) => s.replace(/\s+/g, '').replace(/\\/g, '/');

const HOSTNAME_RE = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/;

// Hostname field: strip whitespace/backslashes, drop a pasted scheme and any
// path/query/hash, lowercase. A remaining :port is an error (https/443 only).
export function normalizeHostname(input: string): Norm {
  let v = strip(input);
  v = v.replace(/^[a-z][a-z0-9+.-]*:\/\//i, ''); // scheme
  v = v.replace(/^\/\//, '');
  const cut = v.search(/[/?#]/); // path / query / hash
  if (cut >= 0) v = v.slice(0, cut);
  v = v.toLowerCase();
  if (!v) return { value: v, error: 'Required' };
  if (/:\d*$/.test(v)) return { value: v, error: 'Ports aren’t allowed — clients are reached over https (443)' };
  if (v.includes(':')) return { value: v, error: 'Invalid hostname' };
  if (!HOSTNAME_RE.test(v)) return { value: v, error: 'Invalid hostname' };
  return { value: v, error: null };
}

// Path field: strip whitespace/backslashes; a pasted full URL keeps only its
// path+query IF its host matches the client's hostname (a foreign host is an
// error, never silently stripped). Guarantees a leading '/', collapses '//'.
export function normalizePath(input: string, hostname: string, opts?: { required?: boolean }): Norm {
  let v = strip(input);
  if (!v) return { value: v, error: opts?.required ? 'Required' : null };

  if (/^([a-z][a-z0-9+.-]*:)?\/\//i.test(v)) {
    // Full URL pasted — decompose it.
    let u: URL;
    try {
      u = new URL(v.startsWith('//') ? 'https:' + v : v);
    } catch {
      return { value: v, error: 'Invalid URL' };
    }
    if (!hostname) return { value: v, error: 'Set the hostname first' };
    if (u.hostname.toLowerCase() !== hostname) {
      return { value: v, error: `Belongs to a different host (${u.hostname.toLowerCase()})` };
    }
    if (u.port) return { value: v, error: 'Ports aren’t allowed — clients are reached over https (443)' };
    v = u.pathname + u.search;
  }

  if (!v.startsWith('/')) v = '/' + v;
  v = v.replace(/\/{2,}/g, '/');
  if (!/^\/[!-~]*$/.test(v)) return { value: v, error: 'Invalid characters in path' };
  return { value: v, error: null };
}

// client_id: username-like slug, immutable after creation.
export const SLUG_RE = /^[a-z0-9](?:[a-z0-9_-]{0,62}[a-z0-9])?$/;
export function normalizeSlug(input: string): Norm {
  const v = strip(input).toLowerCase();
  if (!v) return { value: v, error: 'Required' };
  if (!SLUG_RE.test(v)) {
    return { value: v, error: 'Lowercase letters, digits, - or _ (2–64 chars, alphanumeric ends)' };
  }
  return { value: v, error: null };
}

// Display name: the one field where inner whitespace is legitimate.
export function normalizeName(input: string): Norm {
  const v = input.trim();
  if (!v) return { value: v, error: 'Required' };
  if (v.length > 100) return { value: v, error: 'Max 100 characters' };
  return { value: v, error: null };
}

export const composeUrl = (hostname: string, path: string) => `https://${hostname}${path}`;

// Decompose a stored full URL against a hostname (for prefilling the form).
// Returns null when the URL doesn't belong to that host.
export function decomposeUrl(url: string, hostname: string): string | null {
  try {
    const u = new URL(url);
    return u.hostname.toLowerCase() === hostname ? u.pathname + u.search : null;
  } catch {
    return null;
  }
}
