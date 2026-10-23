/** Login returns only to a concrete admin-console route, never a URL supplied
 * by the caller. Reject backslashes/controls before browsers can normalize them.
 */
export function adminReturnPath(value: unknown): string {
  if (typeof value !== 'string' || value.length > 512 || /[\\\u0000-\u0020\u007f]/.test(value)) return '/admin';
  let path: string;
  try { path = decodeURIComponent(value); } catch { return '/admin'; }
  return /^\/admin(?:\/(?:clients(?:\/[a-z0-9][a-z0-9_-]{0,63})?|keys|settings))?\/?$/.test(path)
    ? path : '/admin';
}
