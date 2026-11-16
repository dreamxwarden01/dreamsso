import type { Request } from 'express';

// Cookie authentication needs an exact origin boundary, including between sibling
// subdomains. Use configuration, never attacker-supplied Host/forwarded headers.
export function isTrustedMutation(req: Pick<Request, 'method' | 'get'>, publicUrl: string, redirectUri: string): boolean {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return true;
  try {
    const expected = new URL(publicUrl || redirectUri);
    if (!['https:', 'http:'].includes(expected.protocol)) return false;
    const site = req.get('Sec-Fetch-Site');
    if (site && site !== 'same-origin') return false;
    const origin = req.get('Origin');
    if (origin !== undefined) {
      const source = new URL(origin);
      return source.origin === expected.origin && origin === source.origin;
    }
    // Older clients may omit Origin; their Referer must still prove the origin.
    const referer = req.get('Referer');
    return !!referer && new URL(referer).origin === expected.origin;
  } catch {
    return false;
  }
}
