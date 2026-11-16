/** Requested scope must remain within the registered grant, at both endpoints. */
export function scopesAllowed(scope: string, allowed: unknown): boolean {
  if (!Array.isArray(allowed) || allowed.some(value => typeof value !== 'string')) return false;
  const requested = scope.split(' ').filter(Boolean);
  return requested.includes('openid') && requested.every(value => allowed.includes(value));
}
