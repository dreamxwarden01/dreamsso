// Client-side twin of the SSO's check-side wildcard matcher (rbac/index.ts):
// '*' = exactly one segment; '**' = any non-empty suffix, terminal only
// ('org.**.d' is invalid and matches nothing). Grants stay concrete keys —
// patterns exist only in checks like canAny('org.**').
export function matchPerm(pattern, key) {
  const ps = pattern.split('.');
  const ks = key.split('.');
  for (let i = 0; i < ps.length; i++) {
    if (ps[i] === '**') return i === ps.length - 1 && ks.length > i;
    if (ks.length <= i) return false;
    if (ps[i] !== '*' && ps[i] !== ks[i]) return false;
  }
  return ks.length === ps.length;
}
