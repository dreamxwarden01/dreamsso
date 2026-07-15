// Initials for the placeholder avatar (real photo upload lands later).
// Rule: first letter of the first and last word; a single word (or a bare
// username fallback) gives just its first letter.
export function initials(name) {
  if (!name) return '?';
  const parts = String(name).trim().split(/\s+/).filter(Boolean);
  if (parts.length === 0) return '?';
  if (parts.length === 1) return parts[0][0].toUpperCase();
  return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
}
