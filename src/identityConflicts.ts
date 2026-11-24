export type IdentityConflict = 'email' | 'username';

/** Identify only the identity indexes that arbitrate final uniqueness. */
export function identityConflict(error: unknown): IdentityConflict | null {
  if (error === null || typeof error !== 'object') return null;
  const { code, constraint } = error as { code?: unknown; constraint?: unknown };
  if (code !== '23505') return null;
  if (constraint === 'uq_identities_email') return 'email';
  if (constraint === 'uq_identities_username') return 'username';
  return null;
}
