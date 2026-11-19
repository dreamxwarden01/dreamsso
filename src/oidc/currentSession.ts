import type { Response, NextFunction } from 'express';
import type { AuthedRequest } from '../accountResourceAuth.js';

const UUID = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i;
export const SESSION_CONTEXT_MISMATCH = 'session_context_mismatch';

/** Call only after bearer verification and current-session liveness checks.
 * This binds caller context, never a target SID selected for administration.
 */
export function currentSessionContextError(auth: { sid?: string } | undefined, supplied: unknown,
  required = true): typeof SESSION_CONTEXT_MISMATCH | null {
  if (!auth?.sid || !UUID.test(auth.sid)) return SESSION_CONTEXT_MISMATCH;
  if (!required && supplied === undefined) return null;
  return typeof supplied === 'string' && UUID.test(supplied) && supplied.toLowerCase() === auth.sid.toLowerCase()
    ? null : SESSION_CONTEXT_MISMATCH;
}

export function requireCurrentSessionContext(select: (req: AuthedRequest) => unknown) {
  return (req: AuthedRequest, res: Response, next: NextFunction): void => {
    const error = currentSessionContextError(req.auth, select(req));
    if (error) { res.status(403).json({ error });return; }
    next();
  };
}
