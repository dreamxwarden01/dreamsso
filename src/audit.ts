import { pool } from './db.js';

// Org audit log writer — every org-management mutation records who did what to
// whom. Labels are snapshots (stay readable after renames); timestamps UTC.
// Fire-and-forget: auditing must never fail the action it describes.
export interface AuditEntry {
  actorSub?: string | null; // null/absent = system-originated (e.g. roles.sync reconciliation)
  actorLabel: string;
  targetSub?: string;
  targetLabel?: string;
  action: string; // e.g. 'user.role_change', 'user.password_set', 'logs.clear'
  detail?: Record<string, unknown>;
}

export function audit(e: AuditEntry): void {
  pool
    .query(
      `INSERT INTO org_audit_log (actor_sub, actor_label, target_sub, target_label, action, detail)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [e.actorSub ?? null, e.actorLabel, e.targetSub ?? null, e.targetLabel ?? null, e.action, JSON.stringify(e.detail ?? {})],
    )
    .catch((err) => console.warn('audit write failed:', (err as Error).message));
}

export async function actorLabel(sub: string): Promise<string> {
  const { rows: [id] } = await pool.query(
    'SELECT display_name, username FROM identities WHERE sub = $1',
    [sub],
  );
  return id?.display_name || id?.username || sub;
}
