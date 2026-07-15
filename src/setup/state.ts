import { pool } from '../db.js';
import { getSetting } from '../settings.js';
import { isConfigured } from '../config.js';

// First-run install state — monotonic RAM latches (false -> true, never back),
// resolved ONCE at boot and flipped in-process by the wizard. The setup gate reads
// these per request; the DB is the durable source of truth, consulted only at boot.
let complete = false;
let configured = false;

export function isSetupComplete(): boolean {
  return complete;
}
export function isSetupConfigured(): boolean {
  return configured;
}

// Flipped in-process by the wizard as it progresses (step 1 -> configured, finish
// transaction -> complete). Both are one-way.
export function markConfigured(): void {
  configured = true;
}
export function markComplete(): void {
  complete = true;
  configured = true;
}

// Resolve the initial state at boot. Installed = a superadmin exists OR the
// setup_complete flag is set. Any DB trouble (unreachable / schema-less) is treated
// as "not installed" → the process stays in setup mode.
export async function resolveSetupState(): Promise<void> {
  configured = isConfigured();
  complete = false;
  if (!configured) return;
  try {
    if (await getSetting('setup_complete')) {
      complete = true;
      return;
    }
    const { rows } = await pool.query(
      "SELECT 1 FROM user_org_roles WHERE org_role_slug = 'superadmin' LIMIT 1",
    );
    complete = rows.length > 0;
  } catch (err) {
    console.warn('setup: DB not ready at boot — entering setup mode:', (err as Error).message);
    configured = false;
    complete = false;
  }
}
