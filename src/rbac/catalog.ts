// The RBAC permission catalog — the single source of truth for permission keys
// and the per-system-role defaults. Mirrors `RBAC model draft.xlsx` (sheet "SSO").
// Keys are defined HERE (each maps to a real enforcement point); the DB stores
// assignments (role_permissions) + per-user overrides. scripts/seed-rbac.ts seeds
// role_permissions from these defaults. Scope: SSO + account-portal only — app
// roles (videosite:user, …) are a separate model (Phase B / delegation).
export type Effect = 'grant' | 'deny';
export type SystemRole = 'superadmin' | 'admin' | 'standard_user';

// Lower level number = higher privilege (sorting + edit-authority). Gaps left for
// custom roles between the system tiers.
export const SYSTEM_ROLES: { slug: SystemRole; label: string; level: number }[] = [
  { slug: 'superadmin', label: 'Superadmin', level: 0 },
  { slug: 'admin', label: 'Admin', level: 1 },
  { slug: 'standard_user', label: 'Standard user', level: 10 },
];

export interface PermDef {
  key: string;
  group: 'profile' | 'org';
  defaults: Record<SystemRole, Effect>;
  description?: string;
}

const G: Effect = 'grant';
const D: Effect = 'deny';
// p(key, superadmin, admin, standard_user, description?)
const p = (key: string, sa: Effect, ad: Effect, su: Effect, description?: string): PermDef => ({
  key,
  group: key.startsWith('profile.') ? 'profile' : 'org',
  defaults: { superadmin: sa, admin: ad, standard_user: su },
  description,
});

export const PERMISSIONS: PermDef[] = [
  // --- self-service (profile page) — gated, NOT baseline ---
  p('profile.displayname.change', G, G, G),
  p('profile.picture.set', G, G, G, 'upload/replace/remove own profile picture'),
  p('profile.username.change', G, D, D),
  p('profile.email.add', G, G, G, 'external address only, if none yet'),
  p('profile.email.change', G, G, G, 'external address only'),
  p('profile.email.setPrimary', G, G, G, 'primary contact for MFA/notifications; one external + future internal addresses'),
  p('profile.security.password.change', G, G, G),
  p('profile.security.sessions.view', G, G, G),
  p('profile.security.sessions.terminate', G, G, G),
  p('profile.security.mfa.enable', G, G, G),
  p('profile.security.mfa.disable', D, D, G, 'privileged roles keep a strong factor; gates last-strong-factor removal'),
  p('profile.security.mfa.totp.add', G, G, G),
  p('profile.security.mfa.totp.rename', G, G, G),
  p('profile.security.mfa.totp.remove', G, G, G),
  p('profile.security.mfa.passkey.add', G, G, G),
  p('profile.security.mfa.passkey.rename', G, G, G),
  p('profile.security.mfa.passkey.remove', G, G, G),

  // --- org: act on OTHER users (org-users page) ---
  p('org.users.view', G, G, D, 'list + read users'),
  p('org.users.create', G, G, D),
  p('org.users.edit.displayname', G, G, D),
  p('org.users.edit.username', G, G, D),
  p('org.users.edit.profilePicture.remove', G, G, D, "remove a user's profile picture (no set — pictures are self-service)"),
  p('org.users.edit.email', G, G, D, 'external address only; internal in the mailer app'),
  p('org.users.edit.password', G, G, D),
  p('org.users.edit.permissions.acctPortal', G, G, D),
  p('org.users.edit.permissions.app', G, G, D),
  p('org.users.edit.sessions.view', G, G, D),
  p('org.users.edit.sessions.terminate', G, G, D, 'not valid without view'),
  p('org.users.edit.deactivate', G, G, D),
  p('org.users.edit.reactivate', G, G, D),
  p('org.users.edit.mfa.view', G, G, D),
  p('org.users.edit.mfa.disable', G, G, D, 'toggle off MFA without reset'),
  p('org.users.edit.mfa.reset', G, G, D, 'remove all TOTP + passkeys, reset toggle'),
  p('org.users.remove', G, D, D),

  // --- org: roles ---
  p('org.roles.view', G, G, D, 'list + read roles'),
  p('org.roles.create', G, G, D),
  p('org.roles.edit.permissions.acctPortal', G, G, D),
  p('org.roles.edit.permissions.app', G, G, D),
  p('org.roles.edit.level', G, G, D),
  p('org.roles.edit.rename', G, G, D),
  p('org.roles.remove', G, G, D),

  // --- org: apps (mirrored role catalogs) ---
  p('org.apps.view', G, G, D, 'app role catalogs (Apps pane)'),
  p('org.apps.sync', G, G, D, 'request a fresh roles.sync from an app'),
  p('org.roles.edit.default', G, G, D, 'move the singular default org role'),

  // --- org: dashboard + audit log ---
  p('org.dashboard', G, G, D, 'organization dashboard (stats + recent activity)'),
  p('org.logs.view', G, G, D, 'the org audit log'),
  p('org.logs.clear', G, D, D, 'soft-hide log entries (cleared, never deleted)'),

  // --- org: invitation codes (registration) ---
  p('org.invites.view', G, G, D, 'list invitation codes (creator same-or-lower level)'),
  p('org.invites.create', G, G, D, 'invited role strictly below own — the lowest role cannot invite'),
  p('org.invites.void', G, D, D, "void OTHERS' codes; own un-consumed codes are always voidable"),

  // --- org: site-level ---
  p('org.siteSettings.acctPortal', G, D, D),
  p('org.siteSettings.sso', G, D, D, 'access the SSO /admin page'),
  p('org.mfaPolicies.view', G, D, D),
  p('org.mfaPolicies.edit', G, D, D, 'not valid without view'),
];

export const PERM_KEYS: ReadonlySet<string> = new Set(PERMISSIONS.map((d) => d.key));
