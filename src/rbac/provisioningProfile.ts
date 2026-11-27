/** Creation-only metadata for an RP that has not seen this subject yet. */
export interface ProvisioningProfile {
  preferred_username?: string;
  name?: string;
  picture?: string | null;
  email?: string | null;
  email_verified?: boolean;
}
export interface ProvisioningIdentity {
  user_sub: string;
  username: unknown;
  display_name: unknown;
  avatar: unknown;
  email: unknown;
  email_verified: unknown;
}

const bounded = (value: unknown, max: number): value is string =>
  typeof value === 'string' && Array.from(value).length >= 1 && Array.from(value).length <= max
  && value.trim().length > 0 && !/[\u0000-\u001f\u007f\ud800-\udfff]/u.test(value);

/**
 * Match the destination's registered OIDC claim scopes. Historical malformed
 * display metadata must not prevent an authority mutation from committing.
 * Omit only an invalid claim group rather than truncating an identity or
 * exposing values in diagnostics. Even an empty seed preserves the intent to
 * create a subject-only RP entry. Existing RP users are never updated here.
 */
export function provisioningProfile(identity: ProvisioningIdentity, scopes: unknown,
  report: () => void = () => console.warn('provisioning_profile_omitted')): ProvisioningProfile {
  const profile: ProvisioningProfile = {};
  const invalid = (): void => { try { report(); } catch { /* Diagnostics cannot block authority changes. */ } };
  if (!Array.isArray(scopes) || scopes.some(scope => typeof scope !== 'string')) {
    invalid();
    return profile;
  }
  if (scopes.includes('profile')) {
    if (!bounded(identity.username, 20) || !bounded(identity.display_name, 100)
      || !(identity.avatar === null || typeof identity.avatar === 'string'
        && identity.avatar.startsWith(identity.user_sub + '-')
        && /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}-[0-9a-f]{16}\.webp$/.test(identity.avatar))) invalid();
    else {
      profile.preferred_username = identity.username;
      profile.name = identity.display_name;
      profile.picture = identity.avatar;
    }
  }
  if (scopes.includes('email')) {
    if (!(identity.email === null || bounded(identity.email, 254)) || typeof identity.email_verified !== 'boolean') invalid();
    else {
      profile.email = identity.email;
      profile.email_verified = identity.email_verified;
    }
  }
  // An empty seed still identifies an allowed account for a scope-minimal RP;
  // it carries provisioning intent without disclosing unregistered claims.
  return profile;
}
