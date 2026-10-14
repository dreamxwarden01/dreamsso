// Shared pure rules: passkeys preempt TOTP for mandatory strong verification.
// Fallback/password/email policies remain in stepupPolicy.ts.
export const acceptedStrongStepup = (passkeys: number, totp: number): string[] =>
  passkeys > 0 ? ['passkey'] : totp > 0 ? ['totp'] : [];

export function stepupSatisfies(accepted: string[], method: string | null, fresh: boolean): boolean {
  return fresh && method != null && accepted.includes(method);
}

export function stepupValidityMinutes(value: string | null | undefined): number {
  const n = parseInt(value ?? '', 10);
  return Number.isFinite(n) && n >= 1 && n <= 1440 ? n : 30;
}

export function stepupStampFresh(stamp: number | null, minutes: number, now = Date.now()): boolean {
  return !!stamp && now / 1000 - stamp < minutes * 60;
}
