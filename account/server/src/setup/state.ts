import { isConfigured } from '../config.js';

// First-run install state — a monotonic RAM latch (false -> true, never back),
// resolved once at boot and flipped in-process by the wizard. The BFF has no DB,
// so "installed" is DERIVED: .env has the SSO + our callback, and the client-key
// file exists. That means a hand-configured portal never sees the wizard.
let complete = false;

export function isSetupComplete(): boolean {
  return complete;
}

// Flipped in-process by the wizard's finish step.
export function markComplete(): void {
  complete = true;
}

export function resolveSetupState(): void {
  complete = isConfigured();
}
