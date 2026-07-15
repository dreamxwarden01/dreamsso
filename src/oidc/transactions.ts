import crypto from 'node:crypto';
import { redis } from '../redis.js';

// A login transaction holds the in-flight /authorize request while the user
// authenticates. Server-side (Redis), referenced by an unguessable id. Replaces
// CAS's fat client-side `execution` blob. ~10 min TTL.
export interface LoginTxn {
  clientId: string;
  redirectUri: string;
  state?: string;
  nonce?: string;
  codeChallenge: string;
  codeChallengeMethod: string;
  scope: string;
  acrValues?: string;
  clientName?: string;
  // First-party local login (e.g. /admin): after auth, redirect to this local
  // path instead of minting a code. No OIDC client involved; the OIDC fields
  // above are empty strings for these txns.
  localNext?: string;
  // First-factor passkey challenge, minted at login-page render (conditional UI
  // + the explicit button share it). Reused across sheet-reopens; consumed per
  // verification attempt (regenerated on failure).
  passkey?: string;
  // Set after the password is verified when a second factor is required — the
  // txn then represents the CHALLENGE phase (no session exists yet).
  mfa?: {
    sub: string;
    userLabel: string; // challenge-chip label: the TYPED identifier at login (username or email);
                       // the display name for a step-up challenge (already authenticated).
    kmsiLabel?: string; // display name to show on the KMSI page after a login MFA challenge.
    methods: string[]; // computed server-side: only what the user owns
    attempts: number;
    maskedEmail?: string; // present when 'email' is the method
    emailSent?: boolean; // the offer was clicked — render the entry state
    passkeyChallenge?: string; // challenge-phase assertion challenge (same consume rules)
    // Step-up mode (the /admin door): success STAMPS this existing session's sudo
    // window instead of creating a session; localNext carries the return path.
    stepupSid?: string;
    // OIDC step-up mode (an RP like videosite): success MINTS a code for this
    // existing session (fresh factor amr, no new session, no KMSI) and returns it
    // to the RP via the txn's redirectUri/state. Distinct from stepupSid, which
    // is local-only. The RP records its own sudo window from the returned token.
    stepupReturn?: { sid: string };
  };
  // Auth complete, "Stay signed in?" pending: the session exists (transient
  // cookie already set); the answer optionally persists it, then the code is
  // minted / localNext redirected.
  kmsi?: {
    sid: string;
    sub: string;
    userLabel: string;
    amr: string[];
    acr: string;
    authTime: number;
  };
  csrf: string;
}

const KEY = (id: string) => `txn:${id}`;
const TTL_SECONDS = 600;

export async function createTxn(data: Omit<LoginTxn, 'csrf'>): Promise<string> {
  const id = crypto.randomBytes(24).toString('base64url');
  const txn: LoginTxn = { ...data, csrf: crypto.randomBytes(24).toString('base64url') };
  await redis.set(KEY(id), JSON.stringify(txn), 'EX', TTL_SECONDS);
  return id;
}

export async function getTxn(id: string): Promise<LoginTxn | null> {
  if (!id) return null;
  const raw = await redis.get(KEY(id));
  return raw ? (JSON.parse(raw) as LoginTxn) : null;
}

// Rewrite a txn in place (challenge-phase transitions), preserving the TTL.
export async function updateTxn(id: string, txn: LoginTxn): Promise<void> {
  await redis.set(KEY(id), JSON.stringify(txn), 'KEEPTTL');
}

export async function consumeTxn(id: string): Promise<void> {
  await redis.del(KEY(id));
}
