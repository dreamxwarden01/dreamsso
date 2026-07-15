import argon2 from 'argon2';
import { pool } from '../db.js';

export interface Identity {
  sub: string;
  username: string;
  display_name: string;
  email: string | null;
  status: string;
  password_hash: string | null;
  mfa_enabled: boolean; // the account MFA toggle — challenge at login only when true
}

// username is citext -> this lookup is case-insensitive, matching videosite.
export async function findByUsername(username: string): Promise<Identity | null> {
  const { rows } = await pool.query(
    `SELECT sub, username, display_name, email, status, password_hash, mfa_enabled
     FROM identities WHERE username = $1 AND deleted_at IS NULL`,
    [username],
  );
  return rows[0] ?? null;
}

// email is citext with a unique partial index (where not deleted) -> case-insensitive, at most one.
export async function findByEmail(email: string): Promise<Identity | null> {
  const { rows } = await pool.query(
    `SELECT sub, username, display_name, email, status, password_hash, mfa_enabled
     FROM identities WHERE email = $1 AND deleted_at IS NULL`,
    [email],
  );
  return rows[0] ?? null;
}

// Resolve a login identifier the way videosite does (auth.js): try username first,
// then fall back to email only when the input looks like one ('@'). Username takes
// precedence so a username can never be shadowed by someone else's email.
export async function findByUsernameOrEmail(identifier: string): Promise<Identity | null> {
  const id = await findByUsername(identifier);
  if (id) return id;
  return identifier.includes('@') ? findByEmail(identifier) : null;
}

export async function verifyPassword(identity: Identity, password: string): Promise<boolean> {
  if (!identity.password_hash) return false;
  try {
    return await argon2.verify(identity.password_hash, password);
  } catch {
    return false;
  }
}
