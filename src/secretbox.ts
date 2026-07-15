import crypto from 'node:crypto';
import { config } from './config.js';

// AES-256-GCM at rest — same layout as keys.ts: [ iv(12) | tag(16) | ciphertext ],
// key = KEY_ENCRYPTION_KEY. Used for TOTP secrets (totp_credentials.secret_enc).
export function sealSecret(plaintext: string): Buffer {
  const key = Buffer.from(config.keyEncryptionKey, 'hex');
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), ct]);
}

export function openSecret(buf: Buffer): string {
  const key = Buffer.from(config.keyEncryptionKey, 'hex');
  const d = crypto.createDecipheriv('aes-256-gcm', key, buf.subarray(0, 12));
  d.setAuthTag(buf.subarray(12, 28));
  return Buffer.concat([d.update(buf.subarray(28)), d.final()]).toString('utf8');
}
