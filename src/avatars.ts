import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import sharp from 'sharp';

// Profile-picture storage: processed images live on local disk as
// {sub}-{16 hex}.webp. The random suffix is the capability — the name is
// unguessable, changes on every upload (so it can be cached for a year with
// `immutable`), and a collision would only ever show a stale picture, never
// someone else's (the sub prefix scopes the name).
//
// Processing rules (server never trusts the client's crop):
//   - decode or reject (unprocessable_image)
//   - EXIF orientation applied, all metadata stripped by re-encode
//   - non-1:1 -> center-crop the largest square
//   - larger than 512 -> downscale to 512; smaller stays as-is (always 1:1)
//   - output is always WebP (quality 85)

const AVATAR_DIR = process.env.AVATAR_DIR ?? path.join(process.cwd(), 'data', 'avatars');
export const AVATAR_FILE_RE = /^[0-9a-f-]{36}-[0-9a-f]{16}\.webp$/;
export const MAX_AVATAR_BYTES = 8 * 1024 * 1024;

let dirReady = false;
async function ensureDir(): Promise<void> {
  if (!dirReady) {
    await fs.mkdir(AVATAR_DIR, { recursive: true });
    dirReady = true;
  }
}

export function avatarFilePath(file: string): string | null {
  if (!AVATAR_FILE_RE.test(file)) return null;
  return path.join(AVATAR_DIR, file);
}

export async function processAndStoreAvatar(
  sub: string,
  input: Buffer,
): Promise<{ file: string; size: number } | { error: 'unprocessable_image' }> {
  let oriented: Buffer;
  let width: number;
  let height: number;
  try {
    oriented = await sharp(input, { limitInputPixels: 40_000_000 }).rotate().toBuffer();
    const meta = await sharp(oriented).metadata();
    if (!meta.width || !meta.height) return { error: 'unprocessable_image' };
    width = meta.width;
    height = meta.height;
  } catch {
    return { error: 'unprocessable_image' };
  }

  const side = Math.min(width, height);
  const out = Math.min(512, side);
  let webp: Buffer;
  try {
    webp = await sharp(oriented)
      .extract({
        left: Math.floor((width - side) / 2),
        top: Math.floor((height - side) / 2),
        width: side,
        height: side,
      })
      .resize(out, out)
      .webp({ quality: 85 })
      .toBuffer();
  } catch {
    return { error: 'unprocessable_image' };
  }

  await ensureDir();
  const file = `${sub}-${crypto.randomBytes(8).toString('hex')}.webp`;
  await fs.writeFile(path.join(AVATAR_DIR, file), webp);
  return { file, size: out };
}

export async function readAvatar(file: string): Promise<Buffer | null> {
  const p = avatarFilePath(file);
  if (!p) return null;
  try {
    return await fs.readFile(p);
  } catch {
    return null;
  }
}

export async function deleteAvatarFile(file: string | null): Promise<void> {
  if (!file) return;
  const p = avatarFilePath(file);
  if (!p) return;
  await fs.unlink(p).catch(() => {});
}
