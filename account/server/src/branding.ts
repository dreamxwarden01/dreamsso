import express from 'express';
import { fileURLToPath } from 'node:url';
import { readFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import { config } from './config.js';

const bundled = path.join(config.spaDist, 'brand/v1');
const bundledComplete = existsSync(bundled) && existsSync(path.resolve(bundled, '../v2'));
export const BRAND_DIR = bundledComplete ? bundled : fileURLToPath(new URL('../../client/public/brand/v1/', import.meta.url));
export const FONT_DIR = path.resolve(BRAND_DIR, '../v2');
export const BRAND_HEAD = '<link rel="preload" href="/brand/v2/inter-variable.woff2" as="font" type="font/woff2" crossorigin><link rel="stylesheet" href="/brand/v2/fonts.css"><link rel="icon" type="image/svg+xml" href="/brand/v1/favicon.svg"><link rel="apple-touch-icon" href="/brand/v1/apple-touch-icon.png">';
export const BRAND_MARK = `<svg width="20" height="20" viewBox="0 0 16 16" fill="#fff" aria-hidden="true"><path fill-rule="evenodd" d="M8 1L14.2 3.25Q15 3.55 15 4.4V7.7C15 11.3 12.4 13.8 8 15.25C3.6 13.8 1 11.3 1 7.7V4.4Q1 3.55 1.8 3.25ZM6 7A2 2 0 1 0 10 7A2 2 0 1 0 6 7Z"/></svg>`;
export const FAVICON_SVG = readFileSync(path.join(BRAND_DIR, 'favicon.svg'), 'utf8');

// Only this versioned, checked-in directory is public before setup completes.
// Missing assets terminate here; they never fall through to a login or SPA shell.
export const brandRouter = express.Router();
for (const [version, directory] of [['v1', BRAND_DIR], ['v2', FONT_DIR]] as const) {
  brandRouter.use('/brand/' + version, express.static(directory, {
    index: false, redirect: false, dotfiles: 'deny', immutable: true, maxAge: '1y',
  }));
  brandRouter.use('/brand/' + version, (_req, res) => { res.status(404).set('Cache-Control', 'no-store').end(); });
}
