import { BRAND_DIR } from './branding.js';
import { readFileSync } from 'node:fs';
import path from 'node:path';
const edgeFont = (name: string) => readFileSync(path.join(BRAND_DIR, name)).toString('base64');
const EDGE_FONTS = `@font-face{font-family:Geist;src:url(data:font/woff2;base64,${edgeFont('geist-sans.woff2')}) format('woff2');font-weight:100 900;font-display:swap}@font-face{font-family:'Geist Mono';src:url(data:font/woff2;base64,${edgeFont('geist-mono.woff2')}) format('woff2');font-weight:100 900;font-display:swap}:root{--font-ui:Geist,system-ui,sans-serif;--font-mono:'Geist Mono',ui-monospace,monospace}`;
import { AUTH_SHELL_CSS, AUTH_BACKGROUND } from './authPresentation.js';

// Self-contained Cloudflare Error Page, served at /challenge.html. Cloudflare
// stores the rendered HTML, so it must not depend on origin assets or scripts.
// Preserve the widget and Ray ID placeholders and let Cloudflare own the widget.
// Matching transition names allow a shell morph on eligible navigations; a
// challenge reload or unsupported browser still gets the same static background.
export const CHALLENGE_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light">
<title>Verifying your browser</title>
<style>
${EDGE_FONTS}
${AUTH_SHELL_CSS}
  .cb{text-align:center}
  h1{font-size:22px;font-weight:600;margin:0 0 8px;color:#1f2937;text-wrap:balance}
  .sub{color:#6b7280;font-size:14px;margin:0 auto 26px;max-width:34ch}
  .widget{display:flex;justify-content:center;min-height:66px;margin-inline:calc(-1 * var(--padx))}
  .ray{font-size:12px;color:#9ca3af;font-family:var(--font-mono);margin:22px 0 0}
</style>
</head>
<body>
${AUTH_BACKGROUND}
<div class="wrap">
  <div class="card"><div class="cb">
    <h1>Verifying your browser</h1>
    <p class="sub">A quick automated check to confirm you&rsquo;re not a bot. It only takes a moment.</p>
    <div class="widget">::CF_WIDGET_BOX::</div>
    <p class="ray">Ray ID: ::RAY_ID::</p>
  </div></div>
</div>
</body>
</html>`;
