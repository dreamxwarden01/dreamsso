// Server-rendered pages for the portal's pre-setup state. The BFF normally ships
// only the SPA bundle, but before it's configured there's no SPA to serve — these
// stand in, styled with the same tokens the SSO's server-rendered pages use so the
// first-run experience reads as one product.

function esc(s: string): string {
  return s.replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
}

// Brand mark — the shield-lock glyph shared with the SSO and the console's Icon.
export const SHIELD = `<svg width="24" height="24" viewBox="0 0 24 24" fill="none" aria-hidden="true">
  <path d="M12 3l7 3v5c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6z" stroke="#fff" stroke-width="2" stroke-linejoin="round"/>
  <rect x="9.5" y="11.5" width="5" height="4" rx="1" stroke="#fff" stroke-width="1.6"/>
  <path d="M10.5 11.5v-1a1.5 1.5 0 0 1 3 0v1" stroke="#fff" stroke-width="1.6"/></svg>`;

// The same soft "bloom" backdrop as the SSO's auth pages. Served same-origin (so a
// strict img-src 'self' CSP is satisfied) and drawn at natural size + centered, so
// resizing CROPS rather than stretches.
export const AUTH_BG_SVG = `<svg xmlns="http://www.w3.org/2000/svg" width="2560" height="1600" viewBox="0 0 2560 1600">
<defs>
<linearGradient id="base" x1="0" y1="0" x2="1" y2="1">
<stop offset="0" stop-color="#eef3fb"/><stop offset="0.55" stop-color="#f1f0f8"/><stop offset="1" stop-color="#f5eef4"/>
</linearGradient>
<filter id="soft" x="-40%" y="-40%" width="180%" height="180%"><feGaussianBlur stdDeviation="140"/></filter>
</defs>
<rect width="2560" height="1600" fill="url(#base)"/>
<g filter="url(#soft)">
<ellipse cx="820" cy="520" rx="560" ry="470" fill="#c7dcfb" opacity="0.72"/>
<ellipse cx="1780" cy="1080" rx="620" ry="520" fill="#e2d6f4" opacity="0.66"/>
<ellipse cx="1640" cy="420" rx="440" ry="380" fill="#f8e1e9" opacity="0.56"/>
<ellipse cx="640" cy="1240" rx="520" ry="430" fill="#d3ebfa" opacity="0.6"/>
<ellipse cx="1260" cy="780" rx="400" ry="360" fill="#d9e6fc" opacity="0.5"/>
</g>
</svg>`;

// The bloom background lives under /setup/ so the gate's token cookie (path=/setup)
// covers it and it 404s along with the rest of the wizard once setup is done.
export const BG_URL = '/setup/bg.svg';

// The neutral pre-setup page: what every path returns before the portal is
// configured, including /setup without a valid token. No CTA, no hint that a
// wizard exists.
export function renderUnavailablePage(nonce: string): string {
  return `<!DOCTYPE html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Service unavailable</title>
<style nonce="${nonce}">
  *{box-sizing:border-box}
  html,body{margin:0}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Oxygen,Ubuntu,sans-serif;
    background:#f1f0f7;color:#1f2937;font-size:14px;line-height:1.5;min-height:100vh;
    display:flex;align-items:center;justify-content:center;padding:24px}
  .wrap{width:100%;max-width:400px}
  .card{background:#fff;border:1px solid #e5e7eb;border-radius:16px;
    box-shadow:0 4px 24px rgba(0,0,0,.06),0 1px 2px rgba(0,0,0,.04);padding:36px 34px}
  .brand{display:flex;align-items:center;gap:8px;justify-content:center;margin-bottom:18px}
  .badge{width:34px;height:34px;border-radius:10px;display:flex;align-items:center;justify-content:center;
    background:linear-gradient(135deg,#1a73e8,#1557b0);box-shadow:0 2px 8px rgba(26,115,232,.35);flex-shrink:0}
  .badge svg{width:20px;height:20px}
  .wordmark{font-size:14px;font-weight:700;color:#1f2937;letter-spacing:-.01em}
  h1{font-size:22px;font-weight:600;text-align:center;margin:0 0 5px;color:#1f2937}
  .msg{text-align:center;color:#6b7280;font-size:14px;line-height:1.55;margin:0}
  .foot{display:flex;align-items:center;justify-content:center;gap:5px;text-align:center;
    color:#9ca3af;font-size:12px;margin-top:18px}
</style></head>
<body>
<div class="wrap">
  <div class="card">
    <div class="brand"><span class="badge">${SHIELD}</span><span class="wordmark">${esc('Account console')}</span></div>
    <h1>Service unavailable</h1>
    <p class="msg">This service is temporarily unavailable. Please try again in a little while.</p>
  </div>
  <div class="foot">
    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <rect x="5" y="11" width="14" height="9" rx="2" stroke="#9ca3af" stroke-width="2"/>
      <path d="M8 11V8a4 4 0 0 1 8 0v3" stroke="#9ca3af" stroke-width="2" stroke-linecap="round"/></svg>
    Protected by DreamSSO</div>
</div>
</body></html>`;
}
