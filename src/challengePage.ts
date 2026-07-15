// Zone-level Cloudflare custom challenge page (Managed / Interactive / JS
// Challenge), served at /challenge.html and pointed at from CF → Custom Pages.
//
// Self-contained by design: inline CSS + the bloom background as an inline SVG,
// so CF's stored copy has no origin dependency at serve time. Requirements
// (developers.cloudflare.com/cloudflare-challenges/.../additional-configuration):
//   - `::CF_WIDGET_BOX::` appears EXACTLY ONCE — CF injects the challenge widget.
//   - `::RAY_ID::` is replaced with the request's Ray ID.
//   - A <head> must be present.
//   - Do NOT define window._cf_chl_opt (CF sets it), and do NOT CSP-block
//     /cdn-cgi/challenge-platform/ or the widget won't load.
//
// Matches the SSO auth pages: same bloom, same white card, and the same
// cross-document view transition (view-transition-name:authcard) so the card
// morphs into the real login/step-up card once the challenge solves.
export const CHALLENGE_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light">
<title>Verifying your browser</title>
<style>
  *{box-sizing:border-box}
  @view-transition{navigation:auto}
  ::view-transition-group(authcard){animation-duration:.4s}
  html,body{margin:0}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Oxygen,Ubuntu,sans-serif;
    color:#1f2937;font-size:14px;line-height:1.5;min-height:100vh;
    display:flex;align-items:center;justify-content:center;padding:24px;background:#f1f0f7}
  .bg{position:fixed;inset:0;width:100%;height:100%;z-index:-1}
  .bg svg{width:100%;height:100%;display:block}
  .wrap{width:100%;max-width:400px}
  .card{background:#fff;border:1px solid #e5e7eb;border-radius:16px;
    box-shadow:0 4px 24px rgba(0,0,0,.06),0 1px 2px rgba(0,0,0,.04);
    padding:38px 34px;text-align:center;view-transition-name:authcard}
  h1{font-size:22px;font-weight:600;margin:0 0 8px;color:#1f2937;text-wrap:balance}
  .sub{color:#6b7280;font-size:14px;margin:0 auto 26px;max-width:34ch}
  .widget{display:flex;justify-content:center;min-height:66px}
  .ray{font-size:12px;color:#9ca3af;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;margin:22px 0 0}
</style>
</head>
<body>
<div class="bg">
  <svg viewBox="0 0 2560 1600" preserveAspectRatio="xMidYMid slice" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
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
  </svg>
</div>
<div class="wrap">
  <div class="card">
    <h1>Verifying your browser</h1>
    <p class="sub">A quick automated check to confirm you&rsquo;re not a bot. It only takes a moment.</p>
    <div class="widget">::CF_WIDGET_BOX::</div>
    <p class="ray">Ray ID: ::RAY_ID::</p>
  </div>
</div>
</body>
</html>`;
