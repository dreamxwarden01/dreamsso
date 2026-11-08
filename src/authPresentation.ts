// Shared by the server-rendered auth pages and the self-contained edge template.
// Keep the background and transition geometry identical across those documents.
export const AUTH_SHELL_CSS = `
  *{box-sizing:border-box}
  html,body{margin:0}
  html{background:#f1f0f7}
  @view-transition{navigation:auto}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Oxygen,Ubuntu,sans-serif;
    color:#1f2937;font-size:14px;line-height:1.5;min-height:100vh;min-height:100svh;
    display:flex;align-items:center;justify-content:center;padding:24px}
  .bg{position:fixed;inset:0;z-index:-1;pointer-events:none;background-color:#f1f0f7;
    background-image:
      radial-gradient(680px 640px at 1260px 780px,rgba(217,230,252,.5) 18%,rgba(217,230,252,.42) 38%,rgba(217,230,252,.25) 59%,rgba(217,230,252,.08) 79%,rgba(217,230,252,0)),
      radial-gradient(800px 710px at 640px 1240px,rgba(211,235,250,.6) 30%,rgba(211,235,250,.5) 48%,rgba(211,235,250,.3) 65%,rgba(211,235,250,.1) 83%,rgba(211,235,250,0)),
      radial-gradient(720px 660px at 1640px 420px,rgba(248,225,233,.56) 22%,rgba(248,225,233,.47) 42%,rgba(248,225,233,.28) 61%,rgba(248,225,233,.09) 81%,rgba(248,225,233,0)),
      radial-gradient(900px 800px at 1780px 1080px,rgba(226,214,244,.66) 38%,rgba(226,214,244,.55) 53%,rgba(226,214,244,.33) 69%,rgba(226,214,244,.11) 84%,rgba(226,214,244,0)),
      radial-gradient(840px 750px at 820px 520px,rgba(199,220,251,.72) 33%,rgba(199,220,251,.6) 50%,rgba(199,220,251,.36) 67%,rgba(199,220,251,.12) 83%,rgba(199,220,251,0)),
      linear-gradient(135deg,#eef3fb,#f1f0f8 55%,#f5eef4);
    background-size:2560px 1600px;background-position:50% 50%;background-repeat:no-repeat}
  .wrap{width:100%;max-width:400px}
  .card{margin-inline:auto;background:#fff;border:1px solid #e5e7eb;border-radius:16px;
    box-shadow:0 4px 24px rgba(0,0,0,.06),0 1px 2px rgba(0,0,0,.04);view-transition-name:authcard}
  .cb{--padx:34px;padding:36px var(--padx);view-transition-name:authcontent}
  .brand{view-transition-name:authbrand}
  .cta{view-transition-name:authcta}
  .foot{view-transition-name:authfoot}
  .overlay .card,.overlay .cb,.overlay .brand{view-transition-name:none}
  .card.morphing{display:flex;justify-content:center;align-items:flex-start;overflow:hidden;overflow:clip}
  .card.morphing>.cb{flex:none}
  @media(max-width:400px){body{padding:16px 12px}.cb{--padx:22px;padding:28px var(--padx)}}
  @media(max-width:340px){body{padding:16px 8px}.cb{--padx:18px;padding:26px var(--padx)}.cb .otp{gap:6px}}

  /* Paint one resizing frame; snapshots of its text keep their natural size. */
  ::view-transition-group(*){animation-duration:.25s;animation-timing-function:cubic-bezier(.2,0,0,1)}
  ::view-transition-old(root){animation:none;opacity:0}
  ::view-transition-new(root){animation:none}
  ::view-transition-group(authcard){box-sizing:border-box;background:#fff;border:1px solid #e5e7eb;border-radius:16px;
    box-shadow:0 4px 24px rgba(0,0,0,.06),0 1px 2px rgba(0,0,0,.04)}
  ::view-transition-old(authcard),::view-transition-new(authcard){animation:none;opacity:0}
  ::view-transition-group(authcontent){overflow:clip;border-radius:15px}
  ::view-transition-old(authcontent),::view-transition-new(authcontent),
  ::view-transition-old(authcta),::view-transition-new(authcta){width:auto;height:auto;left:50%;translate:-50% 0}
  ::view-transition-old(authcontent),::view-transition-old(authcta){animation:auth-out 90ms cubic-bezier(.4,0,1,1) both}
  ::view-transition-new(authcontent),::view-transition-new(authcta){animation:auth-in 180ms cubic-bezier(0,0,.2,1) 70ms both}
  @keyframes auth-out{to{opacity:0}}
  @keyframes auth-in{from{opacity:0}}
  @media(prefers-reduced-motion:reduce){
    @view-transition{navigation:none}
    ::view-transition-group(*),::view-transition-old(*),::view-transition-new(*){animation:none!important}
  }
`;

export const AUTH_BACKGROUND = '<div class="bg" aria-hidden="true"></div>';
