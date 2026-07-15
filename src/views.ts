function esc(s: string): string {
  return s.replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
}

// Brand mark — the same shield-lock glyph as the account console's Icon, in white
// for the gradient badge.
const SHIELD = `<svg width="24" height="24" viewBox="0 0 24 24" fill="none" aria-hidden="true">
  <path d="M12 3l7 3v5c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6z" stroke="#fff" stroke-width="2" stroke-linejoin="round"/>
  <rect x="9.5" y="11.5" width="5" height="4" rx="1" stroke="#fff" stroke-width="1.6"/>
  <path d="M10.5 11.5v-1a1.5 1.5 0 0 1 3 0v1" stroke="#fff" stroke-width="1.6"/></svg>`;

const CHECK = `<svg width="26" height="26" viewBox="0 0 24 24" fill="none" aria-hidden="true">
  <circle cx="12" cy="12" r="9" stroke="#065f46" stroke-width="2"/>
  <path d="M8.5 12l2.5 2.5 4.5-4.5" stroke="#065f46" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>`;

// Shield-with-cross, amber — the "no accepted verification method" state icon.
const SHIELD_X = `<svg width="26" height="26" viewBox="0 0 24 24" fill="none" aria-hidden="true">
  <path d="M12 3l7 3v5c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6z" stroke="#b45309" stroke-width="2" stroke-linejoin="round"/>
  <path d="M9.5 10.5l5 5M14.5 10.5l-5 5" stroke="#b45309" stroke-width="2" stroke-linecap="round"/></svg>`;

// Shared styles — the account console's design tokens (system font, #f0f2f5 bg,
// #fff card, #1a73e8 primary), so the SSO's server-rendered pages and the SPA feel
// like one product. Nonce'd to satisfy the strict CSP (style-src 'nonce-…').
// Soft "bloom" background for the auth pages, served at /auth-bg.svg (same-origin,
// so it satisfies the strict img-src 'self' CSP). Displayed at natural size and
// centered (background-size:auto) so resizing CROPS it rather than zooming/stretching.
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

// Brand favicon (same shield-lock as the account portal), served at /favicon.svg.
// Referenced by every page's <head> via baseStyle().
export const FAVICON_SVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">
<path d="M12 2.5l7.5 3.2v5.1c0 4.8-3.2 8-7.5 9.7-4.3-1.7-7.5-4.9-7.5-9.7V5.7z" fill="#1a73e8"/>
<rect x="9" y="11" width="6" height="5" rx="1" fill="#fff"/>
<path d="M10.2 11v-1.2a1.8 1.8 0 0 1 3.6 0V11" fill="none" stroke="#fff" stroke-width="1.6"/>
</svg>`;

function baseStyle(nonce: string): string {
  return `<link rel="icon" type="image/svg+xml" href="/favicon.svg"><style nonce="${nonce}">
  *{box-sizing:border-box}
  html,body{margin:0}
  /* Cross-document view transitions: the browser morphs the card between the
     server-rendered auth steps (no JS). Graceful no-op where unsupported. */
  @view-transition{navigation:auto}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Oxygen,Ubuntu,sans-serif;
    background:#f1f0f7 url(/auth-bg.svg) center / auto no-repeat fixed;
    color:#1f2937;font-size:14px;line-height:1.5;min-height:100vh;
    display:flex;align-items:center;justify-content:center;padding:24px}
  .wrap{width:100%;max-width:400px}
  .card{background:#fff;border:1px solid #e5e7eb;border-radius:16px;
    box-shadow:0 4px 24px rgba(0,0,0,.06),0 1px 2px rgba(0,0,0,.04);padding:36px 34px;
    view-transition-name:authcard}
  .overlay .card{view-transition-name:none}
  ::view-transition-group(authcard){animation-duration:.4s}
  .brand{display:flex;align-items:center;gap:8px;justify-content:center;margin-bottom:18px}
  .badge{width:34px;height:34px;border-radius:10px;display:flex;align-items:center;justify-content:center;
    background:linear-gradient(135deg,#1a73e8,#1557b0);box-shadow:0 2px 8px rgba(26,115,232,.35);flex-shrink:0}
  .badge svg{width:20px;height:20px}
  .wordmark{font-size:14px;font-weight:700;color:#1f2937;letter-spacing:-.01em}
  .state-ico{width:52px;height:52px;border-radius:50%;display:flex;align-items:center;justify-content:center;margin:0 auto 14px}
  h1{font-size:22px;font-weight:600;text-align:center;margin:0 0 5px;color:#1f2937}
  .sub{text-align:center;color:#6b7280;font-size:14px;margin:0 0 26px}
  .err{background:#fef2f2;border:1px solid #fecaca;color:#b91c1c;padding:10px 13px;border-radius:9px;
    font-size:13px;margin-bottom:18px}
  .grp{margin-bottom:16px}
  label{display:block;margin-bottom:6px;font-weight:500;font-size:13px;color:#374151}
  .lrow{display:flex;justify-content:space-between;align-items:baseline;margin-bottom:6px}
  .lrow label{margin-bottom:0}
  .fgt{font-size:13px;font-weight:400;color:#6b7280;text-decoration:none}
  .fgt:hover{color:#374151;text-decoration:underline}
  .cta{margin-top:16px;background:#fff;border:1px solid #e5e7eb;border-radius:16px;
    box-shadow:0 4px 24px rgba(0,0,0,.06),0 1px 2px rgba(0,0,0,.04);
    padding:18px 24px;text-align:center;font-size:14px;color:#5f6368}
  .cta a{color:#1f2937;font-weight:700;text-decoration:none}
  .cta a:hover{text-decoration:underline}
  input{width:100%;padding:10px 13px;border:1px solid #d1d5db;border-radius:10px;font-size:14px;color:#1f2937;
    outline:none;transition:border-color .15s,box-shadow .15s}
  input::placeholder{color:#9ca3af}
  input:focus{border-color:#1a73e8;box-shadow:0 0 0 3px rgba(26,115,232,.12)}
  .btn{width:100%;padding:11px 16px;border:none;border-radius:10px;background:#1a73e8;color:#fff;
    font-size:14px;font-weight:600;cursor:pointer;transition:background .15s;margin-top:6px;
    box-shadow:0 1px 2px rgba(26,115,232,.4)}
  .btn:hover{background:#1557b0}
  a.btn{display:flex;align-items:center;justify-content:center;text-decoration:none;box-sizing:border-box;margin-top:18px}
  .field-err{display:none;color:#b91c1c;font-size:12px;margin-top:6px}
  .grp.bad .field-err{display:block}
  .grp.bad input{border-color:#dc2626}
  .grp.bad input:focus{border-color:#dc2626;box-shadow:0 0 0 3px rgba(220,38,38,.12)}
  .chip{display:flex;justify-content:center;margin-bottom:16px}
  .chip span{display:inline-flex;align-items:center;gap:7px;border:1px solid #e5e7eb;border-radius:99px;padding:4px 14px;font-size:13px;color:#374151;
    max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .chip-av{width:20px;height:20px;border-radius:50%;flex-shrink:0;margin-left:-6px}
  .otp{display:flex;gap:8px;justify-content:center;margin-bottom:18px}
  .otp input{width:42px;height:50px;padding:0;text-align:center;font-size:21px;font-weight:600;border-radius:9px}
  .btn:disabled{opacity:.5;cursor:default}
  .or{display:flex;align-items:center;gap:10px;margin:16px 0;color:#9ca3af;font-size:12px}
  .or:before,.or:after{content:'';flex:1;height:1px;background:#e5e7eb}
  .btn-ghost{background:#fff;color:#1f2937;border:1px solid #d1d5db;box-shadow:none;
    display:flex;align-items:center;justify-content:center;gap:8px;margin-top:0}
  .btn-ghost:hover{background:#f8f9fa}
  .btn-gap{margin-top:10px}
  .wait{text-align:center;font-size:13px;color:#9ca3af;margin:0 0 16px}
  .alt{display:block;text-align:center;font-size:13px;font-weight:600;color:#1a73e8;text-decoration:none;margin-top:14px}
  .alt:hover{color:#1557b0}
  .resend{text-align:center;font-size:12px;color:#9ca3af;margin:12px 0 0}
  .resend button{background:none;border:0;padding:0;font:inherit;font-weight:600;color:#1a73e8;cursor:pointer}
  .resend button:disabled{color:#9ca3af;cursor:default}
  .errcode{text-align:center;font-size:12px;color:#9ca3af;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;margin:14px 0 0}
  .overlay{position:fixed;inset:0;background:rgba(17,24,39,.55);display:flex;align-items:center;justify-content:center;padding:24px;z-index:50}
  .overlay .card{max-width:340px;width:100%}
  [hidden]{display:none !important}
  .foot{display:flex;align-items:center;justify-content:center;gap:5px;text-align:center;
    color:#9ca3af;font-size:12px;margin-top:18px}
  .done-badge{width:54px;height:54px;border-radius:50%;background:#d1fae5;display:flex;align-items:center;
    justify-content:center;margin:0 auto 18px}
  .msg{text-align:center;color:#6b7280;font-size:14px;line-height:1.55;margin:0}
</style>`;
}

const foot = (siteName: string) => `<div class="foot">
  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" aria-hidden="true">
    <rect x="5" y="11" width="14" height="9" rx="2" stroke="#9ca3af" stroke-width="2"/>
    <path d="M8 11V8a4 4 0 0 1 8 0v3" stroke="#9ca3af" stroke-width="2" stroke-linecap="round"/></svg>
  Protected by ${esc(siteName)}</div>`;

// Server-rendered sign-in page, styled to match the account console. Branding
// (wordmark, titles, footer) follows the admin-editable site_name setting.
export function renderLoginPage(opts: {
  txn: string;
  csrf: string;
  error?: string;
  username?: string;
  nonce: string;
  appName?: string;
  siteName?: string;
  // WebAuthn request options (JSON) for first-factor passkey sign-in — powers
  // BOTH conditional UI (autofill) and the explicit button. The button + divider
  // ship hidden and are revealed only when the browser supports WebAuthn.
  passkeyOptions?: string;
  // The account portal's /forgot page (settings-driven) — the grey entrance
  // link beside the password label, videosite-style.
  forgotUrl?: string;
  // The portal's /register/start page — shown only while registration is
  // enabled (Turnstile gates that entrance on the portal side).
  registerUrl?: string;
}): string {
  const { txn, csrf, error, username = '', nonce, appName, passkeyOptions, forgotUrl, registerUrl } = opts;
  const siteName = opts.siteName || 'DreamSSO';
  const sub = appName ? `Sign in to continue to ${esc(appName)}` : 'Sign in to your account';
  return `<!DOCTYPE html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in · ${esc(appName || siteName)}</title>
${baseStyle(nonce)}</head>
<body>
<div class="wrap">
  <div class="card">
    <div class="brand"><span class="badge">${SHIELD}</span><span class="wordmark">${esc(siteName)}</span></div>
    <h1>Welcome</h1>
    <p class="sub">${sub}</p>
    ${error ? `<div class="err">${esc(error)}</div>` : ''}
    <form method="post" action="/login" novalidate>
      <input type="hidden" name="txn" value="${esc(txn)}">
      <input type="hidden" name="csrf" value="${esc(csrf)}">
      <div class="grp">
        <label for="username">Username or Email Address</label>
        <input id="username" name="username" autocomplete="username webauthn" autofocus
          autocapitalize="none" autocorrect="off" spellcheck="false" value="${esc(username)}">
        <span class="field-err"></span>
      </div>
      <div class="grp">
        ${forgotUrl
          ? `<div class="lrow"><label for="password">Password</label><a class="fgt" href="${esc(forgotUrl)}" tabindex="-1">Forgot password?</a></div>`
          : '<label for="password">Password</label>'}
        <input id="password" name="password" type="password" autocomplete="current-password">
        <span class="field-err"></span>
      </div>
      <button type="submit" class="btn">Sign in</button>
    </form>
    ${passkeyOptions ? `
    <div class="err" id="pk-err" hidden></div>
    <div class="or" id="pk-or" hidden>or</div>
    <a class="btn btn-ghost" id="pk-btn" href="/login/passkey?txn=${encodeURIComponent(txn)}" hidden>${KEY_ICON} Sign in with a passkey</a>
    <form method="post" action="/login/passkey" id="pk-form" hidden>
      <input type="hidden" name="txn" value="${esc(txn)}">
      <input type="hidden" name="csrf" value="${esc(csrf)}">
      <input type="hidden" name="credential" value="">
    </form>` : ''}
  </div>
  ${registerUrl ? `<div class="cta">Don&rsquo;t have an account? <a href="${esc(registerUrl)}">Sign up</a></div>` : ''}
  ${foot(siteName)}
</div>
${loginScript(nonce)}
${passkeyOptions ? webauthnGlue(nonce, passkeyOptions, 'first') : ''}
</body></html>`;
}

const KEY_ICON = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="7.5" cy="16.5" r="3.5"/><path d="M10 14l7-7M14.5 6.5l2.5 2.5M17 4l3 3"/></svg>`;

// Dedicated first-factor passkey page (/login/passkey?txn=): the OS sheet
// launches on load against the txn's REUSED challenge; failure shows retry +
// the way back to the password form.
export function renderPasskeyLoginPage(opts: {
  txn: string;
  csrf: string;
  nonce: string;
  appName?: string;
  siteName?: string;
  passkeyOptions: string;
}): string {
  const { txn, csrf, nonce, appName, passkeyOptions } = opts;
  const siteName = opts.siteName || 'DreamSSO';
  return `<!DOCTYPE html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in with a passkey · ${esc(appName || siteName)}</title>
${baseStyle(nonce)}</head>
<body>
<div class="wrap">
  <div class="card">
    <div class="brand"><span class="badge">${SHIELD}</span><span class="wordmark">${esc(siteName)}</span></div>
    <h1>Verify it’s you</h1>
    <p class="sub">Your device will ask for your fingerprint, face, or PIN</p>
    <div class="err" id="pk-err" hidden></div>
    <p class="wait" id="pk-wait">Waiting for your passkey…</p>
    <button type="button" class="btn btn-ghost" id="pk-again" hidden>Try again</button>
    <a class="alt" href="/login?txn=${encodeURIComponent(txn)}">Back to sign in</a>
    <form method="post" action="/login/passkey" id="pk-form" hidden>
      <input type="hidden" name="txn" value="${esc(txn)}">
      <input type="hidden" name="csrf" value="${esc(csrf)}">
      <input type="hidden" name="credential" value="">
    </form>
  </div>
  ${foot(siteName)}
</div>
${webauthnGlue(nonce, passkeyOptions, 'challenge')}
</body></html>`;
}

// Shared WebAuthn client glue (login page + challenge page). mode 'first' =
// username-less sign-in (conditional UI + button; the button opens a PENDING
// overlay while the OS sheet is up — Microsoft-style, no other UI competing);
// mode 'challenge' = assertion for the known user (auto-run unless re-rendered
// with a server error; "Try another way" is revealed only on failure — while
// the OS window is open the card shows nothing else). Feature-detected: without
// WebAuthn support the passkey UI stays hidden ("or" + button never appear).
function webauthnGlue(nonce: string, optionsJson: string, mode: 'first' | 'challenge', autorun = true): string {
  return `<script nonce="${nonce}">
(function(){
  if(!window.PublicKeyCredential||!navigator.credentials)return;
  var OPTS=${optionsJson};
  function u2b(s){s=s.replace(/-/g,'+').replace(/_/g,'/');var bin=atob(s),a=new Uint8Array(bin.length);for(var i=0;i<bin.length;i++)a[i]=bin.charCodeAt(i);return a.buffer;}
  function b2u(buf){var a=new Uint8Array(buf),bin='';for(var i=0;i<a.length;i++)bin+=String.fromCharCode(a[i]);return btoa(bin).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');}
  function publicKey(){
    var pk={challenge:u2b(OPTS.challenge),timeout:OPTS.timeout||600000,userVerification:OPTS.userVerification||'required'};
    if(OPTS.rpId)pk.rpId=OPTS.rpId;
    if(OPTS.allowCredentials&&OPTS.allowCredentials.length)pk.allowCredentials=OPTS.allowCredentials.map(function(c){return{type:'public-key',id:u2b(c.id),transports:c.transports};});
    return pk;
  }
  var form=document.getElementById('pk-form');
  function submitCred(cred){
    var r=cred.response;
    form.querySelector('input[name=credential]').value=JSON.stringify({
      id:cred.id,rawId:b2u(cred.rawId),type:cred.type,
      clientExtensionResults:cred.getClientExtensionResults?cred.getClientExtensionResults():{},
      response:{clientDataJSON:b2u(r.clientDataJSON),authenticatorData:b2u(r.authenticatorData),
        signature:b2u(r.signature),userHandle:r.userHandle?b2u(r.userHandle):null}
    });
    form.submit();
  }
  function show(id,on){var el=document.getElementById(id);if(el)el.hidden=!on;}
  function fail(err){
    var el=document.getElementById('pk-err');
    if(!el)return;
    el.hidden=false;
    el.textContent=${mode === 'first'
      ? `"Couldn't sign in with your passkey — try again or sign in with your password. ["+((err&&err.name)||'error')+"]"`
      : `"Couldn't verify your passkey — try again. ["+((err&&err.name)||'error')+"]"`};
    show('pk-again',true);show('pk-alt',true);show('pk-wait',false);
  }
${mode === 'first' ? `
  // The explicit button is a LINK to the dedicated /login/passkey page (the
  // txn's challenge is reused there); this page keeps only the conditional-UI
  // (autofill) ceremony.
  show('pk-or',true);show('pk-btn',true);
  function startConditional(){
    if(!PublicKeyCredential.isConditionalMediationAvailable)return;
    PublicKeyCredential.isConditionalMediationAvailable().then(function(ok){
      if(!ok)return;
      navigator.credentials.get({publicKey:publicKey(),mediation:'conditional'})
        .then(submitCred).catch(function(){/* dismissed — the form still works */});
    });
  }
  startConditional();` : `
  function run(){
    show('pk-err',false);show('pk-again',false);show('pk-alt',false);
    show('pk-wait',true);
    navigator.credentials.get({publicKey:publicKey()}).then(submitCred).catch(fail);
  }
  var again=document.getElementById('pk-again');
  if(again)again.addEventListener('click',run);
  ${autorun ? 'run();' : "show('pk-wait',false);"}`}
})();
</script>`;
}

// Progressive enhancement: client-side validation so an empty/whitespace-only
// submit never round-trips to a generic "invalid" error, and never triggers the
// native "Fill out this field" bubble (form is novalidate). Mirrors videosite:
// strip all whitespace from both fields on input; block submit on empties with an
// inline message. No bot-check here yet, so the button isn't gated (videosite greys
// it only for Turnstile) — without JS the server still validates as a fallback.
function loginScript(nonce: string): string {
  return `<script nonce="${nonce}">
(function(){
  var u=document.getElementById('username'),p=document.getElementById('password'),f=u.form;
  function clr(el){el.parentNode.classList.remove('bad');}
  function err(el,m){var g=el.parentNode;g.classList.add('bad');var s=g.querySelector('.field-err');if(s)s.textContent=m;}
  function strip(){this.value=this.value.replace(/\\s/g,'');clr(this);}
  // Frame-click caret fix: a click on the padding/border can collapse the
  // caret to 0,0 on a filled box — after the browser's own placement, move it
  // to the end. Tab-focus (select-all) and mid-text clicks are untouched.
  function caretFix(el){el.addEventListener('focus',function(){
    requestAnimationFrame(function(){
      if(document.activeElement===el&&el.value&&el.selectionStart===0&&el.selectionEnd===0){
        try{el.setSelectionRange(el.value.length,el.value.length);}catch(e){}
      }
    });
  });}
  u.addEventListener('input',strip);
  p.addEventListener('input',strip);
  caretFix(u);caretFix(p);
  f.addEventListener('submit',function(ev){
    var bad=false;
    if(!u.value){err(u,'Enter your username or email.');bad=true;}
    if(!p.value){err(p,'Enter your password.');bad=true;}
    if(bad){ev.preventDefault();(u.value?p:u).focus();}
  });
})();
</script>`;
}

// MFA challenge page — phase 2 of the login card (the password checked out; a
// second factor is required before any session exists). Lands directly on the
// strongest owned method; "Try another way" only when another exists. The 6-box
// OTP input ports videosite's OtpInput behavior: auto-advance, backspace-walk,
// paste-fills-six, auto-submit on the sixth digit.
export type ChallengeMethod = 'totp' | 'email' | 'passkey';

export function renderChallengePage(opts: {
  txn: string;
  csrf: string;
  nonce: string;
  userLabel: string;
  method: ChallengeMethod;
  methods: string[];
  maskedEmail?: string;
  emailSent?: boolean;
  resendIn?: number;
  otpMinutes?: number; // shown as the code's validity on the email states
  passkeyOptions?: string; // WebAuthn request options JSON (method 'passkey')
  error?: string;
  avatar?: string | null;
  siteName?: string;
  cancelUrl?: string; // OIDC step-up only: a Cancel link back to the RP (access_denied)
}): string {
  const { txn, csrf, nonce, userLabel, method, methods, maskedEmail, emailSent, resendIn, otpMinutes, passkeyOptions, error, cancelUrl } = opts;
  const siteName = opts.siteName || 'DreamSSO';

  const hidden = `
      <input type="hidden" name="txn" value="${esc(txn)}">
      <input type="hidden" name="csrf" value="${esc(csrf)}">`;
  const otpBoxes = `<div class="otp">${Array.from({ length: 6 }, (_, i) =>
    `<input inputmode="numeric" autocomplete="${i === 0 ? 'one-time-code' : 'off'}" maxlength="1" aria-label="Digit ${i + 1}">`,
  ).join('')}</div>`;
  const codeForm = (m: ChallengeMethod) => `
    <form method="post" action="/login/challenge" novalidate>
      ${hidden}
      <input type="hidden" name="method" value="${m}">
      <input type="hidden" name="code" value="">
      ${otpBoxes}
      <button type="submit" class="btn" disabled>Verify</button>
    </form>`;

  const LABELS: Record<string, string> = {
    passkey: 'Use your passkey',
    totp: 'Use your authenticator app',
    email: 'Email a code instead',
  };
  // While a passkey ceremony is pending the card shows nothing else (the user is
  // in the OS window — Microsoft-style); the alternatives appear only on failure.
  const altLinks = methods
    .filter((m) => m !== method)
    .map((m) => `<a class="alt" href="/login?txn=${encodeURIComponent(txn)}&use=${m}">${esc(LABELS[m] ?? m)}</a>`)
    .join('');
  const tryAnother = method === 'passkey' && altLinks ? `<div id="pk-alt" hidden>${altLinks}</div>` : altLinks;

  let title = '';
  let sub = '';
  let body = '';
  if (method === 'totp') {
    title = 'Enter your code';
    sub = 'From your authenticator app';
    body = codeForm('totp');
  } else if (method === 'passkey') {
    title = 'Verify it’s you';
    sub = 'Your device will ask for your fingerprint, face, or PIN';
    body = `
    <p class="wait" id="pk-wait">Waiting for your passkey…</p>
    <div class="err" id="pk-err" hidden></div>
    <button type="button" class="btn btn-ghost" id="pk-again" hidden>Try again</button>
    <form method="post" action="/login/challenge" id="pk-form" hidden>
      ${hidden}
      <input type="hidden" name="method" value="passkey">
      <input type="hidden" name="credential" value="">
    </form>`;
  } else if (!emailSent) {
    title = 'Verify it’s you';
    sub = `We’ll email a sign-in code to your address — it stays valid for ${otpMinutes ?? 5} minutes`;
    body = `
    <form method="post" action="/login/challenge/send-email">
      ${hidden}
      <button type="submit" class="btn">Send a code to ${esc(maskedEmail ?? 'your email')}</button>
    </form>`;
  } else {
    title = 'Check your email';
    sub = `We sent a code to ${esc(maskedEmail ?? 'your email')} — it expires in ${otpMinutes ?? 5} minutes`;
    // Live countdown, then the real resend form appears (a resend inside the
    // cooldown is also enforced server-side; this is just honest UI).
    const waiting = !!resendIn && resendIn > 0;
    const resend = `
    ${waiting ? `<p class="resend" id="resend-wait" data-secs="${resendIn}">Resend code in ${resendIn}s</p>` : ''}
    <form method="post" action="/login/challenge/send-email" class="resend" id="resend-form"${waiting ? ' hidden' : ''}>
      ${hidden}
      <button type="submit">Resend code</button>
    </form>`;
    body = codeForm('email') + resend;
  }

  return `<!DOCTYPE html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Verify it's you · ${esc(siteName)}</title>
${baseStyle(nonce)}</head>
<body>
<div class="wrap">
  <div class="card">
    <div class="brand"><span class="badge">${SHIELD}</span><span class="wordmark">${esc(siteName)}</span></div>
    ${chipHtml(userLabel, opts.avatar)}
    <h1>${title}</h1>
    <p class="sub">${sub}</p>
    ${error && method !== 'passkey' ? `<div class="err">${esc(error)}</div>` : ''}
    ${body}
    ${tryAnother}
    ${cancelUrl ? `<a class="btn btn-ghost btn-gap" href="${esc(cancelUrl)}">Cancel</a>` : ''}
  </div>
  ${foot(siteName)}
</div>
${method === 'totp' || (method === 'email' && emailSent) ? challengeScript(nonce) : ''}
${method === 'email' ? sendGuardScript(nonce) : ''}
${method === 'email' && emailSent && resendIn ? resendCountdownScript(nonce) : ''}
${method === 'passkey' && passkeyOptions ? webauthnGlue(nonce, passkeyOptions, 'challenge', !error) : ''}
${method === 'passkey' && error ? `<script nonce="${nonce}">(function(){function s(i,on){var e=document.getElementById(i);if(e)e.hidden=!on;}var el=document.getElementById('pk-err');if(el){el.hidden=false;el.textContent=${JSON.stringify(error)};}s('pk-again',true);s('pk-alt',true);s('pk-wait',false);})();</script>` : ''}
</body></html>`;
}

// Tick the resend cooldown down each second; when it hits zero, swap the wait
// text for the real resend form.
function resendCountdownScript(nonce: string): string {
  return `<script nonce="${nonce}">
(function(){
  var w=document.getElementById('resend-wait');
  if(!w)return;
  var f=document.getElementById('resend-form');
  var s=parseInt(w.getAttribute('data-secs'),10)||0;
  var t=setInterval(function(){
    s-=1;
    if(s<=0){clearInterval(t);w.hidden=true;if(f)f.hidden=false;return;}
    w.textContent='Resend code in '+s+'s';
  },1000);
})();
</script>`;
}

// Grey the send/resend buttons the moment they're clicked — an email send is a
// slow round-trip and a double-click must not double-send.
function sendGuardScript(nonce: string): string {
  return `<script nonce="${nonce}">
(function(){
  var forms=document.querySelectorAll('form[action="/login/challenge/send-email"]');
  for(var i=0;i<forms.length;i++)(function(f){
    f.addEventListener('submit',function(){
      var b=f.querySelector('button');
      if(b){b.disabled=true;b.textContent='Sending…';}
    });
  })(forms[i]);
})();
</script>`;
}

// OTP box behavior (vanilla port of videosite's OtpInput): each box takes one
// digit; the hidden `code` field is assembled on submit; filling the sixth digit
// auto-submits. autocomplete=one-time-code lets iOS/Android suggest SMS/app codes.
function challengeScript(nonce: string): string {
  return `<script nonce="${nonce}">
(function(){
  var boxes=[].slice.call(document.querySelectorAll('.otp input'));
  var form=document.querySelector('form'),btn=form.querySelector('button'),hidden=form.querySelector('input[name=code]');
  function digits(){return boxes.map(function(b){return b.value;}).join('');}
  function sync(auto){var d=digits();btn.disabled=d.length!==6;if(d.length===6&&auto)form.requestSubmit?form.requestSubmit():form.submit();}
  boxes.forEach(function(box,i){
    box.addEventListener('input',function(){
      var v=box.value.replace(/\\D/g,'');
      if(v.length>1){paste(v,i);return;}
      box.value=v;
      if(v&&i<5)boxes[i+1].focus();
      sync(v&&i===5);
    });
    box.addEventListener('keydown',function(e){
      if(e.key==='Backspace'){
        if(box.value){box.value='';}
        else if(i>0){boxes[i-1].value='';boxes[i-1].focus();}
        sync(false);e.preventDefault();
      } else if(e.key==='ArrowLeft'&&i>0){boxes[i-1].focus();}
      else if(e.key==='ArrowRight'&&i<5){boxes[i+1].focus();}
    });
    box.addEventListener('paste',function(e){
      e.preventDefault();
      var t=(e.clipboardData||window.clipboardData).getData('text').replace(/\\D/g,'').slice(0,6);
      if(t)paste(t,0);
    });
  });
  function paste(t,from){
    var start=t.length===6?0:from;
    for(var j=0;j<6;j++)boxes[j].value='';
    for(var k=0;k<t.length&&start+k<6;k++)boxes[start+k].value=t[k];
    boxes[Math.min(start+t.length,5)].focus();
    sync(true);
  }
  form.addEventListener('submit',function(){hidden.value=digits();});
  boxes[0].focus();
})();
</script>`;
}

// "Stay signed in?" (KMSI) — the final phase of every interactive login. The
// session already exists with a browser-session cookie; Yes upgrades it to a
// persistent one. Only shown on session CREATION (never on silent reuse).
// The identity chip: optional profile picture (served from /avatar/<file>,
// same-origin capability URL) before the label.
export function chipHtml(userLabel: string, avatar?: string | null): string {
  const img = avatar ? `<img class="chip-av" src="/avatar/${esc(avatar)}" alt="">` : '';
  return `<div class="chip"><span>${img}${esc(userLabel)}</span></div>`;
}

export function renderKmsiPage(opts: {
  txn: string;
  csrf: string;
  nonce: string;
  userLabel: string;
  avatar?: string | null;
  siteName?: string;
}): string {
  const { txn, csrf, nonce, userLabel } = opts;
  const siteName = opts.siteName || 'DreamSSO';
  return `<!DOCTYPE html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Stay signed in? · ${esc(siteName)}</title>
${baseStyle(nonce)}</head>
<body>
<div class="wrap">
  <div class="card">
    <div class="brand"><span class="badge">${SHIELD}</span><span class="wordmark">${esc(siteName)}</span></div>
    ${chipHtml(userLabel, opts.avatar)}
    <h1>Stay signed in?</h1>
    <p class="sub">Skip signing in next time you open your browser.</p>
    <p class="wait">Only choose Yes on your own device.</p>
    <form method="post" action="/login/stay">
      <input type="hidden" name="txn" value="${esc(txn)}">
      <input type="hidden" name="csrf" value="${esc(csrf)}">
      <button type="submit" class="btn" name="choice" value="yes">Yes</button>
      <button type="submit" class="btn btn-ghost btn-gap" name="choice" value="no">No</button>
    </form>
  </div>
  ${foot(siteName)}
</div>
</body></html>`;
}

// Terminal error page for pre-redirect failures (unknown/disabled client, bad
// redirect_uri, expired txn) — cases where bouncing back to the RP is impossible
// or wrong. Styled like the rest of the SSO. The grey [code] matches the
// account console's error-code convention.
export function renderErrorPage(
  nonce: string,
  opts: {
    title: string;
    message: string;
    code?: string;
    siteName?: string;
    action?: { href: string; label: string }; // optional CTA (e.g. "Open the account portal")
  },
): string {
  const siteName = opts.siteName || 'DreamSSO';
  return `<!DOCTYPE html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(opts.title)} · ${esc(siteName)}</title>
${baseStyle(nonce)}</head>
<body>
<div class="wrap">
  <div class="card">
    <div class="brand"><span class="badge">${SHIELD}</span><span class="wordmark">${esc(siteName)}</span></div>
    <h1>${esc(opts.title)}</h1>
    <p class="msg">${esc(opts.message)}</p>
    ${opts.code ? `<p class="errcode">[${esc(opts.code)}]</p>` : ''}
    ${opts.action ? `<a class="btn" href="${esc(opts.action.href)}">${esc(opts.action.label)}</a>` : ''}
  </div>
  ${foot(siteName)}
</div>
</body></html>`;
}

// Catch-all 404 for unmatched SSO paths. Same bloom + card shell as the custom
// challenge page — deliberately brand-less and with NO call-to-action (there's no
// universally-correct "back" target on the bare IdP host; the account portal is
// where end users belong, but a stray link shouldn't imply a sign-in flow).
export function render404Page(nonce: string, siteName = 'DreamSSO'): string {
  return `<!DOCTYPE html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Page not found · ${esc(siteName)}</title>
${baseStyle(nonce)}</head>
<body>
<div class="wrap">
  <div class="card">
    <h1>Page not found</h1>
    <p class="sub">The page you&rsquo;re looking for doesn&rsquo;t exist or has moved.</p>
    <p class="errcode">[404]</p>
  </div>
</div>
</body></html>`;
}

// OIDC step-up: the SSO-hosted "no accepted verification method" card. Reached when
// an RP asks for a step-up (e.g. passkey/totp) the user owns none of. The primary
// button opens the account portal's security pane (a new page — the RP tab stays
// put); Cancel returns to the RP with error=access_denied (the RP treats it as a
// user cancel). Same card shell as the challenge page, with the amber state icon.
export function renderStepupEnrollPage(
  nonce: string,
  opts: { siteName: string; appName: string; securityUrl: string; cancelUrl: string },
): string {
  const { siteName, appName, securityUrl, cancelUrl } = opts;
  return `<!DOCTYPE html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Verify your identity · ${esc(siteName)}</title>
${baseStyle(nonce)}</head>
<body>
<div class="wrap">
  <div class="card">
    <div class="brand"><span class="badge">${SHIELD}</span><span class="wordmark">${esc(siteName)}</span></div>
    <div class="state-ico" style="background:#fef3e2">${SHIELD_X}</div>
    <h1>You need a way to verify</h1>
    <p class="msg">${esc(appName)} requires a passkey or authenticator app. Add one in your account security, then come back.</p>
    <a class="btn" href="${esc(securityUrl)}" target="_blank" rel="noopener">Open account security</a>
    <a class="btn btn-ghost btn-gap" href="${esc(cancelUrl)}">Cancel</a>
  </div>
  ${foot(siteName)}
</div>
</body></html>`;
}

// Terminal "Signed out" page (end_session). No "return to app" button by design —
// the user just logged out and will close the tab; an extra button only confuses.
export function renderSignedOutPage(nonce: string, siteName = 'DreamSSO'): string {
  return `<!DOCTYPE html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Signed out · ${esc(siteName)}</title>
${baseStyle(nonce)}</head>
<body>
<div class="wrap">
  <div class="card">
    <div class="done-badge">${CHECK}</div>
    <h1>Signed out</h1>
    <p class="msg">You've been signed out of ${esc(siteName)} and the apps you were using on this device.</p>
  </div>
  ${foot(siteName)}
</div>
</body></html>`;
}

// Neutral "service unavailable" page — served pre-setup for every public route (and
// for /setup without a valid token) so the first-run takeover surface is never
// advertised. No config hint, no CTA; styled like the rest of the SSO (gets the
// bloom via /auth-bg.svg).
export function renderUnavailablePage(nonce: string, siteName = 'DreamSSO'): string {
  return `<!DOCTYPE html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Service unavailable · ${esc(siteName)}</title>
${baseStyle(nonce)}</head>
<body>
<div class="wrap">
  <div class="card">
    <div class="brand"><span class="badge">${SHIELD}</span><span class="wordmark">${esc(siteName)}</span></div>
    <h1>Service unavailable</h1>
    <p class="msg">This service is temporarily unavailable. Please try again in a little while.</p>
  </div>
  ${foot(siteName)}
</div>
</body></html>`;
}
