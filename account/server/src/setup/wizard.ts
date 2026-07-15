import { BG_URL } from './views.js';

// The account portal's first-run /setup wizard — a self-contained, server-rendered
// page (no build step; the SPA isn't serveable until the portal is configured).
// String.raw preserves the regex/CSS backslashes verbatim; only ${nonce} and the
// background URL interpolate. Wired to GET /setup/env, POST /setup/config,
// GET /setup/probe-sso, POST /setup/mtls/*, POST /setup/finish.
export function renderWizard(nonce: string): string {
  return String.raw`<!DOCTYPE html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>First-run setup · Account console</title>
<style nonce="${nonce}">
  *{box-sizing:border-box}
  :root{color-scheme:light}
  html,body{margin:0}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Oxygen,Ubuntu,sans-serif;
    color:#1f2937;font-size:14px;line-height:1.5;min-height:100vh;
    background:#f1f0f7 url(${BG_URL}) center / auto no-repeat fixed;
    display:flex;align-items:center;justify-content:center;padding:24px}
  .wrap{width:100%;max-width:452px}
  .eyebrow{display:flex;align-items:center;justify-content:center;gap:7px;
    text-transform:uppercase;letter-spacing:.08em;font-size:11px;font-weight:600;color:#6b7280;margin:0 0 12px}
  .eyebrow svg{opacity:.7}
  .card{background:#fff;border:1px solid #e5e7eb;border-radius:16px;
    box-shadow:0 4px 24px rgba(0,0,0,.06),0 1px 2px rgba(0,0,0,.04);padding:30px 30px 26px}
  .brand{display:flex;align-items:center;gap:8px;justify-content:center;margin-bottom:20px}
  .badge{width:34px;height:34px;border-radius:10px;display:flex;align-items:center;justify-content:center;
    background:linear-gradient(135deg,#1a73e8,#1557b0);box-shadow:0 2px 8px rgba(26,115,232,.35);flex-shrink:0}
  .wordmark{font-size:14px;font-weight:700;color:#1f2937;letter-spacing:-.01em}
  .steps{display:flex;list-style:none;padding:0;margin:0 0 24px}
  .step{flex:1;display:flex;flex-direction:column;align-items:center;position:relative;
    font-size:10.5px;letter-spacing:.01em;color:#9ca3af;min-width:0}
  .step::before{content:'';position:absolute;top:11px;right:50%;width:100%;height:2px;background:#e5e7eb;z-index:0}
  .step:first-child::before{display:none}
  .step.done::before,.step.active::before{background:#1a73e8}
  .dot{width:24px;height:24px;border-radius:50%;background:#fff;border:2px solid #e5e7eb;
    display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:600;color:#9ca3af;
    position:relative;z-index:1;margin-bottom:6px;transition:.2s}
  .dot svg{width:13px;height:13px}
  .step.active .dot{border-color:#1a73e8;color:#1a73e8}
  .step.done .dot{background:#1a73e8;border-color:#1a73e8;color:#fff}
  .step.active .lbl{color:#1f2937;font-weight:600}
  h1{font-size:21px;font-weight:600;text-align:center;margin:0 0 5px;color:#1f2937;text-wrap:balance}
  .sub{text-align:center;color:#6b7280;font-size:14px;margin:0 0 24px;text-wrap:balance}
  .panel{display:none}
  .panel.on{display:block}
  .grp{margin-bottom:16px}
  label.fl{display:block;margin-bottom:6px;font-weight:500;font-size:13px;color:#374151}
  .hint{font-size:12px;color:#9ca3af;margin:6px 0 0}
  .probe{font-size:12px;margin:7px 0 0;display:flex;align-items:flex-start;gap:6px;line-height:1.4}
  .probe .pd{width:8px;height:8px;border-radius:50%;flex-shrink:0;margin-top:4px;background:#9ca3af}
  .probe.ok{color:#12805c} .probe.ok .pd{background:#16a34a}
  .probe.warn{color:#8a5a06} .probe.warn .pd{background:#f59e0b}
  .probe.checking{color:#9ca3af}
  input[type=text],input[type=url],textarea{
    width:100%;padding:10px 13px;border:1px solid #d1d5db;border-radius:10px;font-size:14px;color:#1f2937;
    outline:none;transition:border-color .15s,box-shadow .15s;font-family:inherit}
  input::placeholder,textarea::placeholder{color:#9ca3af}
  input:focus,textarea:focus{border-color:#1a73e8;box-shadow:0 0 0 3px rgba(26,115,232,.12)}
  textarea{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11.5px;line-height:1.45;
    resize:vertical;min-height:104px;white-space:pre;overflow-wrap:normal;overflow-x:auto}
  textarea:read-only{background:#f7f8fa;color:#5c6470}
  .field-err{display:none;color:#b91c1c;font-size:12px;margin-top:6px}
  .grp.bad .field-err{display:block}
  .grp.bad input,.grp.bad textarea{border-color:#dc2626}
  .grp.bad input:focus,.grp.bad textarea:focus{border-color:#dc2626;box-shadow:0 0 0 3px rgba(220,38,38,.12)}
  .checks{display:flex;flex-direction:column;gap:2px;margin-bottom:8px}
  .chk{display:flex;align-items:flex-start;gap:11px;padding:11px 2px;border-bottom:1px solid #f1f2f4}
  .chk:last-child{border-bottom:0}
  .chk-ico{width:22px;height:22px;border-radius:50%;flex-shrink:0;display:flex;align-items:center;justify-content:center;margin-top:1px}
  .chk-ico.ok{background:#d1fae5}
  .chk-ico.info{background:#e0edfe}
  .chk-ico svg{width:13px;height:13px}
  .chk-body{min-width:0;flex:1}
  .chk-name{font-size:13px;font-weight:600;color:#1f2937}
  .chk-val{font-size:12px;color:#6b7280;margin-top:1px;
    font-family:ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-all}
  .chk-note{font-size:12px;color:#6b7280;margin-top:1px}
  .review{border:1px solid #eceef1;border-radius:12px;overflow:hidden;margin-bottom:8px}
  .rrow{display:flex;justify-content:space-between;gap:14px;align-items:baseline;
    padding:11px 15px;border-bottom:1px solid #f1f2f4;font-size:13px}
  .rrow:last-child{border-bottom:0}
  .rrow .k{color:#6b7280;flex-shrink:0}
  .rrow .v{color:#1f2937;font-weight:600;text-align:right;word-break:break-all}
  .rrow .v.muted{color:#9ca3af;font-weight:500}
  .outcome{font-size:12.5px;color:#6b7280;line-height:1.6;margin:14px 2px 0}
  .outcome b{color:#374151;font-weight:600}
  .banner{background:#fef2f2;border:1px solid #fecaca;color:#b91c1c;padding:10px 13px;border-radius:9px;
    font-size:13px;margin-bottom:18px;display:none}
  .banner.on{display:block}
  .nav{display:flex;gap:10px;margin-top:24px}
  .btn{flex:1;padding:11px 16px;border:none;border-radius:10px;background:#1a73e8;color:#fff;
    font-size:14px;font-weight:600;cursor:pointer;transition:background .15s;font-family:inherit;
    box-shadow:0 1px 2px rgba(26,115,232,.4)}
  .btn:hover:not(:disabled){background:#1557b0}
  .btn-ghost{background:#fff;color:#1f2937;border:1px solid #d1d5db;box-shadow:none;flex:0 0 auto;padding:11px 20px}
  .btn-ghost:hover:not(:disabled){background:#f8f9fa}
  .btn-wide{width:100%;flex:none}
  .btn-link{background:none;border:0;color:#6b7280;font-weight:500;box-shadow:none;flex:0 0 auto;padding:11px 8px}
  .btn-link:hover:not(:disabled){background:none;color:#374151;text-decoration:underline}
  .btn:focus-visible,input:focus-visible,textarea:focus-visible{outline:2px solid #1a73e8;outline-offset:2px}
  .btn:disabled{opacity:.45;cursor:not-allowed}
  .done-badge{width:56px;height:56px;border-radius:50%;background:#d1fae5;display:flex;align-items:center;
    justify-content:center;margin:6px auto 18px}
  .msg{text-align:center;color:#6b7280;font-size:14px;line-height:1.55;margin:0 0 4px}
  .foot{display:flex;align-items:center;justify-content:center;gap:5px;text-align:center;
    color:#9ca3af;font-size:12px;margin-top:18px}
  .token-chip{display:inline-flex;align-items:center;gap:6px;background:#fff;border:1px solid #e5e7eb;
    border-radius:99px;padding:4px 12px;font-size:12px;color:#374151;margin:0 auto 16px;width:max-content}
  .token-chip svg{color:#16a34a}
  .note{font-size:12.5px;color:#5c6470;background:#f4f6f8;border:1px solid #eceef1;border-radius:9px;padding:9px 12px;margin-bottom:16px}
  .note.warn{background:#fffaf0;border-color:#fbe4bf;color:#8a5a06}
  .note code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}
  input.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px}
  input:read-only{background:#f7f8fa;color:#6b7280;cursor:default}
  .from-env{float:right;font-size:11px;font-weight:600;color:#12805c}
  .lrow{display:flex;align-items:baseline;justify-content:space-between;gap:10px;margin-bottom:6px}
  .lrow label.fl{margin-bottom:0}
  .linkbtn{background:none;border:0;padding:0;font:inherit;font-size:12px;font-weight:600;color:#1a73e8;cursor:pointer}
  .linkbtn:hover{text-decoration:underline}
  .hint-c{text-align:center}
  .handoff{border:1px solid #e5e7eb;border-radius:12px;padding:14px 15px;margin:18px 0 0;text-align:left}
  .handoff .t{font-size:13px;font-weight:600;color:#1f2937;margin-bottom:8px}
  .handoff .d{font-size:12.5px;color:#6b7280;line-height:1.55;margin-bottom:10px}
  .copyrow{display:flex;gap:8px}
  .copyrow input{flex:1;min-width:0}
</style></head>
<body>
<div class="wrap">
  <p class="eyebrow">
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none"><path d="M12 3l7 3v5c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6z" stroke="#6b7280" stroke-width="2" stroke-linejoin="round"/></svg>
    First-run setup
  </p>
  <div class="card">
    <div class="brand">
      <span class="badge"><svg width="20" height="20" viewBox="0 0 24 24" fill="none"><path d="M12 3l7 3v5c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6z" stroke="#fff" stroke-width="2" stroke-linejoin="round"/><rect x="9.5" y="11.5" width="5" height="4" rx="1" stroke="#fff" stroke-width="1.6"/><path d="M10.5 11.5v-1a1.5 1.5 0 0 1 3 0v1" stroke="#fff" stroke-width="1.6"/></svg></span>
      <span class="wordmark">Account console</span>
    </div>
    <ol class="steps" id="stepper">
      <li class="step" data-i="0"><span class="dot">1</span><span class="lbl">Connection</span></li>
      <li class="step" data-i="1"><span class="dot">2</span><span class="lbl">Certificate</span></li>
      <li class="step" data-i="2"><span class="dot">3</span><span class="lbl">Finish</span></li>
    </ol>
    <div class="banner" id="banner"></div>

    <section class="panel" data-panel="0">
      <h1>Connect to your SSO</h1>
      <p class="sub">The portal keeps this in a <code>.env</code> file. Fill it in here, or create the file yourself — the wizard verifies either way.</p>
      <div id="env-form">
        <div class="note" id="env-note">Loading&hellip;</div>
        <div class="grp">
          <label class="fl" for="portal">Portal URL</label>
          <input type="url" id="portal" class="mono" autocapitalize="none" spellcheck="false"
            data-required data-rule="portal" placeholder="https://account.example.com">
          <p class="hint">This portal's own public https origin. Its callback, key and event endpoints are derived from it.</p>
          <span class="field-err"></span>
        </div>
        <div class="grp">
          <label class="fl" for="issuer">SSO issuer</label>
          <input type="url" id="issuer" class="mono" autocapitalize="none" spellcheck="false"
            data-required data-rule="issuer" placeholder="https://sso.example.com">
          <span class="field-err"></span>
          <p class="probe" id="sso-probe" hidden></p>
        </div>
        <div class="grp">
          <label class="fl" for="redisurl">Redis URL</label>
          <input type="text" id="redisurl" class="mono" data-required data-rule="redis" placeholder="redis://127.0.0.1:6379">
          <p class="hint">Holds sessions. The portal has no database of its own.</p>
          <span class="field-err"></span>
        </div>
      </div>
      <div id="env-ready" hidden>
        <div class="token-chip"><svg width="13" height="13" viewBox="0 0 24 24" fill="none"><path d="M20 6L9 17l-5-5" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/></svg> Configuration saved</div>
        <div class="checks">
          <div class="chk"><span class="chk-ico ok" data-ok></span><div class="chk-body"><div class="chk-name">Portal URL</div><div class="chk-val" id="rv-portal"></div></div></div>
          <div class="chk"><span class="chk-ico ok" data-ok></span><div class="chk-body"><div class="chk-name">SSO issuer</div><div class="chk-val" id="rv-issuer"></div></div></div>
          <div class="chk"><span class="chk-ico ok" data-ok></span><div class="chk-body"><div class="chk-name">Redis</div><div class="chk-val" id="rv-redis"></div></div></div>
          <div class="chk"><span class="chk-ico ok" data-ok></span><div class="chk-body"><div class="chk-name">Client key</div><div class="chk-val" id="rv-kid"></div><div class="chk-note">Generated here — the SSO reads the public half from your key endpoint.</div></div></div>
          <div class="chk"><span class="chk-ico info" data-info></span><div class="chk-body"><div class="chk-name">Derived endpoints</div><div class="chk-val" id="rv-derived"></div></div></div>
        </div>
      </div>
    </section>

    <section class="panel" data-panel="1">
      <h1>Client certificate</h1>
      <p class="sub">Optional. The portal presents this to the SSO on every server-to-server call once your edge enforces mTLS.</p>

      <div id="mtls-start">
        <div class="note">The private key is generated here and never leaves. You'll get a signing request (CSR) to hand to your certificate authority — in Cloudflare, <b>SSL/TLS &rsaquo; Client Certificates &rsaquo; Use my private key and CSR</b>.</div>
        <div class="grp">
          <label class="fl" for="cn">Common name</label>
          <input type="text" id="cn" class="mono" autocapitalize="none" spellcheck="false" placeholder="account-portal">
          <p class="hint">Identifies this portal on the certificate. Leave blank for a generated name.</p>
        </div>
        <button class="btn btn-ghost btn-wide" id="gen-csr">Generate key &amp; signing request</button>
      </div>

      <div id="mtls-pending" hidden>
        <div class="grp">
          <div class="lrow">
            <label class="fl" for="csr">Signing request (CSR)</label>
            <button type="button" class="linkbtn" id="csr-copy">Copy</button>
          </div>
          <textarea id="csr" readonly spellcheck="false"></textarea>
          <p class="hint">Paste this into your CA. ECDSA P-256.</p>
        </div>
        <div class="grp">
          <label class="fl" for="cert">Signed certificate</label>
          <textarea id="cert" spellcheck="false" placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"></textarea>
          <p class="hint">The leaf, or the full chain — order doesn't matter.</p>
          <span class="field-err"></span>
        </div>
        <button class="btn btn-wide" id="install-cert">Install certificate</button>
      </div>

      <div id="mtls-done" hidden>
        <div class="token-chip"><svg width="13" height="13" viewBox="0 0 24 24" fill="none"><path d="M20 6L9 17l-5-5" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/></svg> Certificate installed</div>
        <div class="checks">
          <div class="chk"><span class="chk-ico ok" data-ok></span><div class="chk-body"><div class="chk-name">Subject</div><div class="chk-val" id="cv-cn"></div></div></div>
          <div class="chk"><span class="chk-ico ok" data-ok></span><div class="chk-body"><div class="chk-name">Issued by</div><div class="chk-val" id="cv-issuer"></div></div></div>
          <div class="chk"><span class="chk-ico ok" data-ok></span><div class="chk-body"><div class="chk-name">Expires</div><div class="chk-val" id="cv-exp"></div></div></div>
          <div class="chk"><span class="chk-ico ok" data-ok></span><div class="chk-body"><div class="chk-name">Presentation</div><div class="chk-note">Enabled — outbound calls to the SSO now carry this certificate.</div></div></div>
        </div>
        <p class="hint hint-c">Wrong certificate? <button type="button" class="linkbtn" id="cert-reset">Start over</button></p>
      </div>
    </section>

    <section class="panel" data-panel="2">
      <h1>Review &amp; finish</h1>
      <p class="sub">Nothing else is written — this just unlocks the portal.</p>
      <div class="review" id="review"></div>
      <p class="outcome">Completing setup <b>locks this wizard</b> — <code>/setup</code> stops responding and the portal goes live. Then run the SSO's setup and give it this portal's URL.</p>
    </section>

    <section class="panel" data-panel="3">
      <div class="done-badge"><svg width="28" height="28" viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="9" stroke="#065f46" stroke-width="2"/><path d="M8.5 12l2.5 2.5 4.5-4.5" stroke="#065f46" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg></div>
      <h1>Portal is live</h1>
      <p class="msg">This wizard is now locked.</p>
      <div class="handoff">
        <div class="t">Next: set up your SSO</div>
        <div class="d">Run the SSO's first-run wizard and give it this URL when it asks for the account portal. It registers the portal and reads its key automatically — there's nothing to copy across.</div>
        <div class="copyrow">
          <input type="text" id="handoff-url" class="mono" readonly>
          <button class="btn btn-ghost" id="handoff-copy">Copy</button>
        </div>
      </div>
      <div class="nav"><button class="btn" id="go-portal">Open the portal</button></div>
    </section>

    <div class="nav" id="nav">
      <button class="btn-link" id="back" hidden>Back</button>
      <button class="btn-ghost" id="skip" hidden>Skip</button>
      <button class="btn" id="next">Continue</button>
    </div>
  </div>
  <div class="foot">
    <svg width="12" height="12" viewBox="0 0 24 24" fill="none"><rect x="5" y="11" width="14" height="9" rx="2" stroke="#9ca3af" stroke-width="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3" stroke="#9ca3af" stroke-width="2" stroke-linecap="round"/></svg>
    Account console · first-run setup
  </div>
</div>

<script nonce="${nonce}">
(function(){
  var CHECK='<svg viewBox="0 0 24 24" fill="none"><path d="M20 6L9 17l-5-5" stroke="#065f46" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"/></svg>';
  var INFO='<svg viewBox="0 0 24 24" fill="none"><path d="M12 8h.01M11 12h1v4h1" stroke="#1a73e8" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><circle cx="12" cy="12" r="9" stroke="#1a73e8" stroke-width="1.6"/></svg>';
  document.querySelectorAll('[data-ok]').forEach(function(e){e.innerHTML=CHECK;});
  document.querySelectorAll('[data-info]').forEach(function(e){e.innerHTML=INFO;});

  var cur=0, LAST=2;
  var stepper=document.getElementById('stepper');
  var banner=document.getElementById('banner');
  var back=document.getElementById('back'), next=document.getElementById('next'), skip=document.getElementById('skip');
  function panels(){return document.querySelectorAll('.panel');}
  function panel(i){return document.querySelector('.panel[data-panel="'+i+'"]');}
  function el(id){return document.getElementById(id);}
  function val(id){return (el(id).value||'').trim();}
  function setText(id,t){var e=el(id); if(e) e.textContent=t;}
  function showBanner(msg){ banner.textContent=msg; banner.classList.add('on'); }
  function postJSON(url,body){ return fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body||{}),credentials:'same-origin'}); }
  function esc(s){return String(s).replace(/[&<>"]/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});}
  function flash(btn,txt){ var o=btn.textContent; btn.textContent=txt; setTimeout(function(){btn.textContent=o;},1400); }
  function copy(text,btn){ try{ navigator.clipboard && navigator.clipboard.writeText(text); }catch(e){} flash(btn,'Copied'); }

  // ---- validation (mirrors the server's rules, so the two never disagree) ----
  function httpsMsg(v,what){
    try{ if(new URL(v).protocol!=='https:') return 'Use an https:// address.'; }
    catch(e){ return 'Enter a full URL, e.g. https://'+what+'.example.com'; }
    return '';
  }
  function ruleMsg(inp){
    var v=(inp.value||'').trim();
    var rule=inp.getAttribute('data-rule');
    if(!v) return inp.hasAttribute('data-required') ? emptyMsg(rule) : '';
    if(rule==='portal') return httpsMsg(v,'account');
    if(rule==='issuer') return httpsMsg(v,'sso');
    if(rule==='redis' && !/^rediss?:\/\/.+/.test(v)) return 'Must start with redis:// (or rediss:// for TLS).';
    return '';
  }
  function emptyMsg(rule){
    return ({portal:"Enter this portal's URL.",issuer:'Enter the SSO issuer URL.',redis:'Enter the Redis URL.'})[rule]||'This field is required.';
  }
  function setBad(inp,msg){ var g=inp.closest('.grp'); g.classList.add('bad'); var s=g.querySelector('.field-err'); if(s) s.textContent=msg; }
  function clearBad(inp){ var g=inp.closest('.grp'); if(g) g.classList.remove('bad'); }

  // Installer-only: flag on BLUR (click-out), clear on ANY edit.
  document.querySelectorAll('input[data-rule]').forEach(function(inp){
    inp.addEventListener('blur',function(){ var m=ruleMsg(inp); if(m) setBad(inp,m); });
    inp.addEventListener('input',function(){ clearBad(inp); });
  });

  // ---- step 1: connection ----
  var envVerified=false, keyKid='', derivedUris=null, portalUrl='';
  var envForm=el('env-form'), envReady=el('env-ready'), envNote=el('env-note');

  function lockField(id,v){
    var e=el(id); e.value=v||''; e.readOnly=true;
    var g=e.closest('.grp'); g.classList.remove('bad');
    var lbl=g.querySelector('label');
    if(lbl && !lbl.querySelector('.from-env')){ var t=document.createElement('span'); t.className='from-env'; t.textContent='✓ from .env'; lbl.appendChild(t); }
  }
  function openField(id,v){
    var e=el(id); e.value=v||''; e.readOnly=false;
    var g=e.closest('.grp'); g.classList.remove('bad');
    var t=g.querySelector('.from-env'); if(t) t.remove();
  }
  function setField(id,f,dflt){ if(f && f.present) lockField(id,f.value); else openField(id,dflt); }

  function step1Valid(){
    if(envVerified) return true;
    var ok=true;
    envForm.querySelectorAll('input[data-required]').forEach(function(inp){ if(!inp.readOnly && ruleMsg(inp)) ok=false; });
    return ok;
  }
  function renderStep1(){
    envForm.hidden=envVerified; envReady.hidden=!envVerified;
    if(envVerified){ next.disabled=false; next.textContent='Continue'; }
    else { next.textContent='Save configuration'; next.disabled=!step1Valid(); }
  }
  function fillReady(d){
    setText('rv-portal', d.portal);
    setText('rv-issuer', d.issuer);
    setText('rv-redis', d.redis+' · reachable');
    setText('rv-kid', d.kid);
    setText('rv-derived', d.redirectUri+'  ·  '+d.jwksUri);
  }
  function configPayload(){
    var o={};
    [['portal','publicUrl'],['issuer','issuer'],['redisurl','redisUrl']].forEach(function(p){
      var e=el(p[0]); if(!e.readOnly) o[p[1]]=e.value.trim();
    });
    return o;
  }
  function paintConfigErrors(errors){
    var map={publicUrl:'portal',issuer:'issuer',redis:'redisurl'};
    var first=null;
    Object.keys(errors).forEach(function(k){
      var id=map[k]; if(!id) return;
      var e=el(id); if(!e) return;
      setBad(e,errors[k]); if(!first) first=e;
    });
    if(first) first.focus();
  }
  function saveEnv(){
    next.disabled=true; next.textContent='Saving & testing…';
    postJSON('/setup/config',configPayload()).then(function(res){
      if(!res.ok){
        return res.json().then(function(d){ paintConfigErrors(d.errors||{}); next.disabled=false; next.textContent='Save configuration'; });
      }
      return res.json().then(function(d){
        envVerified=true; keyKid=d.kid; derivedUris=d; portalUrl=d.redirectUri.replace(/\/auth\/callback$/,'');
        fillReady({ portal:portalUrl, issuer:val('issuer'), redis:val('redisurl'), kid:d.kid, redirectUri:d.redirectUri, jwksUri:d.jwksUri });
        renderStep1();
      });
    }).catch(function(){ showBanner('Could not reach the server — please try again.'); next.disabled=false; next.textContent='Save configuration'; });
  }
  function loadEnv(){
    fetch('/setup/env',{credentials:'same-origin'}).then(function(r){return r.json();}).then(function(d){
      var f=d.fields||{};
      setField('portal',f.publicUrl,''); setField('issuer',f.issuer,''); setField('redisurl',f.redis,'redis://127.0.0.1:6379');
      var partial=(f.publicUrl&&f.publicUrl.present)||(f.issuer&&f.issuer.present)||(f.redis&&f.redis.present);
      envNote.className='note';
      envNote.innerHTML = partial ? 'Found <code>.env</code> — fill in anything still missing.' : 'No <code>.env</code> found — the wizard will create one.';
      renderStep1(); render();
    }).catch(function(){ envNote.className='note warn'; envNote.textContent='Could not load setup state — reload the page.'; });
  }

  // Non-blocking SSO reachability probe: warns if the SSO isn't up or advertises a
  // different issuer, but never blocks (the SSO may be installed after the portal).
  var issuerEl=el('issuer'), ssoProbe=el('sso-probe');
  function probeSso(){
    var v=issuerEl.value.trim();
    if(!v || ruleMsg(issuerEl)){ ssoProbe.hidden=true; return; }
    ssoProbe.hidden=false; ssoProbe.className='probe checking'; ssoProbe.innerHTML='<span class="pd"></span>Checking the SSO…';
    fetch('/setup/probe-sso?url='+encodeURIComponent(v),{credentials:'same-origin'}).then(function(r){return r.json();}).then(function(d){
      var cls,msg;
      if(d.ok){ cls='ok'; msg='SSO reachable — discovery matches this issuer.'; }
      else if(d.reason==='issuer_mismatch'){ cls='warn'; msg='That host advertises a different issuer ('+esc(d.issuer||'')+'). Sign-in would fail — use that value instead.'; }
      else if(d.reachable){ cls='warn'; msg='Reached the host, but it isn’t serving OpenID discovery yet.'; }
      else { cls='warn'; msg='Couldn’t reach the SSO yet — fine if you’ll start it later; the portal needs it online to sign anyone in.'; }
      ssoProbe.className='probe '+cls; ssoProbe.innerHTML='<span class="pd"></span>'+msg;
    }).catch(function(){ ssoProbe.hidden=true; });
  }
  issuerEl.addEventListener('blur',probeSso);
  issuerEl.addEventListener('input',function(){ ssoProbe.hidden=true; });

  // ---- step 2: client certificate (optional) ----
  var certInfo=null;
  var mStart=el('mtls-start'), mPending=el('mtls-pending'), mDone=el('mtls-done');
  function renderMtls(){
    mStart.hidden = !!certInfo || !!el('csr').value;
    mPending.hidden = !!certInfo || !el('csr').value;
    mDone.hidden = !certInfo;
    skip.hidden = !!certInfo;      // nothing left to skip once it's installed
    next.disabled=false;
    next.textContent='Continue';
  }
  function fmtDate(iso){ try{ return new Date(iso).toLocaleDateString(undefined,{year:'numeric',month:'short',day:'numeric'}); }catch(e){ return iso; } }
  function showCert(d){
    certInfo=d;
    setText('cv-cn', d.cn||'—');
    setText('cv-issuer', d.issuer||'—');
    setText('cv-exp', fmtDate(d.not_after));
    renderMtls();
  }
  el('gen-csr').addEventListener('click',function(){
    var b=this; b.disabled=true; b.textContent='Generating…';
    postJSON('/setup/mtls/start',{cn:val('cn')}).then(function(r){return r.json();}).then(function(d){
      b.disabled=false; b.textContent='Generate key & signing request';
      if(!d.csr){ showBanner('Could not generate a signing request.'); return; }
      el('csr').value=d.csr; el('cn').value=d.cn;
      renderMtls();
      setTimeout(function(){ el('cert').focus(); },50);
    }).catch(function(){ b.disabled=false; b.textContent='Generate key & signing request'; showBanner('Could not reach the server — please try again.'); });
  });
  el('csr-copy').addEventListener('click',function(){ copy(el('csr').value,this); });
  el('cert').addEventListener('input',function(){ clearBad(el('cert')); });
  el('install-cert').addEventListener('click',function(){
    var b=this, ta=el('cert'), v=(ta.value||'').trim();
    clearBad(ta);
    if(!v){ setBad(ta,'Paste the certificate your CA issued.'); return; }
    b.disabled=true; b.textContent='Installing…';
    postJSON('/setup/mtls/install',{cert:v}).then(function(res){
      return res.json().then(function(d){
        b.disabled=false; b.textContent='Install certificate';
        if(res.ok){ showCert(d); return; }
        setBad(ta,({parse_failed:"That doesn’t look like a PEM certificate.",
          key_mismatch:'That certificate was issued for a different key. Use the signing request above.',
          expired:'That certificate has already expired.',
          no_key:'No signing request is pending — generate one first.',
          no_cert:'Paste the certificate your CA issued.'})[d.reason] || 'That certificate could not be installed.');
      });
    }).catch(function(){ b.disabled=false; b.textContent='Install certificate'; showBanner('Could not reach the server — please try again.'); });
  });
  el('cert-reset').addEventListener('click',function(){
    postJSON('/setup/mtls/reset').then(function(){
      certInfo=null; el('csr').value=''; el('cert').value=''; clearBad(el('cert'));
      renderMtls();
    });
  });

  // ---- review ----
  function buildReview(){
    var rows=[
      ['Portal URL', portalUrl||'—'],
      ['SSO issuer', val('issuer')||'—'],
      ['Redis', val('redisurl')||'—'],
      ['Client key', keyKid ? keyKid.slice(0,16)+'…' : '—'],
      ['Client certificate', certInfo ? (certInfo.cn||'installed') : 'Skipped']
    ];
    el('review').innerHTML=rows.map(function(r){
      var muted=(r[1]==='—'||r[1]==='Skipped')?' muted':'';
      return '<div class="rrow"><span class="k">'+r[0]+'</span><span class="v'+muted+'">'+esc(r[1])+'</span></div>';
    }).join('');
  }

  // ---- navigation ----
  function render(){
    panels().forEach(function(p){p.classList.remove('on');});
    var done = cur>LAST;
    panel(done?3:cur).classList.add('on');
    el('nav').style.display = done?'none':'flex';
    stepper.querySelectorAll('.step').forEach(function(s){
      var i=+s.getAttribute('data-i');
      s.classList.remove('active','done');
      if(done||i<cur) s.classList.add('done');
      else if(i===cur) s.classList.add('active');
      var dot=s.querySelector('.dot');
      dot.innerHTML=(done||i<cur)?'<svg viewBox="0 0 24 24" fill="none"><path d="M20 6L9 17l-5-5" stroke="#fff" stroke-width="2.8" stroke-linecap="round" stroke-linejoin="round"/></svg>':(i+1);
    });
    if(done) return;
    back.hidden = cur===0;
    skip.hidden = cur!==1;
    banner.classList.remove('on');
    if(cur===0) renderStep1();
    else if(cur===1) renderMtls();
    else { next.disabled=false; next.textContent='Complete setup'; buildReview(); }
  }
  function advance(){
    if(cur===0){
      if(!envVerified){
        if(!step1Valid()){ panel(0).querySelectorAll('input[data-rule]').forEach(function(inp){ var m=ruleMsg(inp); if(m) setBad(inp,m); }); return; }
        saveEnv(); return;
      }
      cur++; render(); return;
    }
    if(cur===LAST){ doFinish(); return; }
    cur++; render();
  }

  // ---- finish ----
  function doFinish(){
    next.disabled=true; next.textContent='Finishing…';
    postJSON('/setup/finish').then(function(res){
      if(res.status===204){
        el('handoff-url').value=portalUrl;
        cur=3; render();
        return;
      }
      next.disabled=false; next.textContent='Complete setup';
      showBanner('Setup could not be completed — please try again.');
    }).catch(function(){ next.disabled=false; next.textContent='Complete setup'; showBanner('Could not reach the server — please try again.'); });
  }

  // ---- wire ----
  next.addEventListener('click',advance);
  back.addEventListener('click',function(){ if(cur>0){ cur--; render(); } });
  skip.addEventListener('click',function(){ cur++; render(); });
  el('handoff-copy').addEventListener('click',function(){ copy(portalUrl,this); });
  el('go-portal').addEventListener('click',function(){ location.href='/'; });
  envForm.addEventListener('input',renderStep1);

  render();   // paint the shell immediately
  loadEnv();  // then populate step 1 from the server
})();
</script>
</body></html>`;
}
