// The first-run /setup wizard — a self-contained, server-rendered page (no build
// step). String.raw preserves the regex/CSS backslashes verbatim; only ${nonce}
// interpolates. Wired to GET /setup/env, POST /setup/config, POST /setup/finish.
export function renderWizard(nonce: string): string {
  return String.raw`<!DOCTYPE html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<title>First-run setup · DreamSSO</title>
<style nonce="${nonce}">
  *{box-sizing:border-box}
  :root{color-scheme:light}
  html,body{margin:0}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Oxygen,Ubuntu,sans-serif;
    color:#1f2937;font-size:14px;line-height:1.5;min-height:100vh;
    background:#f1f0f7 url(/auth-bg.svg) center / auto no-repeat fixed;
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
  .grp-t14{margin-top:14px}
  .grp-t18{margin-top:18px}
  label.fl{display:block;margin-bottom:6px;font-weight:500;font-size:13px;color:#374151}
  .hint{font-size:12px;color:#9ca3af;margin:6px 0 0}
  .probe{font-size:12px;margin:7px 0 0;display:flex;align-items:flex-start;gap:6px;line-height:1.4}
  .probe .pd{width:8px;height:8px;border-radius:50%;flex-shrink:0;margin-top:4px;background:#9ca3af}
  .probe.ok{color:#12805c} .probe.ok .pd{background:#16a34a}
  .probe.warn{color:#8a5a06} .probe.warn .pd{background:#f59e0b}
  .probe.checking{color:#9ca3af}
  input[type=text],input[type=email],input[type=password],input[type=url]{
    width:100%;padding:10px 13px;border:1px solid #d1d5db;border-radius:10px;font-size:14px;color:#1f2937;
    outline:none;transition:border-color .15s,box-shadow .15s;font-family:inherit}
  input::placeholder{color:#9ca3af}
  input:focus{border-color:#1a73e8;box-shadow:0 0 0 3px rgba(26,115,232,.12)}
  .field-err{display:none;color:#b91c1c;font-size:12px;margin-top:6px}
  .grp.bad .field-err{display:block}
  .grp.bad input{border-color:#dc2626}
  .grp.bad input:focus{border-color:#dc2626;box-shadow:0 0 0 3px rgba(220,38,38,.12)}
  .pw-wrap{position:relative}
  .pw-wrap input{padding-right:64px}
  .reveal{position:absolute;top:0;right:0;height:100%;padding:0 12px;background:none;border:0;
    font:inherit;font-size:12px;font-weight:600;color:#6b7280;cursor:pointer}
  .reveal:hover{color:#374151}
  .pwrules{list-style:none;padding:0;margin:10px 0 0;display:flex;flex-direction:column;gap:6px}
  .pwrule{display:flex;align-items:center;gap:8px;font-size:12px;color:#9ca3af;transition:color .15s}
  .pwrule-ico{width:15px;height:15px;flex-shrink:0;display:inline-flex;align-items:center;justify-content:center;
    border-radius:50%;font-size:9px;font-weight:700;background:#eceef1;color:#9ca3af;transition:.15s}
  .pwrule.pass{color:#065f46}
  .pwrule.pass .pwrule-ico{background:#d1fae5;color:#065f46}
  .pwrule.fail{color:#b91c1c}
  .pwrule.fail .pwrule-ico{background:#fee2e2;color:#b91c1c}
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
  .switch-row{display:flex;align-items:center;justify-content:space-between;gap:12px;
    padding:13px 15px;border:1px solid #e5e7eb;border-radius:12px;margin-bottom:4px}
  .switch-row .t{font-size:13px;font-weight:600;color:#1f2937}
  .switch-row .d{font-size:12px;color:#9ca3af;margin-top:2px}
  .switch{position:relative;width:40px;height:23px;flex-shrink:0;cursor:pointer}
  .switch input{position:absolute;opacity:0;width:100%;height:100%;margin:0;cursor:pointer}
  .track{position:absolute;inset:0;background:#d1d5db;border-radius:99px;transition:.18s}
  .track::after{content:'';position:absolute;top:2px;left:2px;width:19px;height:19px;
    background:#fff;border-radius:50%;box-shadow:0 1px 2px rgba(0,0,0,.3);transition:.18s}
  .switch input:checked + .track{background:#1a73e8}
  .switch input:checked + .track::after{transform:translateX(17px)}
  .email-fields{margin-top:16px}
  .email-fields[hidden]{display:none}
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
  .btn:hover{background:#1557b0}
  .btn-ghost{background:#fff;color:#1f2937;border:1px solid #d1d5db;box-shadow:none;flex:0 0 auto;padding:11px 20px}
  .btn-ghost:hover{background:#f8f9fa}
  .btn-link{background:none;border:0;color:#6b7280;font-weight:500;box-shadow:none;flex:0 0 auto;padding:11px 8px}
  .btn-link:hover{background:none;color:#374151;text-decoration:underline}
  .btn:focus-visible,.reveal:focus-visible,.switch input:focus-visible + .track,input:focus-visible{outline:2px solid #1a73e8;outline-offset:2px}
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
  .gen-pill{font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.04em;color:#065f46;
    background:#d1fae5;border-radius:99px;padding:1px 8px;margin-left:6px;vertical-align:middle}
  .from-env{float:right;font-size:11px;font-weight:600;color:#12805c}
  .linkbtn{background:none;border:0;padding:0;font:inherit;font-size:12px;font-weight:600;color:#1a73e8;cursor:pointer}
  .linkbtn:hover{text-decoration:underline}
  details.adv{margin-top:6px;border-top:1px solid #f1f2f4;padding-top:14px}
  details.adv summary{font-size:13px;font-weight:600;color:#374151;cursor:pointer;list-style:none;user-select:none}
  details.adv summary::-webkit-details-marker{display:none}
  details.adv summary::before{content:'\25B8\00a0';color:#9ca3af}
  details.adv[open] summary::before{content:'\25BE\00a0'}
  .btn:disabled{opacity:.45;cursor:not-allowed}
  .btn:disabled:hover{background:#1a73e8}
</style></head>
<body>
<div class="wrap">
  <p class="eyebrow">
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none"><path d="M12 3l7 3v5c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6z" stroke="#6b7280" stroke-width="2" stroke-linejoin="round"/></svg>
    First-run setup
  </p>
  <div class="card" id="card">
    <div class="brand">
      <span class="badge"><svg width="20" height="20" viewBox="0 0 24 24" fill="none"><path d="M12 3l7 3v5c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6z" stroke="#fff" stroke-width="2" stroke-linejoin="round"/><rect x="9.5" y="11.5" width="5" height="4" rx="1" stroke="#fff" stroke-width="1.6"/><path d="M10.5 11.5v-1a1.5 1.5 0 0 1 3 0v1" stroke="#fff" stroke-width="1.6"/></svg></span>
      <span class="wordmark">DreamSSO</span>
    </div>
    <ol class="steps" id="stepper">
      <li class="step" data-i="0"><span class="dot">1</span><span class="lbl">Server</span></li>
      <li class="step" data-i="1"><span class="dot">2</span><span class="lbl">Admin</span></li>
      <li class="step" data-i="2"><span class="dot">3</span><span class="lbl">Site</span></li>
      <li class="step" data-i="3"><span class="dot">4</span><span class="lbl">Email</span></li>
      <li class="step" data-i="4"><span class="dot">5</span><span class="lbl">Finish</span></li>
    </ol>
    <div class="banner" id="banner"></div>

    <section class="panel" data-panel="0">
      <h1>Server configuration</h1>
      <p class="sub">DreamSSO stores this in a <code>.env</code> file. Fill it in here, or create the file yourself — the wizard verifies either way.</p>
      <div id="env-form">
        <div class="note" id="env-note">Loading&hellip;</div>
        <div class="grp" id="grp-key">
          <label class="fl">Encryption key<span class="gen-pill" id="key-pill">generated</span></label>
          <div class="pw-wrap">
            <input type="text" id="enckey" class="mono" readonly>
            <button type="button" class="reveal" id="key-copy">Copy</button>
          </div>
          <p class="hint" id="key-hint">32 random bytes, written to <code>.env</code> as <code>KEY_ENCRYPTION_KEY</code>. <button type="button" class="linkbtn" id="key-regen">Regenerate</button></p>
        </div>
        <div class="grp">
          <label class="fl" for="dburl">Database URL</label>
          <input type="text" id="dburl" class="mono" data-required data-rule="pg" placeholder="postgres://user:pass@host:5432/dreamsso">
          <span class="field-err"></span>
        </div>
        <div class="grp">
          <label class="fl" for="redisurl">Redis URL</label>
          <input type="text" id="redisurl" class="mono" data-required data-rule="redis" placeholder="redis://127.0.0.1:6379">
          <span class="field-err"></span>
        </div>
        <div class="grp">
          <label class="fl" for="issuer">Issuer URL</label>
          <input type="url" id="issuer" class="mono" data-required data-rule="issuer" placeholder="https://sso.example.com">
          <p class="hint">The public https origin. Baked into every token — it can't change later.</p>
          <span class="field-err"></span>
        </div>
        <details class="adv">
          <summary>Passkeys (optional)</summary>
          <div class="grp grp-t14">
            <label class="fl" for="rpid">WebAuthn RP ID</label>
            <input type="text" id="rpid" class="mono" data-rule="host" placeholder="example.com">
            <span class="field-err"></span>
          </div>
          <div class="grp">
            <label class="fl" for="origins">WebAuthn origins</label>
            <input type="text" id="origins" class="mono" data-rule="origins" placeholder="https://sso.example.com,https://account.example.com">
            <p class="hint">Comma-separated https origins. Leave blank to disable passkeys — you can enable them later.</p>
            <span class="field-err"></span>
          </div>
        </details>
      </div>
      <div id="env-ready" hidden>
        <div class="token-chip"><svg width="13" height="13" viewBox="0 0 24 24" fill="none"><path d="M20 6L9 17l-5-5" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/></svg> Setup token verified</div>
        <div class="checks">
          <div class="chk"><span class="chk-ico ok" data-ok></span><div class="chk-body"><div class="chk-name">Encryption key</div><div class="chk-val">KEY_ENCRYPTION_KEY · 64 hex</div></div></div>
          <div class="chk"><span class="chk-ico ok" data-ok></span><div class="chk-body"><div class="chk-name">Database</div><div class="chk-val" id="rv-db"></div></div></div>
          <div class="chk"><span class="chk-ico ok" data-ok></span><div class="chk-body"><div class="chk-name">Redis</div><div class="chk-val" id="rv-redis"></div></div></div>
          <div class="chk"><span class="chk-ico ok" data-ok></span><div class="chk-body"><div class="chk-name">Issuer</div><div class="chk-val" id="rv-issuer"></div></div></div>
          <div class="chk"><span class="chk-ico ok" data-ok></span><div class="chk-body"><div class="chk-name">Signing keys</div><div class="chk-note">Generated at boot</div></div></div>
          <div class="chk"><span class="chk-ico info" data-info></span><div class="chk-body"><div class="chk-name">Passkeys</div><div class="chk-note" id="rv-passkeys"></div></div></div>
        </div>
      </div>
    </section>

    <section class="panel" data-panel="1">
      <h1>Create your administrator</h1>
      <p class="sub">The first account. It becomes the superadmin and can never be locked out.</p>
      <div class="grp">
        <label class="fl" for="username">Username</label>
        <input type="text" id="username" autocomplete="off" autocapitalize="none" spellcheck="false"
          data-required data-rule="username" placeholder="jordan_reyes">
        <span class="field-err"></span>
      </div>
      <div class="grp">
        <label class="fl" for="displayname">Display name</label>
        <input type="text" id="displayname" autocomplete="off" data-required data-rule="name" placeholder="Jordan Reyes">
        <p class="hint">Shown on the account menu and in audit logs.</p>
        <span class="field-err"></span>
      </div>
      <div class="grp">
        <label class="fl" for="email">Email address</label>
        <input type="email" id="email" autocomplete="off" autocapitalize="none" spellcheck="false"
          data-required data-rule="email" placeholder="you@example.com">
        <span class="field-err"></span>
      </div>
      <div class="grp">
        <label class="fl" for="password">Password</label>
        <div class="pw-wrap">
          <input type="password" id="password" autocomplete="new-password" data-required data-rule="password" placeholder="At least 8 characters">
          <button type="button" class="reveal" data-reveal="password">Show</button>
        </div>
        <ul class="pwrules" id="pwrules">
          <li class="pwrule" data-k="length"><span class="pwrule-ico">•</span>At least 8 characters</li>
          <li class="pwrule" data-k="complexity"><span class="pwrule-ico">•</span>Includes 3 of: uppercase, lowercase, digit, special character</li>
        </ul>
        <span class="field-err"></span>
      </div>
      <div class="grp">
        <label class="fl" for="confirm">Confirm password</label>
        <div class="pw-wrap">
          <input type="password" id="confirm" autocomplete="new-password" data-required data-rule="match" data-match="password" placeholder="Re-enter your password">
          <button type="button" class="reveal" data-reveal="confirm">Show</button>
        </div>
        <span class="field-err"></span>
      </div>
    </section>

    <section class="panel" data-panel="2">
      <h1>Name your sign-in</h1>
      <p class="sub">Shown on every sign-in page and in the shield footer.</p>
      <div class="grp">
        <label class="fl" for="sitename">Site name</label>
        <input type="text" id="sitename" data-required data-rule="text" placeholder="Acme SSO" value="DreamSSO">
        <p class="hint">Appears as the wordmark and in “Protected by …”.</p>
        <span class="field-err"></span>
      </div>
      <div class="grp">
        <label class="fl" for="portal">Account portal URL</label>
        <input type="url" id="portal" autocapitalize="none" spellcheck="false" data-required data-rule="url" placeholder="https://account.example.com">
        <p class="hint">Where people manage their password, passkeys, and sessions.</p>
        <span class="field-err"></span>
        <p class="probe" id="portal-probe" hidden></p>
      </div>
    </section>

    <section class="panel" data-panel="3">
      <h1>Outbound email</h1>
      <p class="sub">Powers verification codes and password resets. You can add this later from Settings.</p>
      <div class="switch-row">
        <div>
          <div class="t">Configure email now</div>
          <div class="d">Cloudflare Email — sends codes &amp; resets</div>
        </div>
        <label class="switch"><input type="checkbox" id="email-on"><span class="track"></span></label>
      </div>
      <div class="email-fields" id="email-fields" hidden>
        <div class="grp grp-t18">
          <label class="fl" for="mailfrom">From address</label>
          <input type="email" id="mailfrom" autocapitalize="none" spellcheck="false" data-rule="email" data-optional-group="email" placeholder="no-reply@example.com">
          <span class="field-err"></span>
        </div>
        <div class="grp">
          <label class="fl" for="cfacct">Cloudflare account ID</label>
          <input type="text" id="cfacct" autocapitalize="none" spellcheck="false" data-rule="text" data-optional-group="email" placeholder="32-character account ID">
          <span class="field-err"></span>
        </div>
        <div class="grp">
          <label class="fl" for="cftoken">API token</label>
          <input type="password" id="cftoken" autocomplete="off" data-rule="text" data-optional-group="email" placeholder="Stored sealed with your encryption key">
          <p class="hint">Encrypted at rest with your encryption key.</p>
          <span class="field-err"></span>
        </div>
      </div>
    </section>

    <section class="panel" data-panel="4">
      <h1>Review &amp; finish</h1>
      <p class="sub">One transaction — nothing is written until you confirm.</p>
      <div class="review" id="review"></div>
      <p class="outcome">Completing setup <b>creates your administrator</b>, seeds the role catalog, registers the account portal, then <b>locks this wizard</b> — <code>/setup</code> stops responding and sign-in goes live.</p>
    </section>

    <section class="panel" data-panel="5">
      <div class="done-badge"><svg width="28" height="28" viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="9" stroke="#065f46" stroke-width="2"/><path d="M8.5 12l2.5 2.5 4.5-4.5" stroke="#065f46" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg></div>
      <h1>Setup complete</h1>
      <p class="msg">DreamSSO is live and this wizard is now locked. You’re signed in as the superadmin — taking you to your settings&hellip;</p>
      <div class="nav"><button class="btn" id="go-admin">Go to settings</button></div>
    </section>

    <div class="nav" id="nav">
      <button class="btn-link" id="back" hidden>Back</button>
      <button class="btn-ghost" id="skip" hidden>Skip</button>
      <button class="btn" id="next">Continue</button>
    </div>
  </div>
  <div class="foot">
    <svg width="12" height="12" viewBox="0 0 24 24" fill="none"><rect x="5" y="11" width="14" height="9" rx="2" stroke="#9ca3af" stroke-width="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3" stroke="#9ca3af" stroke-width="2" stroke-linecap="round"/></svg>
    DreamSSO · first-run setup
  </div>
</div>

<script nonce="${nonce}">
(function(){
  var CHECK='<svg viewBox="0 0 24 24" fill="none"><path d="M20 6L9 17l-5-5" stroke="#065f46" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"/></svg>';
  var INFO='<svg viewBox="0 0 24 24" fill="none"><path d="M12 8h.01M11 12h1v4h1" stroke="#1a73e8" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><circle cx="12" cy="12" r="9" stroke="#1a73e8" stroke-width="1.6"/></svg>';
  document.querySelectorAll('[data-ok]').forEach(function(e){e.innerHTML=CHECK;});
  document.querySelectorAll('[data-info]').forEach(function(e){e.innerHTML=INFO;});

  var cur=0, LAST=4;
  var stepper=document.getElementById('stepper');
  var banner=document.getElementById('banner');
  var back=document.getElementById('back'), next=document.getElementById('next'), skip=document.getElementById('skip');
  function panels(){return document.querySelectorAll('.panel');}
  function panel(i){return document.querySelector('.panel[data-panel="'+i+'"]');}

  // ---- validation ----
  var EMAIL=/^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  var UNAME=/^[A-Za-z0-9_-]{3,20}$/;
  function catCount(v){var c=0;if(/[A-Z]/.test(v))c++;if(/[a-z]/.test(v))c++;if(/[0-9]/.test(v))c++;if(/[^A-Za-z0-9]/.test(v))c++;return c;}
  function complexityOk(v){return v.length>=8 && catCount(v)>=3;}
  function ruleMsg(inp){
    var v=(inp.value||'').trim();
    var rule=inp.getAttribute('data-rule');
    var required=inp.hasAttribute('data-required');
    var grp=inp.getAttribute('data-optional-group');
    if(grp==='email'){ if(!document.getElementById('email-on').checked) return ''; required=true; }
    if(!v) return required ? emptyMsg(inp) : '';
    if(rule==='email' && !EMAIL.test(v)) return 'Enter a valid email address.';
    if(rule==='username' && !UNAME.test(v)) return 'Usernames are 3-20 characters: letters, digits, - and _.';
    if(rule==='name' && v.length>100) return 'Display names are 1-100 characters.';
    if(rule==='url'||rule==='issuer'){ try{ var u=new URL(v); if(u.protocol!=='https:') return 'Use an https:// address.'; }catch(e){ return rule==='issuer'?'Enter a full URL, e.g. https://sso.example.com':'Enter a full URL, e.g. https://account.example.com'; } }
    if(rule==='pg' && !/^postgres(ql)?:\/\/.+@?.+/.test(v)) return 'Must start with postgres:// and include host and database.';
    if(rule==='redis' && !/^rediss?:\/\/.+/.test(v)) return 'Must start with redis:// (or rediss:// for TLS).';
    if(rule==='host' && !/^[a-z0-9.-]+$/i.test(v)) return 'A bare domain like example.com — no scheme, no port.';
    if(rule==='origins'){ var bad=v.split(',').some(function(o){o=o.trim();if(!o)return false;try{return new URL(o).protocol!=='https:';}catch(e){return true;}}); if(bad) return 'Comma-separated https origins.'; }
    if(rule==='password'){ if(v.length<8) return 'Password must be at least 8 characters long.'; if(!complexityOk(v)) return 'Must include at least 3 of: uppercase, lowercase, digits, special characters.'; }
    if(rule==='match'){ var other=document.getElementById(inp.getAttribute('data-match')); if(v!==(other.value||'').trim()) return "Passwords don't match."; }
    return '';
  }
  function emptyMsg(inp){
    return ({username:'Choose a username.',name:'Enter a display name.',email:'Enter an email address.',password:'Create a password.',
      match:'Re-enter your password.',url:'Enter the portal URL.',issuer:'Enter the issuer URL.',pg:'Enter the database URL.',
      redis:'Enter the Redis URL.',text:'This field is required.'})[inp.getAttribute('data-rule')]||'This field is required.';
  }
  function setBad(inp,msg){ var g=inp.closest('.grp'); g.classList.add('bad'); var s=g.querySelector('.field-err'); if(s) s.textContent=msg; }
  function clearBad(inp){ inp.closest('.grp').classList.remove('bad'); }

  // Installer-only: flag on BLUR (click-out), clear on ANY edit.
  document.querySelectorAll('input[data-rule]').forEach(function(inp){
    inp.addEventListener('blur',function(){ var m=ruleMsg(inp); if(m) setBad(inp,m); });
    inp.addEventListener('input',function(){ if(inp.id==='username'||inp.id==='confirm'){inp.value=inp.value.replace(/\s/g,'');} clearBad(inp); });
  });
  function validatePanel(i){
    var ok=true, first=null;
    panel(i).querySelectorAll('input[data-rule]').forEach(function(inp){
      var m=ruleMsg(inp);
      if(m){ setBad(inp,m); ok=false; if(!first) first=inp; }
    });
    if(first) first.focus();
    return ok;
  }

  // live password requirements
  var pw=document.getElementById('password');
  function setRule(k,state){
    var li=document.querySelector('.pwrule[data-k="'+k+'"]'); if(!li) return;
    li.className='pwrule'+(state?' '+state:'');
    li.querySelector('.pwrule-ico').textContent=state==='pass'?'✓':state==='fail'?'✗':'•';
  }
  pw.addEventListener('input',function(){
    var v=pw.value, has=v.length>0;
    setRule('length', has?(v.length>=8?'pass':'fail'):'');
    setRule('complexity', has?(catCount(v)>=3?'pass':'fail'):'');
  });

  // reveal toggles
  document.querySelectorAll('.reveal').forEach(function(b){
    b.addEventListener('click',function(){
      var t=document.getElementById(b.getAttribute('data-reveal'));
      var show=t.type==='password'; t.type=show?'text':'password'; b.textContent=show?'Hide':'Show';
    });
  });

  // email switch
  var emailOn=document.getElementById('email-on'), emailFields=document.getElementById('email-fields');
  emailOn.addEventListener('change',function(){
    emailFields.hidden=!emailOn.checked;
    if(!emailOn.checked) emailFields.querySelectorAll('.grp').forEach(function(g){g.classList.remove('bad');});
  });

  // ---- helpers ----
  function val(id){return (document.getElementById(id).value||'').trim();}
  function raw(id){return document.getElementById(id).value||'';}
  function esc(s){return String(s).replace(/[&<>"]/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});}
  function setText(id,t){var e=document.getElementById(id); if(e) e.textContent=t;}
  function showBanner(msg){ banner.textContent=msg; banner.classList.add('on'); }
  function maskPw(u){ try{ var url=new URL(u); if(url.password) url.password='****'; return url.toString(); }catch(e){ return u; } }
  function postJSON(url,body){ return fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body),credentials:'same-origin'}); }

  // ---- review ----
  function buildReview(){
    var rows=[
      ['Administrator', val('displayname')||'—'],
      ['Username', val('username')||'—'],
      ['Email', val('email')||'—'],
      ['Password', Array(13).join('•')],
      ['Site name', val('sitename')||'—'],
      ['Account portal', val('portal')||'—'],
      ['Outbound email', emailOn.checked ? (val('mailfrom')||'configured') : 'Skipped']
    ];
    document.getElementById('review').innerHTML=rows.map(function(r){
      var muted=(r[1]==='—'||r[1]==='Skipped')?' muted':'';
      return '<div class="rrow"><span class="k">'+r[0]+'</span><span class="v'+muted+'">'+esc(r[1])+'</span></div>';
    }).join('');
  }

  // ---- navigation ----
  function render(){
    panels().forEach(function(p){p.classList.remove('on');});
    var showSuccess = cur>LAST;
    panel(showSuccess?5:cur).classList.add('on');
    document.getElementById('nav').style.display = showSuccess?'none':'flex';
    stepper.querySelectorAll('.step').forEach(function(s){
      var i=+s.getAttribute('data-i');
      s.classList.remove('active','done');
      if(showSuccess||i<cur) s.classList.add('done');
      else if(i===cur) s.classList.add('active');
      var dot=s.querySelector('.dot');
      dot.innerHTML=(showSuccess||i<cur)?'<svg viewBox="0 0 24 24" fill="none"><path d="M20 6L9 17l-5-5" stroke="#fff" stroke-width="2.8" stroke-linecap="round" stroke-linejoin="round"/></svg>':(i+1);
    });
    if(showSuccess) return;
    back.hidden = cur===0;
    skip.hidden = cur!==3;
    if(cur===0){ renderStep1(); }
    else { next.disabled=false; next.textContent = cur===LAST ? 'Complete setup' : 'Continue'; }
    if(cur===LAST) buildReview();
    banner.classList.remove('on');
    var f=panel(cur).querySelector('input'); if(f && cur!==0) setTimeout(function(){f.focus();},50);
  }
  function advance(){
    if(cur===0){
      if(!envVerified){ if(!step1Valid()){ validatePanel(0); return; } saveEnv(); return; }
      cur++; render(); return;
    }
    if(!validatePanel(cur)) return;
    if(cur===LAST){ doFinish(); return; }
    cur++; render();
  }

  // ---- step 1: server configuration (.env) ----
  var envVerified=false;
  var envForm=document.getElementById('env-form'), envReady=document.getElementById('env-ready');
  var envNote=document.getElementById('env-note'), keyInp=document.getElementById('enckey'), keyPill=document.getElementById('key-pill');
  function lockField(id,v){var el=document.getElementById(id);el.value=v||'';el.readOnly=true;var g=el.closest('.grp');g.classList.remove('bad');var lbl=g.querySelector('label');if(lbl&&!lbl.querySelector('.from-env')){var t=document.createElement('span');t.className='from-env';t.textContent='✓ from .env';lbl.appendChild(t);}}
  function openField(id,v){var el=document.getElementById(id);el.value=v||'';el.readOnly=false;var g=el.closest('.grp');g.classList.remove('bad');var t=g.querySelector('.from-env');if(t)t.remove();}
  function setField(id,f,dflt){ if(f && f.present) lockField(id,f.value); else openField(id,dflt); }
  function step1Valid(){
    if(envVerified) return true;
    var ok=true;
    envForm.querySelectorAll('input[data-required]').forEach(function(inp){ if(!inp.readOnly && ruleMsg(inp)) ok=false; });
    envForm.querySelectorAll('input[data-rule=host],input[data-rule=origins]').forEach(function(inp){ if(!inp.readOnly && inp.value.trim() && ruleMsg(inp)) ok=false; });
    return ok;
  }
  function renderStep1(){
    envForm.hidden=envVerified; envReady.hidden=!envVerified;
    if(envVerified){ next.disabled=false; next.textContent='Looks good — continue'; }
    else { next.textContent='Save configuration'; next.disabled=!step1Valid(); }
  }
  function fillReady(v){
    setText('rv-db',(v.database||'(from .env)')+' · schema applied');
    setText('rv-redis',(v.redis||'(from .env)')+' · reachable');
    setText('rv-issuer',v.issuer||'(from .env)');
    setText('rv-passkeys', v.rpId ? 'WEBAUTHN_RP_ID = '+v.rpId : 'Not configured — you can enable passkeys later');
  }
  function readyFromForm(){ return { database: maskPw(val('dburl')), redis: val('redisurl'), issuer: val('issuer'), rpId: val('rpid') }; }
  function configPayload(){
    var o={};
    [['dburl','databaseUrl'],['redisurl','redisUrl'],['issuer','issuer'],['rpid','rpId'],['origins','origins']].forEach(function(p){
      var el=document.getElementById(p[0]); if(!el.readOnly) o[p[1]]=el.value.trim();
    });
    return o;
  }
  function paintConfigErrors(errors){
    var map={database:'dburl',redis:'redisurl',issuer:'issuer',rpId:'rpid',origins:'origins'};
    var first=null;
    Object.keys(errors).forEach(function(k){ var id=map[k]; if(id){ var el=document.getElementById(id); if(el){ setBad(el,errors[k]); if(!first)first=el; } } });
    if(first) first.focus();
  }
  function saveEnv(){
    next.disabled=true; next.textContent='Saving & testing…';
    postJSON('/setup/config',configPayload()).then(function(res){
      if(res.status===204){ envVerified=true; fillReady(readyFromForm()); renderStep1(); return; }
      return res.json().then(function(d){ paintConfigErrors(d.errors||{}); next.disabled=false; next.textContent='Save configuration'; });
    }).catch(function(){ showBanner('Could not reach the server — please try again.'); next.disabled=false; next.textContent='Save configuration'; });
  }
  function hideKeyTools(){ var c=document.getElementById('key-copy'); if(c)c.style.display='none'; var h=document.getElementById('key-hint'); if(h)h.style.display='none'; }
  function loadEnv(){
    fetch('/setup/env',{credentials:'same-origin'}).then(function(r){return r.json();}).then(function(d){
      if(d.configured){
        envVerified=true;
        var f=d.fields||{};
        fillReady({ database:(f.database&&f.database.value)||'', redis:(f.redis&&f.redis.value)||'', issuer:(f.issuer&&f.issuer.value)||'', rpId:(f.rpId&&f.rpId.value)||'' });
        renderStep1(); render(); return;
      }
      if(d.hasKey){ keyInp.value='present — kept from .env'; keyPill.textContent='from .env'; hideKeyTools(); }
      else { keyInp.value=d.generatedKey||''; keyPill.textContent='generated'; }
      var f=d.fields||{};
      setField('dburl',f.database,''); setField('redisurl',f.redis,'redis://127.0.0.1:6379'); setField('issuer',f.issuer,'');
      setField('rpid',f.rpId,''); setField('origins',f.origins,'');
      var partial = (f.database&&f.database.present) || (f.issuer&&f.issuer.present) || d.hasKey;
      envNote.className='note';
      envNote.innerHTML = partial ? 'Found <code>.env</code> — fill in anything still missing.' : 'No <code>.env</code> found — the wizard will create one.';
      renderStep1(); render();
    }).catch(function(){ envNote.className='note warn'; envNote.textContent='Could not load setup state — reload the page.'; });
  }
  function regen(){ fetch('/setup/env?regen=1',{credentials:'same-origin'}).then(function(r){return r.json();}).then(function(d){ if(d.generatedKey) keyInp.value=d.generatedKey; }); }

  // ---- finish ----
  function doFinish(){
    next.disabled=true; next.textContent='Setting up…';
    var body={ username:val('username'), displayName:val('displayname'), email:val('email'), password:raw('password'),
      siteName:val('sitename'), accountPortalUrl:val('portal'),
      emailEnabled:emailOn.checked, mailFrom:val('mailfrom'), cfAccountId:val('cfacct'), cfApiToken:raw('cftoken') };
    postJSON('/setup/finish',body).then(function(res){
      if(res.status===204){ cur=5; render(); setTimeout(function(){ location.href='/admin/settings'; },1400); return; }
      return res.json().then(function(d){ finishErrors(d.errors||{}); });
    }).catch(function(){ showBanner('Something went wrong — please try again.'); next.disabled=false; next.textContent='Complete setup'; });
  }
  function finishErrors(errors){
    var map={username:[1,'username'],displayName:[1,'displayname'],email:[1,'email'],password:[1,'password'],
      siteName:[2,'sitename'],accountPortalUrl:[2,'portal'],mailFrom:[3,'mailfrom'],cfAccountId:[3,'cfacct'],cfApiToken:[3,'cftoken']};
    var firstStep=99, firstEl=null, n=0;
    Object.keys(errors).forEach(function(k){ var m=map[k]; if(m){ var el=document.getElementById(m[1]); if(el){ setBad(el,errors[k]); n++; if(m[0]<firstStep){firstStep=m[0];firstEl=el;} } } });
    next.disabled=false; next.textContent='Complete setup';
    if(firstStep<99){ cur=firstStep; render(); showBanner('Please fix the highlighted field'+(n>1?'s':'')+'.'); if(firstEl) setTimeout(function(){firstEl.focus();},80); }
    else { showBanner('Setup failed — please try again.'); }
  }

  // ---- wire ----
  next.addEventListener('click',advance);
  back.addEventListener('click',function(){ if(cur>0){cur--; render();} });
  skip.addEventListener('click',function(){ emailOn.checked=false; emailFields.hidden=true; cur++; render(); });
  document.getElementById('go-admin').addEventListener('click',function(){ location.href='/admin'; });
  envForm.addEventListener('input',renderStep1);
  document.getElementById('key-copy').addEventListener('click',function(){var b=this;try{navigator.clipboard&&navigator.clipboard.writeText(keyInp.value);}catch(e){} b.textContent='Copied';setTimeout(function(){b.textContent='Copy';},1400);});
  document.getElementById('key-regen').addEventListener('click',regen);

  // Non-blocking portal reachability probe (Site step): warns if the portal isn't
  // online/serving its key yet, but never blocks (the BFF may come up later).
  var portalEl=document.getElementById('portal'), portalProbe=document.getElementById('portal-probe');
  function probePortal(){
    var v=portalEl.value.trim();
    if(!v || ruleMsg(portalEl)){ portalProbe.hidden=true; return; }
    portalProbe.hidden=false; portalProbe.className='probe checking'; portalProbe.innerHTML='<span class="pd"></span>Checking the portal…';
    fetch('/setup/probe-portal?url='+encodeURIComponent(v),{credentials:'same-origin'}).then(function(r){return r.json();}).then(function(d){
      var cls,msg;
      if(d.ok){ cls='ok'; msg='Portal reachable — its key endpoint is serving.'; }
      else if(d.reachable){ cls='warn'; msg='Reached the portal, but /.well-known/jwks.json isn’t serving keys yet.'; }
      else { cls='warn'; msg='Couldn’t reach the portal yet — fine if you’ll start it later; sign-in through the portal needs it online.'; }
      portalProbe.className='probe '+cls; portalProbe.innerHTML='<span class="pd"></span>'+msg;
    }).catch(function(){ portalProbe.hidden=true; });
  }
  portalEl.addEventListener('blur',probePortal);
  portalEl.addEventListener('input',function(){ portalProbe.hidden=true; });

  render();   // paint the shell immediately
  loadEnv();  // then populate step 1 from the server
})();
</script>
</body></html>`;
}
