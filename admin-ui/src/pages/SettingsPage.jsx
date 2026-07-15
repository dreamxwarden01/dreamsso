import { useEffect, useState } from 'react';
import { useOutletContext } from 'react-router-dom';
import { getSettings, updateSettings, sendTestEmail, generateGateKey, rotatePortalClientKey } from '../api.js';
import { normalizeHostname } from '../../../src/clientNormalize.ts';
import MtlsCard from '../MtlsCard.jsx';

function Field({ label, note, error, children }) {
  return (
    <label className="field">
      <span>
        {label} {note && <span className="note">({note})</span>}
      </span>
      {children}
      {error && <span className="ferr">{error}</span>}
    </label>
  );
}

// Per-field skeleton: an input-shaped shimmer bar (loading happens per entry
// field, not as one whole-card block).
const SkelInput = ({ width }) => (
  <div className="skel" style={{ height: 38, borderRadius: 9, ...(width ? { maxWidth: width } : {}) }} />
);

function Row({ label, value, loading }) {
  return (
    <div className="row">
      <p className="k" style={{ fontSize: 13 }}>{label}</p>
      {loading ? (
        <div className="skel" style={{ height: 16, width: 180, borderRadius: 6 }} />
      ) : (
        <p className="row-title mono" style={{ margin: 0, fontSize: 13 }}>{value}</p>
      )}
    </div>
  );
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const IDLE_MAX = 2160; // 90 days
const ABS_MAX = 8760; // 1 year

// Split a stored portal URL into the protocol select + bare hostname box.
function splitPortal(url) {
  try {
    const u = new URL(url);
    return { proto: u.protocol === 'http:' ? 'http' : 'https', host: u.hostname };
  } catch {
    return { proto: 'https', host: url || '' };
  }
}

export default function SettingsPage() {
  const { refreshSite } = useOutletContext();
  const [s, setS] = useState(null); // server snapshot
  const [f, setF] = useState(null); // form values
  const [errs, setErrs] = useState({});
  const [loadErr, setLoadErr] = useState(false);
  // per-card save state — each card owns its Save button
  const [siteBusy, setSiteBusy] = useState(false);
  const [siteErr, setSiteErr] = useState(null);
  const [secBusy, setSecBusy] = useState(false);
  const [secErr, setSecErr] = useState(null);
  const [emailBusy, setEmailBusy] = useState(false);
  const [emailErr, setEmailErr] = useState(null);
  const [tsBusy, setTsBusy] = useState(false);
  const [tsErr, setTsErr] = useState(null);
  const [regBusy, setRegBusy] = useState(false);
  const [regErr, setRegErr] = useState(null);
  // gate signing key: generation result shown ONCE (never persisted)
  const [gateBusy, setGateBusy] = useState(false);
  const [gateErr, setGateErr] = useState(null);
  const [gateNew, setGateNew] = useState(null); // { private_jwk, kid, created_at }
  const [gateCopied, setGateCopied] = useState(false);
  // test send
  const [testTo, setTestTo] = useState('');
  const [testState, setTestState] = useState(null);
  const [testBusy, setTestBusy] = useState(false);

  const load = () =>
    getSettings()
      .then((d) => {
        const portal = splitPortal(d.account_portal_url ?? '');
        setS(d);
        setF({
          site_name: d.site_name ?? '',
          portal_proto: portal.proto,
          portal_host: portal.host,
          session_idle_hours: d.session_idle_hours ?? '72',
          session_max_hours: d.session_max_hours ?? '168',
          session_transient_max_hours: d.session_transient_max_hours ?? '24',
          stepup_admin_required: d.stepup_admin_required ?? false,
          stepup_portal_required: d.stepup_portal_required ?? false,
          stepup_validity_minutes: d.stepup_validity_minutes ?? '30',
          mail_from: d.mail_from ?? '',
          cf_account_id: d.cf_account_id ?? '',
          cf_api_token: '', // write-only; blank = unchanged
          turnstile_site_key: d.turnstile_site_key ?? '',
          turnstile_secret_key: '', // write-only; blank = unchanged
          enable_registration: d.enable_registration ?? false,
          require_invitation_code: d.require_invitation_code ?? true,
        });
        setErrs({});
      })
      .catch((e) => {
        if (e.message !== 'unauthenticated') setLoadErr(true);
      });
  useEffect(() => {
    load();
  }, []);

  const loading = !f && !loadErr;
  const set = (patch) => setF((cur) => ({ ...cur, ...patch }));
  const setErr = (k, m) => setErrs((cur) => ({ ...cur, [k]: m || undefined }));

  const onHostChange = (raw) => {
    const m = /^(https?):\/\//i.exec(raw.trim());
    set(m ? { portal_proto: m[1].toLowerCase(), portal_host: raw } : { portal_host: raw });
    setErr('account_portal_url', null);
  };

  const blur = {
    site_name: () => setErr('site_name', f.site_name.trim() ? null : 'Required'),
    portal_host: () => {
      const r = normalizeHostname(f.portal_host);
      set({ portal_host: r.value });
      setErr('account_portal_url', r.error);
    },
    session_hours: () => {
      const num = (v, hi) => (/^\d{1,4}$/.test(v) && +v >= 1 && +v <= hi ? +v : null);
      const idle = num(f.session_idle_hours, IDLE_MAX);
      const max = num(f.session_max_hours, ABS_MAX);
      const trans = num(f.session_transient_max_hours, ABS_MAX);
      setErr('session_idle_hours', idle == null ? `Whole hours, 1–${IDLE_MAX}` : null);
      setErr('session_max_hours',
        max == null ? `Whole hours, 1–${ABS_MAX}`
        : idle != null && max < idle ? 'Can’t be smaller than the idle timeout' : null);
      setErr('session_transient_max_hours',
        trans == null ? `Whole hours, 1–${ABS_MAX}`
        : max != null && trans > max ? 'Can’t exceed the persistent maximum' : null);
    },
    stepup_minutes: () => {
      const v = f.stepup_validity_minutes;
      setErr('stepup_validity_minutes',
        /^\d{1,4}$/.test(v) && +v >= 1 && +v <= 1440 ? null : 'Whole minutes, 1–1440');
    },
    mail_from: () => {
      const v = f.mail_from.trim().replace(/\s+/g, '');
      set({ mail_from: v });
      setErr('mail_from', !v || EMAIL_RE.test(v) ? null : 'Must be a valid email address');
    },
    cf_account_id: () => {
      const v = f.cf_account_id.trim().replace(/\s+/g, '').toLowerCase();
      set({ cf_account_id: v });
      setErr('cf_account_id', !v || /^[0-9a-f]{32}$/.test(v) ? null : 'Must be a 32-char hex account ID');
    },
    turnstile_site_key: () => {
      const v = f.turnstile_site_key.trim().replace(/\s+/g, '');
      set({ turnstile_site_key: v });
      setErr('turnstile_site_key', !v || v.length <= 100 ? null : 'No spaces, max 100 chars');
    },
  };

  const portalUrl = f ? `${f.portal_proto}://${f.portal_host}` : '';
  const SITE_ERRS = ['site_name', 'account_portal_url', 'session_idle_hours', 'session_max_hours', 'session_transient_max_hours'];
  const EMAIL_ERRS = ['mail_from', 'cf_account_id', 'cf_api_token'];
  const TS_ERRS = ['turnstile_site_key', 'turnstile_secret_key'];
  const hasErr = (keys) => keys.some((k) => errs[k]);

  const siteDirty =
    f && s &&
    (f.site_name !== (s.site_name ?? '') ||
      portalUrl !== (s.account_portal_url ?? '') ||
      f.session_idle_hours !== (s.session_idle_hours ?? '72') ||
      f.session_max_hours !== (s.session_max_hours ?? '168') ||
      f.session_transient_max_hours !== (s.session_transient_max_hours ?? '24'));
  const emailDirty =
    f && s &&
    (f.mail_from !== (s.mail_from ?? '') ||
      f.cf_account_id !== (s.cf_account_id ?? '') ||
      f.cf_api_token !== '');
  const secDirty =
    f && s &&
    (f.stepup_admin_required !== (s.stepup_admin_required ?? false) ||
      f.stepup_portal_required !== (s.stepup_portal_required ?? false) ||
      f.stepup_validity_minutes !== (s.stepup_validity_minutes ?? '30'));
  const tsDirty =
    f && s &&
    (f.turnstile_site_key !== (s.turnstile_site_key ?? '') ||
      f.turnstile_secret_key !== '');
  const regDirty =
    f && s &&
    (f.enable_registration !== (s.enable_registration ?? false) ||
      f.require_invitation_code !== (s.require_invitation_code ?? true));
  const canSaveSite = !siteBusy && siteDirty && !hasErr(SITE_ERRS) && f?.site_name.trim();
  const canSaveEmail = !emailBusy && emailDirty && !hasErr(EMAIL_ERRS);
  const canSaveSec = !secBusy && secDirty && !errs.stepup_validity_minutes;
  const canSaveTs = !tsBusy && tsDirty && !hasErr(TS_ERRS);
  const canSaveReg = !regBusy && regDirty;

  // Each card PUTs only its own changed fields.
  const saveSite = async () => {
    setSiteBusy(true);
    setSiteErr(null);
    try {
      const body = {};
      if (f.site_name !== (s.site_name ?? '')) body.site_name = f.site_name;
      if (portalUrl !== (s.account_portal_url ?? '')) body.account_portal_url = portalUrl;
      if (f.session_idle_hours !== (s.session_idle_hours ?? '72')) body.session_idle_hours = f.session_idle_hours;
      if (f.session_max_hours !== (s.session_max_hours ?? '168')) body.session_max_hours = f.session_max_hours;
      if (f.session_transient_max_hours !== (s.session_transient_max_hours ?? '24'))
        body.session_transient_max_hours = f.session_transient_max_hours;
      await updateSettings(body);
      await load();
      refreshSite(); // reflect a renamed site in the header/tab title immediately
    } catch (e) {
      if (e.message === 'unauthenticated') return;
      if (e.status === 422 && e.data?.errors) setErrs((cur) => ({ ...cur, ...e.data.errors }));
      else setSiteErr(`Couldn't save. [${e.data?.error || 'http_' + e.status}]`);
    } finally {
      setSiteBusy(false);
    }
  };

  const saveEmail = async () => {
    setEmailBusy(true);
    setEmailErr(null);
    try {
      const body = {};
      if (f.mail_from !== (s.mail_from ?? '')) body.mail_from = f.mail_from;
      if (f.cf_account_id !== (s.cf_account_id ?? '')) body.cf_account_id = f.cf_account_id;
      if (f.cf_api_token !== '') body.cf_api_token = f.cf_api_token;
      await updateSettings(body);
      await load();
    } catch (e) {
      if (e.message === 'unauthenticated') return;
      if (e.status === 422 && e.data?.errors) setErrs((cur) => ({ ...cur, ...e.data.errors }));
      else setEmailErr(`Couldn't save. [${e.data?.error || 'http_' + e.status}]`);
    } finally {
      setEmailBusy(false);
    }
  };

  const saveSec = async () => {
    setSecBusy(true);
    setSecErr(null);
    try {
      const body = {};
      if (f.stepup_admin_required !== (s.stepup_admin_required ?? false)) body.stepup_admin_required = f.stepup_admin_required;
      if (f.stepup_portal_required !== (s.stepup_portal_required ?? false)) body.stepup_portal_required = f.stepup_portal_required;
      if (f.stepup_validity_minutes !== (s.stepup_validity_minutes ?? '30')) body.stepup_validity_minutes = f.stepup_validity_minutes;
      await updateSettings(body);
      await load();
    } catch (e) {
      if (e.message === 'unauthenticated') return;
      if (e.status === 422 && e.data?.errors) setErrs((cur) => ({ ...cur, ...e.data.errors }));
      else setSecErr(`Couldn't save. [${e.data?.error || 'http_' + e.status}]`);
    } finally {
      setSecBusy(false);
    }
  };

  const saveTs = async () => {
    setTsBusy(true);
    setTsErr(null);
    try {
      const body = {};
      if (f.turnstile_site_key !== (s.turnstile_site_key ?? '')) body.turnstile_site_key = f.turnstile_site_key;
      if (f.turnstile_secret_key !== '') body.turnstile_secret_key = f.turnstile_secret_key;
      await updateSettings(body);
      await load();
    } catch (e) {
      if (e.message === 'unauthenticated') return;
      if (e.status === 422 && e.data?.errors) setErrs((cur) => ({ ...cur, ...e.data.errors }));
      else setTsErr(`Couldn't save. [${e.data?.error || 'http_' + e.status}]`);
    } finally {
      setTsBusy(false);
    }
  };

  const saveReg = async () => {
    setRegBusy(true);
    setRegErr(null);
    try {
      const body = {};
      if (f.enable_registration !== (s.enable_registration ?? false)) body.enable_registration = f.enable_registration;
      if (f.require_invitation_code !== (s.require_invitation_code ?? true)) body.require_invitation_code = f.require_invitation_code;
      await updateSettings(body);
      await load();
    } catch (e) {
      if (e.message === 'unauthenticated') return;
      if (e.status === 422 && e.data?.errors) setErrs((cur) => ({ ...cur, ...e.data.errors }));
      else setRegErr(`Couldn't save. [${e.data?.error || 'http_' + e.status}]`);
    } finally {
      setRegBusy(false);
    }
  };

  const runGenerateGateKey = async () => {
    setGateBusy(true);
    setGateErr(null);
    setGateCopied(false);
    try {
      setGateNew(await generateGateKey());
      await load();
    } catch (e) {
      if (e.message === 'unauthenticated') return;
      setGateErr(`Couldn't generate. [${e.data?.error || 'http_' + e.status}]`);
    } finally {
      setGateBusy(false);
    }
  };

  // Portal client key: relayed to the portal's BFF (the key is RP-owned).
  const [acctKey, setAcctKey] = useState(null); // {kid, rotated_at} after a rotate this session
  const [acctKeyBusy, setAcctKeyBusy] = useState(false);
  const [acctKeyErr, setAcctKeyErr] = useState(null);
  const runRotateAcctKey = async () => {
    setAcctKeyBusy(true);
    setAcctKeyErr(null);
    try {
      setAcctKey(await rotatePortalClientKey());
    } catch (e) {
      if (e.message === 'unauthenticated') return;
      setAcctKeyErr(`Couldn't rotate. [${e.data?.error || 'http_' + e.status}]`);
    } finally {
      setAcctKeyBusy(false);
    }
  };
  const copyGateKey = async () => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(gateNew.private_jwk));
      setGateCopied(true);
    } catch {
      setGateErr('Clipboard blocked — select and copy the JSON manually.');
    }
  };

  const runTest = async () => {
    setTestBusy(true);
    setTestState(null);
    try {
      await sendTestEmail(testTo.trim());
      setTestState({ ok: true, msg: `Test email sent to ${testTo.trim()}.` });
    } catch (e) {
      if (e.message === 'unauthenticated') return;
      const code = e.data?.errors?.to || e.data?.error || 'http_' + e.status;
      setTestState({ ok: false, msg: `Send failed. [${code}]${e.data?.detail ? ' ' + e.data.detail : ''}` });
    } finally {
      setTestBusy(false);
    }
  };

  if (loadErr) {
    return (
      <>
        <h1>Settings</h1>
        <p className="err">Couldn't load settings.</p>
      </>
    );
  }

  return (
    <>
      <h1>Settings</h1>
      <p className="sub">The SSO's site identity, sessions, and outbound email configuration.</p>

      <p className="section">Site</p>
      <div className="card pad">
        <div className="form">
          <div className="grid2">
            <Field label="Site name" note="email titles, page branding" error={errs.site_name}>
              {loading ? (
                <SkelInput />
              ) : (
                <input
                  className={'input' + (errs.site_name ? ' bad' : '')}
                  value={f.site_name}
                  onChange={(e) => { set({ site_name: e.target.value }); setErr('site_name', null); }}
                  onBlur={blur.site_name}
                />
              )}
            </Field>
            <Field label="Account portal" note="links in emails, GET / redirect" error={errs.account_portal_url}>
              {loading ? (
                <SkelInput />
              ) : (
                <div style={{ display: 'flex', gap: 0 }}>
                  <select
                    className="input"
                    style={{ width: 92, flexShrink: 0, borderRadius: '9px 0 0 9px' }}
                    value={f.portal_proto}
                    onChange={(e) => set({ portal_proto: e.target.value })}
                  >
                    <option value="https">https://</option>
                    <option value="http">http://</option>
                  </select>
                  <input
                    className={'input mono' + (errs.account_portal_url ? ' bad' : '')}
                    style={{ borderRadius: '0 9px 9px 0', borderLeft: 'none' }}
                    value={f.portal_host}
                    placeholder="account.example.com"
                    onChange={(e) => onHostChange(e.target.value)}
                    onBlur={blur.portal_host}
                  />
                </div>
              )}
            </Field>
          </div>
          <div className="grid2">
            <Field label="Session idle timeout (hours)" note="signed out after this much inactivity" error={errs.session_idle_hours}>
              {loading ? (
                <SkelInput width={120} />
              ) : (
                <input
                  className={'input' + (errs.session_idle_hours ? ' bad' : '')}
                  inputMode="numeric"
                  style={{ maxWidth: 120 }}
                  value={f.session_idle_hours}
                  onChange={(e) => {
                    set({ session_idle_hours: e.target.value.replace(/\D/g, '') });
                    setErr('session_idle_hours', null);
                  }}
                  onBlur={blur.session_hours}
                />
              )}
            </Field>
            <Field label="Session maximum (hours)" note="absolute cap for 'stay signed in' sessions" error={errs.session_max_hours}>
              {loading ? (
                <SkelInput width={120} />
              ) : (
                <input
                  className={'input' + (errs.session_max_hours ? ' bad' : '')}
                  inputMode="numeric"
                  style={{ maxWidth: 120 }}
                  value={f.session_max_hours}
                  onChange={(e) => {
                    set({ session_max_hours: e.target.value.replace(/\D/g, '') });
                    setErr('session_max_hours', null);
                  }}
                  onBlur={blur.session_hours}
                />
              )}
            </Field>
            <Field
              label="Transient session maximum (hours)"
              note="sessions that answered No to 'Stay signed in?'"
              error={errs.session_transient_max_hours}
            >
              {loading ? (
                <SkelInput width={120} />
              ) : (
                <input
                  className={'input' + (errs.session_transient_max_hours ? ' bad' : '')}
                  inputMode="numeric"
                  style={{ maxWidth: 120 }}
                  value={f.session_transient_max_hours}
                  onChange={(e) => {
                    set({ session_transient_max_hours: e.target.value.replace(/\D/g, '') });
                    setErr('session_transient_max_hours', null);
                  }}
                  onBlur={blur.session_hours}
                />
              )}
            </Field>
          </div>
          {siteErr && <p className="err">{siteErr}</p>}
          <div className="form-actions">
            <button className="btn btn-primary" onClick={saveSite} disabled={loading || !canSaveSite}>
              {siteBusy ? 'Saving…' : 'Save changes'}
            </button>
            {!loading && !siteDirty && <span className="dirty-note">No unsaved changes</span>}
          </div>
        </div>
      </div>

      <p className="section">Step-up verification</p>
      <div className="card pad">
        <div className="form">
          {loading ? (
            <>
              <SkelInput width={340} />
              <SkelInput width={120} />
            </>
          ) : (
            <>
              <div className="checks" style={{ flexDirection: 'column', alignItems: 'flex-start', gap: 8 }}>
                <label>
                  <input
                    type="checkbox"
                    checked={f.stepup_admin_required}
                    onChange={(e) => set({ stepup_admin_required: e.target.checked })}
                  />
                  Require verification to enter this admin console
                </label>
                <label>
                  <input
                    type="checkbox"
                    checked={f.stepup_portal_required}
                    onChange={(e) => set({ stepup_portal_required: e.target.checked })}
                  />
                  Require verification for organization management in the account portal
                </label>
              </div>
              {(errs.stepup_admin_required || errs.stepup_portal_required) && (
                <p className="ferr" style={{ marginTop: 0 }}>
                  {errs.stepup_admin_required || errs.stepup_portal_required}
                </p>
              )}
              <Field
                label="Verification window (minutes)"
                note="a passkey/authenticator check stays valid this long; strong-factor logins pre-clear it"
                error={errs.stepup_validity_minutes}
              >
                <input
                  className={'input' + (errs.stepup_validity_minutes ? ' bad' : '')}
                  inputMode="numeric"
                  style={{ maxWidth: 120 }}
                  value={f.stepup_validity_minutes}
                  onChange={(e) => {
                    set({ stepup_validity_minutes: e.target.value.replace(/\D/g, '') });
                    setErr('stepup_validity_minutes', null);
                  }}
                  onBlur={blur.stepup_minutes}
                />
              </Field>
            </>
          )}
          {secErr && <p className="err">{secErr}</p>}
          <div className="form-actions">
            <button className="btn btn-primary" onClick={saveSec} disabled={loading || !canSaveSec}>
              {secBusy ? 'Saving…' : 'Save changes'}
            </button>
            {!loading && !secDirty && <span className="dirty-note">No unsaved changes</span>}
          </div>
        </div>
      </div>

      <p className="section">Registration</p>
      <div className="card pad">
        <div className="form">
          {loading ? (
            <SkelInput width={340} />
          ) : (
            <div className="checks" style={{ flexDirection: 'column', alignItems: 'flex-start', gap: 8 }}>
              <label>
                <input
                  type="checkbox" checked={f.enable_registration}
                  onChange={(e) => set({ enable_registration: e.target.checked })}
                />
                Allow new accounts to register (portal /register/start; adds a &ldquo;Create an account&rdquo; link to the sign-in page)
              </label>
              <label>
                <input
                  type="checkbox" checked={f.require_invitation_code}
                  onChange={(e) => set({ require_invitation_code: e.target.checked })}
                />
                Require an invitation code (codes are managed in the portal&rsquo;s Organization &rarr; Invitations)
              </label>
            </div>
          )}
          {regErr && <p className="err">{regErr}</p>}
          <div className="form-actions">
            <button className="btn btn-primary" onClick={saveReg} disabled={loading || !canSaveReg}>
              {regBusy ? 'Saving…' : 'Save changes'}
            </button>
            {!loading && !regDirty && <span className="dirty-note">No unsaved changes</span>}
          </div>
        </div>
      </div>

      <p className="section">Account portal</p>
      <div className="card pad">
        <div className="form">
          <p className="card-title">Turnstile</p>
          {loading ? (
            <>
              <SkelInput width={340} />
              <SkelInput />
            </>
          ) : (
            <>
              <p className="hint" style={{ margin: 0 }}>
                {s.turnstile_site_key && s.turnstile_secret_set
                  ? 'Active — password reset requires human verification. Clear the site key to turn it off.'
                  : 'Off — set both keys to require human verification for password reset. Registration will share this gate later.'}
              </p>
              <div className="grid2">
                <Field label="Site key" note="public — rendered into the widget; blank = gate off" error={errs.turnstile_site_key}>
                  <input
                    className={'input mono' + (errs.turnstile_site_key ? ' bad' : '')}
                    value={f.turnstile_site_key}
                    placeholder="0x4AAAAAAA…"
                    onChange={(e) => { set({ turnstile_site_key: e.target.value }); setErr('turnstile_site_key', null); }}
                    onBlur={blur.turnstile_site_key}
                  />
                </Field>
                <Field
                  label="Secret key"
                  note={s.turnstile_secret_set ? 'configured — enter a value to replace' : 'not configured'}
                  error={errs.turnstile_secret_key}
                >
                  <input
                    className="input mono"
                    type="password"
                    autoComplete="off"
                    value={f.turnstile_secret_key}
                    placeholder={s.turnstile_secret_set ? '••••••••••••' : 'paste the Turnstile secret key'}
                    onChange={(e) => set({ turnstile_secret_key: e.target.value.replace(/\s+/g, '') })}
                  />
                </Field>
              </div>
              <span className="hint">The secret is stored encrypted and never displayed again.</span>
            </>
          )}
          {tsErr && <p className="err">{tsErr}</p>}
          <div className="form-actions">
            <button className="btn btn-primary" onClick={saveTs} disabled={loading || !canSaveTs}>
              {tsBusy ? 'Saving…' : 'Save changes'}
            </button>
            {!loading && !tsDirty && <span className="dirty-note">No unsaved changes</span>}
          </div>
        </div>
      </div>

      <div className="card pad">
        <div className="form">
          <Field
            label="Portal client key"
            note={acctKey ? `current kid ${acctKey.kid}` : 'the key the portal signs its client assertions with'}
          >
            <div className="inline-row">
              <button className="btn" onClick={runRotateAcctKey} disabled={acctKeyBusy}>
                {acctKeyBusy ? 'Rotating…' : 'Rotate client key'}
              </button>
            </div>
          </Field>
          <span className="hint">
            One-click safe: the portal generates a fresh key, keeps the old one published for overlap,
            and the SSO picks the new one up from its JWKS automatically.
          </span>
          {acctKeyErr && <p className="err">{acctKeyErr}</p>}
        </div>
      </div>

      <div className="card pad">
        <div className="form">
          <Field
            label="Edge gate signing key"
            note={
              loading ? undefined
              : s.gate_key ? `active key ${s.gate_key.kid} · generated ${(s.gate_key.created_at || '').slice(0, 10)}`
              : 'not configured — the BFF accepts Turnstile tokens only'
            }
          >
            {loading ? (
              <SkelInput width={200} />
            ) : (
              <div className="inline-row">
                <button className="btn" onClick={runGenerateGateKey} disabled={gateBusy}>
                  {gateBusy ? 'Generating…' : s.gate_key ? 'Rotate key' : 'Generate key'}
                </button>
              </div>
            )}
          </Field>
          {!loading && !gateNew && (
            <span className="hint">
              Lets the turnstile-gate-sso worker verify Turnstile at the edge and sign what it forwards.
              Only the public key is stored; the private key is shown once after generating.
            </span>
          )}
          {gateNew && (
            <>
              <p className="hint" style={{ color: 'var(--warn-tx, #92400e)' }}>
                Copy this PRIVATE key now — it won&rsquo;t be shown again. Set it on the worker:
                {' '}<span className="mono">wrangler secret put GATE_SIGNING_KEY</span> (paste the JSON verbatim).
              </p>
              <div className="keybox">
                <span className="keytext">{JSON.stringify(gateNew.private_jwk)}</span>
                <button className="keycopy" onClick={copyGateKey} title="Copy">
                  {gateCopied ? '✓' : 'Copy'}
                </button>
              </div>
            </>
          )}
          {gateErr && <p className="err">{gateErr}</p>}
        </div>
      </div>

      <p className="section">Outbound email (Cloudflare)</p>
      <div className="card pad">
        <div className="form">
          <div className="grid2">
            <Field label="From address" note="on a domain verified for Email Sending" error={errs.mail_from}>
              {loading ? (
                <SkelInput />
              ) : (
                <input
                  className={'input mono' + (errs.mail_from ? ' bad' : '')}
                  value={f.mail_from}
                  placeholder="no-reply@dreamxwarden.ca"
                  onChange={(e) => { set({ mail_from: e.target.value }); setErr('mail_from', null); }}
                  onBlur={blur.mail_from}
                />
              )}
            </Field>
            <Field label="Cloudflare account ID" error={errs.cf_account_id}>
              {loading ? (
                <SkelInput />
              ) : (
                <input
                  className={'input mono' + (errs.cf_account_id ? ' bad' : '')}
                  value={f.cf_account_id}
                  onChange={(e) => { set({ cf_account_id: e.target.value }); setErr('cf_account_id', null); }}
                  onBlur={blur.cf_account_id}
                />
              )}
            </Field>
          </div>
          <Field
            label="API token"
            note={loading ? undefined : s.cf_token_set ? 'configured — enter a value to replace' : 'not configured'}
            error={errs.cf_api_token}
          >
            {loading ? (
              <SkelInput />
            ) : (
              <>
                <input
                  className="input mono"
                  type="password"
                  autoComplete="off"
                  value={f.cf_api_token}
                  placeholder={s.cf_token_set ? '••••••••••••' : 'paste the Email Sending API token'}
                  onChange={(e) => set({ cf_api_token: e.target.value.replace(/\s+/g, '') })}
                />
                <span className="hint">Stored encrypted (AES-256-GCM, key in the server environment). Never displayed again.</span>
              </>
            )}
          </Field>
          {emailErr && <p className="err">{emailErr}</p>}
          <div className="form-actions">
            <button className="btn btn-primary" onClick={saveEmail} disabled={loading || !canSaveEmail}>
              {emailBusy ? 'Saving…' : 'Save changes'}
            </button>
            {!loading && !emailDirty && <span className="dirty-note">No unsaved changes</span>}
          </div>
        </div>
      </div>

      <div className="card pad">
        <div className="form">
          <Field label="Send a test email">
            {loading ? (
              <SkelInput />
            ) : (
              <div className="inline-row">
                <input
                  className="input mono grow"
                  type="email"
                  value={testTo}
                  placeholder="you@example.com"
                  onChange={(e) => { setTestTo(e.target.value); setTestState(null); }}
                />
                <button className="btn" onClick={runTest} disabled={testBusy || !EMAIL_RE.test(testTo.trim())}>
                  {testBusy ? 'Sending…' : 'Send test'}
                </button>
              </div>
            )}
          </Field>
          {testState && (
            <p className={testState.ok ? 'hint' : 'err'} style={testState.ok ? { color: 'var(--ok-tx)' } : undefined}>
              {testState.msg}
            </p>
          )}
        </div>
      </div>

      <MtlsCard />

      <p className="section">Environment (view-only)</p>
      <div className="card">
        <Row label="Issuer" value={s?.issuer} loading={loading} />
        <Row label="Passkey RP ID" value={s?.webauthn_rp_id} loading={loading} />
        <Row label="Passkey origins" value={(s?.webauthn_origins || []).join(', ')} loading={loading} />
      </div>
    </>
  );
}
