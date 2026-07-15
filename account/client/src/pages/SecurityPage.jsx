import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { getSecurity, getStepupStatus, mfaEnable, mfaDisable } from '../api.js';
import { useAuth } from '../context/AuthContext.jsx';
import Icon from '../components/Icon.jsx';
import { Ph } from '../components/Skeleton.jsx';
import StepUpModal from '../components/StepUpModal.jsx';

export function fmtDate(iso) {
  if (!iso) return null;
  try {
    return new Date(iso).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
  } catch {
    return null;
  }
}

export default function SecurityPage() {
  const nav = useNavigate();
  const { can, reload } = useAuth();
  const [data, setData] = useState(null);
  const [err, setErr] = useState(false);
  const [toggling, setToggling] = useState(false);
  const [toggleErr, setToggleErr] = useState(null);
  // Flipping the MFA toggle demands a fresh sudo window (when a strong factor
  // exists); the solved challenge stamps stepup_at, so the window is reusable
  // across the portal afterwards.
  const [stepup, setStepup] = useState(null); // { status, retry }

  const load = () =>
    getSecurity()
      .then(setData)
      .catch((e) => {
        if (e.message !== 'unauthenticated') setErr(true);
      });
  useEffect(() => {
    reload(); // refresh effective permissions on entry
    load();
  }, [reload]);

  const toggleMfa = async (enable) => {
    setToggling(true);
    setToggleErr(null);
    try {
      await (enable ? mfaEnable() : mfaDisable());
      await load();
    } catch (e) {
      if (e.message === 'unauthenticated') return;
      if (e.code === 'step_up_required') {
        setStepup({ status: await getStepupStatus('fallback'), retry: () => toggleMfa(enable) });
        return;
      }
      setToggleErr(
        e.code === 'permission_denied'
          ? 'Your organization manages this setting.'
          : "Couldn't update. Please try again.",
      );
    } finally {
      setToggling(false);
    }
  };

  if (err) {
    return (
      <>
        <h1>Security</h1>
        <p className="err">Couldn't load your security settings.</p>
      </>
    );
  }
  // Loading: the page's structure is fully static (fixed rows, icons, titles,
  // controls) — render it all for real and shimmer only the value lines. The
  // sub-page links even work before data lands.
  if (!data) {
    return (
      <>
        <h1>Security</h1>
        <p className="sub">Password and multi-factor authentication.</p>

        <h2 className="section">Your password</h2>
        <div className="card">
          <div className="row">
            <div className="mfa-lhs">
              <span className="mfa-ico"><Icon name="password" size={20} /></span>
              <div className="row-main">
                <p className="mfa-title">Password</p>
                <p className="k"><Ph w={160} /></p>
              </div>
            </div>
            {can('profile.security.password.change') ? (
              <button className="btn" onClick={() => nav('/security/password')}>Change</button>
            ) : (
              <span className="locked"><Icon name="lock" size={14} />Managed by your organization</span>
            )}
          </div>
        </div>

        <h2 className="section">Multi-factor authentication</h2>
        <div className="card">
          <div className="row">
            <div className="mfa-lhs">
              <span className="mfa-ico"><Icon name="shield-check" size={20} /></span>
              <div className="row-main">
                <p className="mfa-title">Multi-factor authentication</p>
                <p className="k"><Ph w={280} /></p>
              </div>
            </div>
            <span className="skeleton" style={{ width: 40, height: 22, borderRadius: 99, flexShrink: 0 }} />
          </div>
          <div className="row">
            <div className="mfa-lhs">
              <span className="mfa-ico"><Icon name="mail" size={20} /></span>
              <div className="row-main">
                <p className="mfa-title">Primary email</p>
                <p className="k"><Ph w={180} /></p>
              </div>
            </div>
            <span className="locked">Recovery</span>
          </div>
          <button className="row row-link" onClick={() => nav('/security/authenticator')}>
            <div className="mfa-lhs">
              <span className="mfa-ico"><Icon name="qr" size={20} /></span>
              <div className="row-main">
                <p className="mfa-title">Authenticator apps</p>
                <p className="k"><Ph w={100} /></p>
              </div>
            </div>
            <Icon name="chevron" size={18} className="chev" />
          </button>
          <button className="row row-link" onClick={() => nav('/security/passkeys')}>
            <div className="mfa-lhs">
              <span className="mfa-ico"><Icon name="key" size={20} /></span>
              <div className="row-main">
                <p className="mfa-title">Passkeys and security keys</p>
                <p className="k"><Ph w={100} /></p>
              </div>
            </div>
            <Icon name="chevron" size={18} className="chev" />
          </button>
        </div>
      </>
    );
  }

  const { password, mfa } = data;
  const changed = fmtDate(password.changed_at);
  const authCount = mfa.authenticators.length;
  const pkCount = mfa.passkeys.length;

  return (
    <>
      <h1>Security</h1>
      <p className="sub">Password and multi-factor authentication.</p>

      <h2 className="section">Your password</h2>
      <div className="card">
        <div className="row">
          <div className="mfa-lhs">
            <span className="mfa-ico">
              <Icon name="password" size={20} />
            </span>
            <div className="row-main">
              <p className="mfa-title">Password</p>
              <p className="k">
                {password.is_set ? `Last changed ${changed || 'never'}` : 'Not set'}
              </p>
            </div>
          </div>
          {can('profile.security.password.change') ? (
            <button className="btn" onClick={() => nav('/security/password')}>
              Change
            </button>
          ) : (
            <span className="locked">
              <Icon name="lock" size={14} />
              Managed by your organization
            </span>
          )}
        </div>
      </div>

      <h2 className="section">Multi-factor authentication</h2>
      <div className="card">
        {/* The account toggle — login challenges only when ON. Turning it off is
            what the mfa.disable permission guards (privileged roles can't). */}
        <div className="row">
          <div className="mfa-lhs">
            <span className="mfa-ico">
              <Icon name="shield-check" size={20} />
            </span>
            <div className="row-main">
              <p className="mfa-title">Multi-factor authentication</p>
              <p className="k">
                {mfa.enabled
                  ? "On — you'll be asked for a second step when signing in"
                  : 'Off — sign in with your password only'}
              </p>
              {mfa.enabled && !can('profile.security.mfa.disable') && (
                <p className="switch-tip">
                  <Icon name="lock" size={12} />
                  Required by your organization — can't be turned off.
                </p>
              )}
              {toggleErr && <p className="err">{toggleErr}</p>}
            </div>
          </div>
          <label className="switch" title={mfa.enabled ? 'Turn off' : 'Turn on'}>
            <input
              type="checkbox"
              checked={mfa.enabled}
              disabled={toggling || (mfa.enabled && !can('profile.security.mfa.disable'))}
              onChange={(e) => toggleMfa(e.target.checked)}
            />
            <span className="slider" />
          </label>
        </div>

        {/* Primary email — display-only placeholder for now */}
        <div className="row">
          <div className="mfa-lhs">
            <span className="mfa-ico">
              <Icon name="mail" size={20} />
            </span>
            <div className="row-main">
              <p className="mfa-title">Primary email</p>
              <p className="k">{mfa.email.address || '—'}</p>
            </div>
          </div>
          <span className="locked">Recovery</span>
        </div>

        {/* Authenticator apps — opens settings */}
        <button className="row row-link" onClick={() => nav('/security/authenticator')}>
          <div className="mfa-lhs">
            <span className="mfa-ico">
              <Icon name="qr" size={20} />
            </span>
            <div className="row-main">
              <p className="mfa-title">Authenticator apps</p>
              <p className="k">{authCount ? `${authCount} configured` : 'Not set up'}</p>
            </div>
          </div>
          <Icon name="chevron" size={18} className="chev" />
        </button>

        {/* Passkeys — opens settings (stub this turn) */}
        <button className="row row-link" onClick={() => nav('/security/passkeys')}>
          <div className="mfa-lhs">
            <span className="mfa-ico">
              <Icon name="key" size={20} />
            </span>
            <div className="row-main">
              <p className="mfa-title">Passkeys and security keys</p>
              <p className="k">{pkCount ? `${pkCount} registered` : 'Not set up'}</p>
            </div>
          </div>
          <Icon name="chevron" size={18} className="chev" />
        </button>
      </div>

      {stepup && (
        <StepUpModal
          status={stepup.status}
          onSuccess={() => {
            const r = stepup.retry;
            setStepup(null);
            r?.();
          }}
          onCancel={() => setStepup(null)}
        />
      )}
    </>
  );
}
