import { useCallback, useEffect, useRef, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { startAuthentication, browserSupportsWebAuthn } from '@simplewebauthn/browser';
import AuthCard from '../components/AuthCard.jsx';
import Icon from '../components/Icon.jsx';
import PasswordRules, { passwordValid } from '../components/PasswordRules.jsx';
import { resetValidate, resetPasskeyOptions, resetConfirm } from '../api.js';

// Six-box OTP entry — the SSO challenge page's look, React-ified.
function OtpBoxes({ code, setCode, disabled, onComplete }) {
  const refs = useRef([]);
  const digits = Array.from({ length: 6 }, (_, i) => code[i] ?? '');

  const put = (next, focusIdx) => {
    const clean = next.replace(/\D/g, '').slice(0, 6);
    setCode(clean);
    if (focusIdx != null) refs.current[Math.min(focusIdx, 5)]?.focus();
    if (clean.length === 6) onComplete?.(clean);
  };

  return (
    <div className="auth-otp">
      {digits.map((d, i) => (
        <input
          key={i}
          ref={(el) => { refs.current[i] = el; }}
          inputMode="numeric"
          autoComplete={i === 0 ? 'one-time-code' : 'off'}
          maxLength={2}
          disabled={disabled}
          value={d}
          autoFocus={i === 0}
          onChange={(e) => {
            const typed = e.target.value.replace(/\D/g, '');
            if (!typed) return put(code.slice(0, i), i);
            const next = (code.slice(0, i) + typed[typed.length - 1] + code.slice(i + 1)).slice(0, 6);
            put(next, i + 1);
          }}
          onKeyDown={(e) => {
            if (e.key === 'Backspace' && !digits[i] && i > 0) {
              e.preventDefault();
              put(code.slice(0, i - 1), i - 1);
            }
          }}
          onPaste={(e) => {
            e.preventDefault();
            put(e.clipboardData.getData('text'), 5);
          }}
        />
      ))}
    </div>
  );
}

export default function ResetPage() {
  const [params] = useSearchParams();
  const token = params.get('token') || '';

  // 'loading' -> 'form' -> ('challenge') -> 'redirect' | 'invalid'
  const [phase, setPhase] = useState('loading');
  const [challenge, setChallenge] = useState(null); // { methods, label } | null
  const [invalidMsg, setInvalidMsg] = useState('This password reset link is invalid or has expired.');

  const [pw, setPw] = useState('');
  const [confirmPw, setConfirmPw] = useState('');
  // Blur-validation contract (same as /forgot): red border appears when an
  // invalid value loses focus, clears on the next change; the button is
  // greyed until everything is valid regardless.
  const [pwBad, setPwBad] = useState(false);
  const [cfErr, setCfErr] = useState(null);
  const [srvErr, setSrvErr] = useState(null); // server-side banner (weak_password etc.)
  const [busy, setBusy] = useState(false);

  const [method, setMethod] = useState(null); // 'passkey' | 'totp'
  const [code, setCode] = useState('');
  const [chErr, setChErr] = useState(null); // { msg, code }
  const ranOnce = useRef(false);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      if (!token) return setPhase('invalid');
      try {
        const d = await resetValidate(token);
        if (cancelled) return;
        if (!d?.valid) return setPhase('invalid');
        // Passkey-first smart default (no selector) — same as login + step-up.
        // WebAuthn-less browsers fall to totp when available.
        let methods = d.challenge?.methods ?? [];
        if (!browserSupportsWebAuthn()) methods = methods.filter((m) => m !== 'passkey');
        setChallenge(d.challenge ? { ...d.challenge, methods } : null);
        setMethod(methods[0] ?? null);
        setPhase('form');
      } catch {
        if (!cancelled) {
          setInvalidMsg("Couldn't check this reset link — try again in a moment.");
          setPhase('invalid');
        }
      }
    })();
    return () => { cancelled = true; };
  }, [token]);

  const finish = (data) => {
    setPhase('redirect');
    window.location.replace(data.complete_url);
  };

  const confirmFail = useCallback((err, fallbackMsg) => {
    if (err.status === 422 && err.code === 'invalid_token') {
      setPhase('invalid');
    } else if (err.status === 403 && err.code === 'too_many_attempts') {
      setInvalidMsg('Too many failed verification attempts — this link is no longer valid.');
      setPhase('invalid');
    } else if (err.status === 422 && err.code === 'weak_password') {
      setPhase('form');
      setPwBad(true);
      setSrvErr(err.data?.error_description || 'That password doesn’t meet the requirements.');
    } else {
      const left = err.data?.attempts_left;
      setChErr({
        msg: fallbackMsg + (left ? ` (${left} ${left === 1 ? 'attempt' : 'attempts'} left)` : ''),
        code: err.code || 'http_' + (err.status ?? 'network'),
      });
    }
  }, []);

  const runPasskey = useCallback(async () => {
    setChErr(null);
    setBusy(true);
    try {
      const options = await resetPasskeyOptions(token);
      let cred;
      try {
        cred = await startAuthentication({ optionsJSON: options });
      } catch (e) {
        setChErr({ msg: 'Verification was cancelled or didn’t complete.', code: e.name || 'passkey_error' });
        return;
      }
      finish(await resetConfirm({
        token, password: pw, method: 'passkey', credential: JSON.stringify(cred),
      }));
    } catch (err) {
      confirmFail(err, "Couldn't verify your passkey — try again.");
    } finally {
      setBusy(false);
    }
  }, [token, pw, confirmFail]);

  const submitTotp = async (theCode) => {
    const c = (theCode ?? code).trim();
    if (c.length !== 6 || busy) return;
    setChErr(null);
    setBusy(true);
    try {
      finish(await resetConfirm({ token, password: pw, method: 'totp', code: c }));
    } catch (err) {
      setCode('');
      confirmFail(err, 'That code is incorrect or expired — enter the current one.');
    } finally {
      setBusy(false);
    }
  };

  const pwOk = passwordValid(pw) && !/\s/.test(pw);
  const canSave = !busy && pwOk && confirmPw.length > 0 && confirmPw === pw;

  const submitPassword = async (e) => {
    e.preventDefault();
    if (!canSave) return;
    setPwBad(false);
    setCfErr(null);
    setSrvErr(null);

    if (challenge && challenge.methods.length > 0) {
      setPhase('challenge');
      // Passkey default auto-runs once (Microsoft-style) — the quiet link
      // switches to the authenticator code.
      if (method === 'passkey' && !ranOnce.current) {
        ranOnce.current = true;
        runPasskey();
      }
      return;
    }
    setBusy(true);
    try {
      finish(await resetConfirm({ token, password: pw }));
    } catch (err) {
      confirmFail(err, 'Something went wrong — try again.');
      setBusy(false);
    }
  };

  if (phase === 'loading') {
    return (
      <AuthCard docTitle="Reset password">
        <div className="auth-spinner" aria-hidden="true" />
        <p className="auth-wait">Checking your reset link…</p>
      </AuthCard>
    );
  }

  if (phase === 'invalid') {
    return (
      <AuthCard docTitle="Reset password" title="Link expired">
        <p className="auth-msg">{invalidMsg} Request a new one and try again.</p>
        <a
          className="auth-btn"
          style={{ display: 'block', textAlign: 'center', textDecoration: 'none', boxSizing: 'border-box', marginTop: 14 }}
          href="/forgot"
        >
          Request a new link
        </a>
      </AuthCard>
    );
  }

  if (phase === 'redirect') {
    return (
      <AuthCard docTitle="Reset password">
        <div className="auth-done">
          <Icon name="check" size={26} />
        </div>
        <h1 className="auth-h1">Password changed</h1>
        <p className="auth-msg">Signing you in…</p>
        <div className="auth-spinner" aria-hidden="true" />
      </AuthCard>
    );
  }

  if (phase === 'challenge') {
    const other = challenge.methods.find((m) => m !== method);
    const switchLink = other && (
      <button
        type="button"
        className="auth-alt"
        disabled={busy}
        onClick={() => {
          setChErr(null);
          setCode('');
          setMethod(other);
          if (other === 'passkey') runPasskey();
        }}
      >
        {other === 'passkey' ? 'Use your passkey instead' : 'Use your authenticator app instead'}
      </button>
    );

    return (
      <AuthCard docTitle="Reset password" title="Verify it’s you">
        <div className="auth-chip"><span>{challenge.label}</span></div>
        {chErr && <div className="auth-err">{chErr.msg} [{chErr.code}]</div>}
        {method === 'passkey' ? (
          <>
            <p className="auth-sub" style={{ marginBottom: 16 }}>
              {busy ? 'Your device will ask for your fingerprint, face, or PIN' : 'Confirm with your passkey to finish resetting your password'}
            </p>
            {busy ? (
              <>
                <div className="auth-spinner" aria-hidden="true" />
                <p className="auth-wait">Waiting for your passkey…</p>
              </>
            ) : (
              <button type="button" className="auth-btn" onClick={runPasskey}>
                {chErr ? 'Try again' : 'Use passkey'}
              </button>
            )}
          </>
        ) : (
          <>
            <p className="auth-sub" style={{ marginBottom: 16 }}>Enter the code from your authenticator app</p>
            <OtpBoxes code={code} setCode={(c) => { setCode(c); setChErr(null); }} disabled={busy} onComplete={submitTotp} />
            <button type="button" className="auth-btn" disabled={busy || code.length !== 6} onClick={() => submitTotp()}>
              {busy ? 'Verifying…' : 'Verify'}
            </button>
          </>
        )}
        {switchLink}
      </AuthCard>
    );
  }

  return (
    <AuthCard docTitle="Reset password" title="Choose a new password" sub="for your account">
      {srvErr && <div className="auth-err">{srvErr}</div>}
      <form onSubmit={submitPassword} noValidate>
        <div className={'auth-grp' + (pwBad ? ' bad' : '')}>
          <label htmlFor="newpw">New password</label>
          <input
            id="newpw"
            className="auth-input"
            type="password"
            autoFocus
            autoComplete="new-password"
            value={pw}
            onChange={(e) => { setPw(e.target.value.replace(/\s/g, '')); setPwBad(false); setSrvErr(null); }}
            onBlur={() => { if (pw && !pwOk) setPwBad(true); }}
          />
          <PasswordRules password={pw} />
        </div>
        <div className={'auth-grp' + (cfErr ? ' bad' : '')}>
          <label htmlFor="confirmpw">Confirm new password</label>
          <input
            id="confirmpw"
            className="auth-input"
            type="password"
            autoComplete="new-password"
            value={confirmPw}
            onChange={(e) => { setConfirmPw(e.target.value.replace(/\s/g, '')); setCfErr(null); }}
            onBlur={() => { if (confirmPw && confirmPw !== pw) setCfErr('Passwords do not match.'); }}
          />
          <span className="auth-ferr">{cfErr}</span>
        </div>
        <button type="submit" className="auth-btn" disabled={!canSave}>
          {busy ? 'Saving…' : 'Set new password'}
        </button>
      </form>
    </AuthCard>
  );
}
