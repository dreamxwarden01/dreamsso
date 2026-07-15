import { useCallback, useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { startAuthentication, browserSupportsWebAuthn } from '@simplewebauthn/browser';
import { useSite } from '../context/SiteContext.jsx';
import { useAuth } from '../context/AuthContext.jsx';
import { avatarUrl } from '../api.js';
import Icon from './Icon.jsx';
import OtpBoxes from './OtpBoxes.jsx';

// The unified step-up / action challenge — the modal twin of the SSO's
// login-challenge card (shield badge, wordmark from site settings, identity
// chip, red error banner, 6-box OTP, quiet switch links). It's driven by
// `accepted` (the methods the server will take, in priority order) plus injected
// async handlers, so the SAME UI backs both the sudo-window verify and the
// one-time action-token ceremony. Method strength order: passkey > totp > email
// > password; the modal opens on accepted[0] and offers the rest as switches.
//
// Handlers (all optional except verify):
//   getPasskeyOptions() -> WebAuthn request options JSON (needed if 'passkey' is accepted)
//   verify({ method, code, credential, password }) -> resolves on success (value
//     is forwarded to onSuccess), throws on failure (err.status===429 => rate limit)
//   sendEmail() -> { otpMinutes?, resendIn? } (needed if 'email' is accepted)
// A method absent from `accepted` is never rendered. An EMPTY `accepted` renders
// the enroll-required card (no strong factor to challenge with).

const METHOD_SWITCH = {
  passkey: 'Use your passkey',
  totp: 'Use your authenticator app',
  email: 'Email a code instead',
};

function startPhase(method) {
  if (method === 'passkey') return 'waiting';
  if (method === 'email') return 'send';
  return null;
}

export default function ChallengeModal({
  accepted = [],
  maskedEmail,
  getPasskeyOptions,
  verify,
  sendEmail,
  onSuccess,
  onCancel,
  enrollHref = '/security',
}) {
  const { siteName } = useSite();
  const { user } = useAuth();
  const nav = useNavigate();
  const name = siteName || 'DreamSSO';
  const profile = user?.profile; // /api/me nests identity under `profile`
  const userLabel = profile?.display_name || profile?.username || profile?.email || '';
  const avatar = profile?.picture || null;
  const enroll = accepted.length === 0;

  const [method, setMethod] = useState(accepted[0] ?? null);
  const [phase, setPhase] = useState(() => startPhase(accepted[0])); // passkey: waiting|failure · email: send|check
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);
  const [code, setCode] = useState('');
  const [password, setPassword] = useState('');
  const [otpMinutes, setOtpMinutes] = useState(5);
  const [resendIn, setResendIn] = useState(0);
  const [leaving, setLeaving] = useState(false);

  const pkRun = useRef(0); // bumped to invalidate an in-flight passkey ceremony (cancel-while-waiting)
  const pkAuto = useRef(false); // guards the one-time auto-run on open
  const resendRef = useRef(null);
  const left = useRef(false); // idempotency: only the first exit wins

  // Play the exit animation, THEN hand control back to the parent (which unmounts us).
  const finish = useCallback((fn) => {
    if (left.current) return;
    left.current = true;
    setLeaving(true);
    setTimeout(() => fn?.(), 150);
  }, []);

  const startResend = useCallback((secs) => {
    if (resendRef.current) clearInterval(resendRef.current);
    let n = secs > 0 ? secs : 0;
    setResendIn(n);
    if (n <= 0) return;
    resendRef.current = setInterval(() => {
      n -= 1;
      if (n <= 0) {
        clearInterval(resendRef.current);
        resendRef.current = null;
        setResendIn(0);
      } else setResendIn(n);
    }, 1000);
  }, []);
  useEffect(() => () => resendRef.current && clearInterval(resendRef.current), []);

  const runPasskey = useCallback(async () => {
    setErr(null);
    setMethod('passkey');
    setPhase('waiting');
    const run = ++pkRun.current;
    const live = () => run === pkRun.current;
    try {
      if (!browserSupportsWebAuthn()) {
        if (live()) { setPhase('failure'); setErr("This browser doesn't support passkeys."); }
        return;
      }
      const options = await getPasskeyOptions();
      if (!live()) return;
      let cred;
      try {
        cred = await startAuthentication({ optionsJSON: options });
      } catch {
        if (live()) { setPhase('failure'); setErr('Verification was cancelled or didn’t complete.'); }
        return;
      }
      if (!live()) return; // user hit Cancel while the OS dialog was up
      setBusy(true);
      const result = await verify({ method: 'passkey', credential: cred });
      if (!live()) return;
      finish(() => onSuccess?.(result));
    } catch (e) {
      if (!live()) return;
      if (e?.message === 'unauthenticated') return;
      setPhase('failure');
      setErr("Couldn't verify your passkey — try again.");
    } finally {
      if (live()) setBusy(false);
    }
  }, [getPasskeyOptions, verify, onSuccess, finish]);

  // Auto-run the passkey ceremony once when the modal opens on 'passkey'.
  useEffect(() => {
    if (!enroll && method === 'passkey' && phase === 'waiting' && !pkAuto.current) {
      pkAuto.current = true;
      runPasskey();
    }
  }, [enroll, method, phase, runPasskey]);

  // Cancel pressed during the passkey wait -> land on the failure card (treat as a
  // cancelled ceremony), NOT dismiss. Bumping pkRun makes any late resolve a no-op.
  const cancelWaiting = () => {
    pkRun.current += 1;
    setBusy(false);
    setPhase('failure');
    setErr('Verification was cancelled or didn’t complete.');
  };

  const verifyCode = async (m, c = code) => {
    setErr(null);
    setBusy(true);
    try {
      const result = await verify({ method: m, code: String(c).trim() });
      finish(() => onSuccess?.(result));
    } catch (e) {
      if (e?.message === 'unauthenticated') return;
      setErr(
        e?.status === 429
          ? `Too many attempts — try again in ${e?.data?.retry_after ?? 120}s.`
          : 'That code is incorrect or expired — enter the current one.',
      );
      setCode('');
    } finally {
      setBusy(false);
    }
  };

  const verifyPassword = async () => {
    setErr(null);
    setBusy(true);
    try {
      const result = await verify({ method: 'password', password });
      finish(() => onSuccess?.(result));
    } catch (e) {
      if (e?.message === 'unauthenticated') return;
      setErr(
        e?.status === 429
          ? `Too many attempts — try again in ${e?.data?.retry_after ?? 120}s.`
          : 'That password is incorrect.',
      );
      setPassword('');
    } finally {
      setBusy(false);
    }
  };

  const doSendEmail = async (isResend = false) => {
    setErr(null);
    if (!isResend) setBusy(true);
    try {
      const r = (await sendEmail?.()) || {};
      if (r.otpMinutes) setOtpMinutes(r.otpMinutes);
      startResend(r.resendIn ?? 30);
      setCode('');
      setPhase('check');
    } catch (e) {
      if (e?.message === 'unauthenticated') return;
      setErr(
        e?.status === 429
          ? `Too many requests — try again in ${e?.data?.retry_after ?? 60}s.`
          : 'Couldn’t send the code — try again in a moment.',
      );
    } finally {
      if (!isResend) setBusy(false);
    }
  };

  const switchTo = (m) => {
    setErr(null);
    setCode('');
    setMethod(m);
    setPhase(startPhase(m));
    if (m === 'passkey') runPasskey();
  };

  const dismiss = useCallback(() => finish(() => onCancel?.()), [finish, onCancel]);

  // Esc dismisses (except mid-passkey-wait, where the OS dialog owns focus); body
  // scroll locked while open.
  useEffect(() => {
    const onKey = (e) => {
      if (e.key === 'Escape' && !(method === 'passkey' && phase === 'waiting') && !busy) dismiss();
    };
    document.addEventListener('keydown', onKey, true);
    const prev = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => {
      document.removeEventListener('keydown', onKey, true);
      document.body.style.overflow = prev;
    };
  }, [dismiss, method, phase, busy]);

  const switchLinks = accepted
    .filter((m) => m !== method)
    .map((m) => (
      <button key={m} className="ch-alt" onClick={() => switchTo(m)}>
        {METHOD_SWITCH[m] ?? m}
      </button>
    ));

  const chip = (
    <div className="auth-chip ch-chip">
      <span>
        {avatar && <img className="ch-chip-av" src={avatarUrl(avatar)} alt="" />}
        {userLabel}
      </span>
    </div>
  );

  let title;
  let sub;
  let body;

  if (enroll) {
    title = 'Verification required';
    sub = 'Managing this area needs a passkey or authenticator app on your account. Add one in Security, then come back.';
    body = (
      <>
        <button className="ch-btn" onClick={() => finish(() => nav(enrollHref))}>
          Go to Security
        </button>
        <button className="ch-alt ch-muted" onClick={dismiss}>
          Not now
        </button>
      </>
    );
  } else if (method === 'passkey') {
    title = 'Verify it’s you';
    sub = 'Your device will ask for your fingerprint, face, or PIN';
    if (phase === 'waiting') {
      body = (
        <>
          <p className="wait">Waiting for your passkey…</p>
          <button className="ch-ghost" onClick={cancelWaiting}>Cancel</button>
        </>
      );
    } else {
      body = (
        <>
          <button className="ch-btn" onClick={runPasskey}>Try again</button>
          {switchLinks}
          <button className="ch-ghost" onClick={dismiss}>Cancel</button>
        </>
      );
    }
  } else if (method === 'totp') {
    title = 'Enter your code';
    sub = 'From your authenticator app';
    body = (
      <>
        <OtpBoxes
          value={code}
          onChange={(v) => { setCode(v); setErr(null); }}
          onComplete={(c) => verifyCode('totp', c)}
          disabled={busy}
        />
        <button className="ch-btn" onClick={() => verifyCode('totp')} disabled={busy || code.length !== 6}>
          {busy ? 'Verifying…' : 'Verify'}
        </button>
        {switchLinks}
        <button className="ch-ghost" onClick={dismiss}>Cancel</button>
      </>
    );
  } else if (method === 'email' && phase === 'send') {
    title = 'Verify it’s you';
    sub = `We’ll email a code to your address — it stays valid for ${otpMinutes} minutes`;
    body = (
      <>
        <button className="ch-btn" onClick={() => doSendEmail(false)} disabled={busy}>
          {busy ? 'Sending…' : `Send a code to ${maskedEmail || 'your email'}`}
        </button>
        {switchLinks}
        <button className="ch-ghost" onClick={dismiss}>Cancel</button>
      </>
    );
  } else if (method === 'email') {
    title = 'Check your email';
    sub = `We sent a code to ${maskedEmail || 'your email'} — it expires in ${otpMinutes} minutes`;
    body = (
      <>
        <OtpBoxes
          value={code}
          onChange={(v) => { setCode(v); setErr(null); }}
          onComplete={(c) => verifyCode('email', c)}
          disabled={busy}
        />
        <button className="ch-btn" onClick={() => verifyCode('email')} disabled={busy || code.length !== 6}>
          {busy ? 'Verifying…' : 'Verify'}
        </button>
        <p className="ch-resend">
          {resendIn > 0
            ? `Resend code in ${resendIn}s`
            : <button onClick={() => doSendEmail(true)}>Resend code</button>}
        </p>
        {switchLinks}
        <button className="ch-ghost" onClick={dismiss}>Cancel</button>
      </>
    );
  } else if (method === 'password') {
    title = 'Confirm your password';
    sub = 'Enter your password to continue';
    body = (
      <>
        <input
          className="input ch-input"
          type="password"
          autoComplete="current-password"
          placeholder="Password"
          aria-label="Password"
          value={password}
          autoFocus
          disabled={busy}
          onChange={(e) => { setPassword(e.target.value); setErr(null); }}
          onKeyDown={(e) => { if (e.key === 'Enter' && password && !busy) verifyPassword(); }}
        />
        <button className="ch-btn" onClick={verifyPassword} disabled={busy || !password}>
          {busy ? 'Verifying…' : 'Confirm'}
        </button>
        <button className="ch-ghost" onClick={dismiss}>Cancel</button>
      </>
    );
  }

  return (
    <div className={`ch-scrim${leaving ? ' ch-leaving' : ''}`}>
      <div className="ch-wrap">
        <div className="auth-card" role="dialog" aria-modal="true">
          <div className="auth-brand">
            <span className="auth-badge"><Icon name="shield-lock" size={24} /></span>
            <span className="auth-wordmark">{name}</span>
          </div>
          {chip}
          {enroll && <div className="ch-lock"><Icon name="lock" size={26} /></div>}
          <div className="ch-body" key={`${method}/${phase}`}>
            <h1 className="auth-h1">{title}</h1>
            <p className="auth-sub ch-sub">{sub}</p>
            {err && <div className="err-banner ch-err">{err}</div>}
            {body}
          </div>
        </div>
      </div>
    </div>
  );
}
