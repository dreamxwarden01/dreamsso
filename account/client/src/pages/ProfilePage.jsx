import { useCallback, useEffect, useRef, useState } from 'react';
import { NavLink } from 'react-router-dom';
import { useAuth } from '../context/AuthContext.jsx';
import {
  updateProfile, getStepupStatus, getSecurity,
  emailChangeGet, emailChangeStart, emailChangeCheck, emailChangeResend, emailChangeCancel, emailVerifySend,
  usernameChange, usernameChangeCheck, avatarUrl } from '../api.js';
import Icon from '../components/Icon.jsx';
import Modal from '../components/Modal.jsx';
import StepUpModal from '../components/StepUpModal.jsx';
import { toast } from '../components/Toast.jsx';
import { initials } from '../components/Avatar.jsx';
import AvatarModal from '../components/AvatarModal.jsx';

const EMAIL_OK = (v) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v) && v.length <= 254;
const USERNAME_OK = (v) => /^[A-Za-z0-9_-]{3,20}$/.test(v);
const emailOperationChanged = (e) => ['email_change_changed', 'no_pending'].includes(e.code);
const EMAIL_CHANGED = 'Your email settings changed or the request expired. Review the current state and try again.';
const SEND_UNCONFIRMED = 'We couldn’t confirm whether the email was sent. Check your inbox before trying again.';

function errorText(e) {
  switch (e.data?.error || e.message) {
    case 'invalid_display_name':
      return 'Enter a valid display name.';
    case 'permission_denied':
      return 'Your organization manages this setting.';
    default:
      return "Couldn't save changes. Please try again.";
  }
}

// One editable identity row (display_name): inline edit, PATCH /api/profile.
function EditableRow({ label, field, value, editable = true }) {
  const { reload } = useAuth();
  const [editing, setEditing] = useState(false);
  const [val, setVal] = useState(value ?? '');
  const [saving, setSaving] = useState(false);
  const [err, setErr] = useState(null);

  const start = () => {
    setVal(value ?? '');
    setErr(null);
    setEditing(true);
  };
  const cancel = () => {
    setEditing(false);
    setErr(null);
  };
  const save = async () => {
    setSaving(true);
    setErr(null);
    try {
      await updateProfile({ [field]: val });
      await reload();
      setEditing(false);
    } catch (e) {
      if (e.message !== 'unauthenticated') setErr(errorText(e));
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="row">
      <div className="row-main">
        <p className="k">{label}</p>
        {!editing ? (
          <p className="v">{value || <span style={{ color: 'var(--faint)' }}>—</span>}</p>
        ) : (
          <>
            <div className="edit">
              <input
                className="input" value={val} autoFocus disabled={saving}
                onChange={(e) => setVal(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') save();
                  if (e.key === 'Escape') cancel();
                }}
              />
              <button className="btn btn-primary" onClick={save} disabled={saving}>
                {saving ? 'Saving…' : 'Save'}
              </button>
              <button className="btn" onClick={cancel} disabled={saving}>Cancel</button>
            </div>
            {err && <p className="err">{err}</p>}
          </>
        )}
      </div>
      {!editing &&
        (editable ? (
          <button className="btn" onClick={start}>
            <Icon name="edit" size={15} />
            Edit
          </button>
        ) : (
          <span className="locked">
            <Icon name="lock" size={14} />
            Managed by your organization
          </span>
        ))}
    </div>
  );
}

// The change ceremony in one modal (user design): step 1 = the new value
// (blank box, blur-validated, availability checked IMMEDIATELY on submit —
// before any challenge is spent); step 2 = the unified tiered step-up (the
// ChallengeModal: passkey/totp if owned, else an OTP to the current email, else
// the password). The server re-checks uniqueness at start regardless.
function ChangeModal({ kind, st, onClose, onDone, reload, onChanged }) {
  const isEmail = kind === 'email';
  const [phase, setPhase] = useState('input'); // input | verify
  const [val, setVal] = useState('');
  const [valBad, setValBad] = useState(false);
  const [fieldErr, setFieldErr] = useState(null);
  const [err, setErr] = useState(null);
  const [busy, setBusy] = useState(false);
  const [stepup, setStepup] = useState(null);
  const snapshot = useRef(st), request = useRef(null), starting = useRef(false), checking = useRef(false), mounted = useRef(true), activeStepup = useRef(null);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);

  const current = isEmail ? snapshot.current.email : st.username;
  const newVal = val.trim();
  const validNew = isEmail
    ? EMAIL_OK(newVal) && (current ?? '').toLowerCase() !== newVal.toLowerCase()
    : USERNAME_OK(newVal) && newVal.toLowerCase() !== (current ?? '').toLowerCase();
  const formatHint = isEmail
    ? 'Enter a valid email address.'
    : 'Usernames are 3–20 characters: letters, digits, - and _.';
  const sameHint = isEmail ? 'That is already your email address.' : 'That is already your username.';
  const takenHint = isEmail ? 'This email address is already registered.' : 'This username is already taken.';
  const fieldCode = (e) => e.data?.errors?.new_email ?? e.data?.errors?.email ?? e.data?.errors?.new_username ?? e.code;

  const mapStartErr = (e) => {
    if (e.code === 'send_unconfirmed') return SEND_UNCONFIRMED;
    const f = fieldCode(e);
    if (f === 'email_taken' || f === 'username_taken') return takenHint;
    if (f === 'same_email' || f === 'same_username') return sameHint;
    if (['invalid_email', 'invalid_username'].includes(f)) return formatHint;
    if (e.status === 429) return `Too many emails — try again in ${e.data?.retry_after ?? 60}s.`;
    return `Couldn't complete the change. [${e.code || 'error'}]`;
  };

  // Attempt the change. The proof is a fresh FALLBACK-tier step-up window; a stale
  // one makes the server 403, so we open the unified ChallengeModal and retry.
  const start = async () => {
    if (starting.current || !mounted.current) return;
    starting.current = true;
    setBusy(true);
    setErr(null);
    try {
      if (isEmail) {
        // Once sent, the entire tuple is immutable through step-up and an
        // uncertain HTTP retry. A later edit is prepared against fresh state.
        if (!request.current) request.current = { new_email: newVal.toLowerCase(), request_id: crypto.randomUUID(), expected_revision: snapshot.current.revision };
        const d = await emailChangeStart(request.current);
        if (mounted.current) onDone(`Verification email sent to ${d.new_email}.`);
      } else {
        const d = await usernameChange({ new_username: newVal });
        if (mounted.current) onDone(`Username changed to ${d.username}.`);
      }
    } catch (e) {
      if (!mounted.current) return;
      if (e.message === 'unauthenticated') return;
      if (isEmail && emailOperationChanged(e)) {
        request.current = null; await reload(); if (mounted.current) onChanged();
      } else if (e.code === 'step_up_required') {
        // email-change tier: passkey/totp if owned, else an OTP to the CURRENT
        // (verified) email — regardless of the MFA toggle — else the password.
        try { const status = await getStepupStatus('email-change'); if (mounted.current) { activeStepup.current = status; setStepup(status); } } catch { if (mounted.current) setErr("Couldn't start verification — try again."); }
      } else if (['email_taken', 'username_taken', 'same_email', 'same_username', 'invalid_email', 'invalid_username'].includes(fieldCode(e))) {
        setPhase('input'); setStepup(null); setFieldErr(mapStartErr(e));
      } else {
        setErr(mapStartErr(e));
      }
      if (isEmail && (['send_failed', 'send_unconfirmed', 'email_change_unavailable', 'network_error', 'request_timeout', 'upstream_unreachable', 'upstream_timeout'].includes(e.code) || e.uncertain || e.status === 0)) {
        // The operation may have committed before mail/transport failed. Refresh
        // the row without replacing this attempt's immutable retry identity.
        await reload();
      }
    } finally {
      starting.current = false; if (mounted.current) setBusy(false);
    }
  };

  // Step 1 submit: availability probe FIRST — a taken value must not cost a
  // challenge. Then into the identity-verification step.
  const submitValue = async () => {
    if (checking.current || starting.current || !mounted.current) return;
    if (!validNew) return setValBad(true);
    checking.current = true;
    setBusy(true);
    setFieldErr(null);
    try {
      if (isEmail && (typeof snapshot.current.revision !== 'string' || request.current && request.current.new_email !== newVal.toLowerCase())) {
        const fresh = await reload();
        if (!mounted.current) return;
        if (!fresh) throw new Error('refresh_failed');
        if (fresh.revision !== snapshot.current.revision) { request.current = null; onChanged(); return; }
        snapshot.current = fresh; request.current = null;
      }
      await (isEmail ? emailChangeCheck(newVal) : usernameChangeCheck(newVal));
      if (!mounted.current) return;
      setPhase('verify');
      await start(); // fresh window sails through; a stale one 403s -> opens the challenge
    } catch (e) {
      if (!mounted.current) return;
      if (e.message === 'unauthenticated') return;
      const f = fieldCode(e);
      if (f === 'email_taken' || f === 'username_taken') setFieldErr(takenHint);
      else if (f === 'same_email' || f === 'same_username') setFieldErr(sameHint);
      else if (['invalid_email', 'invalid_username'].includes(f)) setFieldErr(formatHint);
      else setFieldErr(`Couldn't check availability. [${e.code || 'error'}]`);
    } finally {
      checking.current = false; if (mounted.current) setBusy(false);
    }
  };

  return (
    <Modal title={isEmail ? 'Change email address' : 'Change username'} onClose={onClose}>
      {phase === 'input' && (
        <div className="form">
          <p className="modal-msg" style={{ marginTop: 0 }}>
            Current: <strong>{current || '—'}</strong>
          </p>
          <label className="field"><span>{isEmail ? 'New email address' : 'New username'}</span>
            <input
              className={'input' + ((valBad || fieldErr) ? ' bad' : '')}
              type={isEmail ? 'email' : 'text'} autoFocus disabled={busy}
              autoCapitalize="none" autoCorrect="off" spellCheck="false"
              placeholder={isEmail ? 'new-address@example.com' : 'new-username'}
              value={val}
              onChange={(e) => { setVal(e.target.value.replace(/\s/g, '')); setValBad(false); setFieldErr(null); }}
              onBlur={() => { if (newVal && !validNew) setValBad(true); }}
              onKeyDown={(e) => { if (e.key === 'Enter') submitValue(); }}
            />
            <span className={'fhint' + ((valBad || fieldErr) ? ' bad' : '')}>
              {fieldErr || (valBad
                ? (newVal.toLowerCase() === (current ?? '').toLowerCase() ? sameHint : formatHint)
                : isEmail
                  ? 'We’ll email the new address a confirmation link — your current email stays active until it’s clicked.'
                  : 'You sign in with this — changing it takes effect immediately.')}
            </span>
          </label>
          <div className="modal-actions">
            <button className="btn btn-primary" onClick={submitValue} disabled={busy || !validNew}>
              {busy ? 'Checking…' : 'Continue'}
            </button>
            <button className="btn" onClick={onClose} disabled={busy}>Cancel</button>
          </div>
        </div>
      )}
      {phase === 'verify' && (
        <>
          <p className="modal-msg" style={{ marginTop: 0 }}>
            <Icon name="lock" size={14} /> <strong>Verify your identity</strong> — to continue, we need to confirm it&rsquo;s you.
          </p>
          {err && <p className="err">{err}</p>}
          <div className="modal-actions">
            <button className="btn btn-primary" onClick={() => start()} disabled={busy}>
              {busy ? 'Verifying…' : 'Verify'}
            </button>
            <button className="btn" onClick={() => { setPhase('input'); setErr(null); }} disabled={busy}>Back</button>
          </div>
        </>
      )}
      {stepup && (
        <StepUpModal
          status={stepup}
          onSuccess={() => { if (!mounted.current || activeStepup.current !== stepup) return; activeStepup.current = null; setStepup(null); start(); }}
          onCancel={() => { activeStepup.current = null; setStepup(null); setErr('Verification cancelled — try again.'); }}
        />
      )}
    </Modal>
  );
}

// The email row — verify-then-commit. Renders LIVE data from
// GET /api/email-change (session claims go stale after an SSO-side swap).
// A pending NEW address shows under the current one, same style, with a blue
// "Pending verification" badge + Resend/Cancel.
function EmailRow({ st, reload }) {
  const { can } = useAuth();
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const acting = useRef(false), confirmation = useRef(null), mounted = useRef(true);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  useEffect(() => {
    if (confirmation.current?.expected_revision !== st?.revision) confirmation.current = null;
  }, [st?.revision]);

  if (!st) {
    return (
      <div className="row">
        <div className="row-main"><p className="k">Email</p><p className="v">…</p></div>
      </div>
    );
  }

  const editable = can(st.email ? 'profile.email.change' : 'profile.email.add');

  const act = async (fn, okMsg) => {
    if (acting.current || !mounted.current) return;
    acting.current = true; setBusy(true);
    try {
      await fn();
      if (!mounted.current) return;
      confirmation.current = null;
      if (okMsg) toast.success(okMsg);
      await reload();
    } catch (e) {
      if (!mounted.current) return;
      if (e.message === 'unauthenticated') return;
      if (emailOperationChanged(e)) { confirmation.current = null; await reload(); if (mounted.current) toast.error(EMAIL_CHANGED); return; }
      toast.error(e.code === 'send_unconfirmed' ? SEND_UNCONFIRMED : e.code === 'email_taken' ? 'This email address is already registered. Review your email settings.' : e.status === 429
        ? `Too many emails — try again in ${e.data?.retry_after ?? 60}s.`
        : `Failed. [${e.code || 'error'}]`);
    } finally {
      acting.current = false; if (mounted.current) setBusy(false);
    }
  };
  const pendingAction = (fn, message) => act(() => {
    if (!st.pending?.request_id) throw Object.assign(new Error('email_change_changed'), { code: 'email_change_changed' });
    return fn(st.pending.request_id);
  }, message);
  const confirmCurrent = () => act(() => {
    if (typeof st.revision !== 'string') throw Object.assign(new Error('email_change_changed'), { code: 'email_change_changed' });
    confirmation.current ??= { request_id: crypto.randomUUID(), expected_revision: st.revision };
    return emailVerifySend(confirmation.current);
  }, 'Verification email sent — check your inbox.');

  return (
    <div className="row">
      <div className="row-main">
        <p className="k">Email</p>
        <p className="v">
          {st.email || <span style={{ color: 'var(--faint)' }}>—</span>}
          {st.email && (st.email_verified ? (
            <span className="pill pill-ok"><Icon name="check" size={12} />Verified</span>
          ) : (
            <span className="pill pill-warn"><Icon name="alert" size={12} />Unverified</span>
          ))}
        </p>
        {st.pending?.kind === 'change' && (
          <>
            <p className="v" style={{ marginTop: 2 }}>
              {st.pending.new_email}
              <span className="pill pill-info"><Icon name="mail" size={12} />Pending verification</span>
            </p>
            <p className="hint" style={{ marginTop: 2 }}>
              <a href="#resend" aria-disabled={busy} onClick={(e) => { e.preventDefault(); pendingAction(emailChangeResend, 'Verification email re-sent.'); }}>Resend</a>
              {' · '}
              <a href="#cancel" aria-disabled={busy} onClick={(e) => { e.preventDefault(); pendingAction(emailChangeCancel, 'Pending change cancelled.'); }}>Cancel</a>
            </p>
          </>
        )}
        {st.pending?.kind === 'confirm' && (
          <p className="hint" style={{ marginTop: 4 }}>
            Verification pending — check your inbox.{' '}
            <a href="#resend" aria-disabled={busy} onClick={(e) => { e.preventDefault(); pendingAction(emailChangeResend, 'Verification email re-sent.'); }}>Resend</a>
            {' · '}
            <a href="#cancel" aria-disabled={busy} onClick={(e) => { e.preventDefault(); pendingAction(emailChangeCancel, 'Cancelled.'); }}>Cancel</a>
          </p>
        )}
      </div>
      <div className="row-actions">
        {st.email && !st.email_verified && !st.pending && (
          <button className="btn" disabled={busy} onClick={confirmCurrent}>
            Verify
          </button>
        )}
        {editable ? (
          <button className="btn" disabled={busy} onClick={() => setOpen(true)}>
            <Icon name="edit" size={15} />
            Edit
          </button>
        ) : (
          <span className="locked">
            <Icon name="lock" size={14} />
            Managed by your organization
          </span>
        )}
      </div>
      {open && (
        <ChangeModal
          kind="email" st={st} reload={reload}
          onClose={() => { setOpen(false); reload(); }}
          onDone={(msg) => { setOpen(false); toast.success(msg); reload(); }}
          onChanged={() => { setOpen(false); toast.error(EMAIL_CHANGED); }}
        />
      )}
    </div>
  );
}

// The username row — permission-gated (profile.username.change), same modal
// ceremony; commits immediately (no inbox to prove).
function UsernameRow({ st, reload, fallback }) {
  const { can, reload: reloadMe } = useAuth();
  const [open, setOpen] = useState(false);
  const current = st?.username ?? fallback;
  const editable = can('profile.username.change');

  return (
    <div className="row">
      <div className="row-main">
        <p className="k">Username</p>
        <p className="v">{current || '—'}</p>
      </div>
      {editable && st ? (
        <button className="btn" onClick={() => setOpen(true)}>
          <Icon name="edit" size={15} />
          Edit
        </button>
      ) : (
        <span className="locked">
          <Icon name="lock" size={14} />
          Can&rsquo;t be changed
        </span>
      )}
      {open && (
        <ChangeModal
          kind="username" st={st}
          onClose={() => setOpen(false)}
          onDone={(msg) => { setOpen(false); toast.success(msg); reload(); reloadMe(); }}
        />
      )}
    </div>
  );
}

export default function ProfilePage() {
  const { user, can, reload } = useAuth();
  const [avatarOpen, setAvatarOpen] = useState(false);
  // Refresh effective permissions + profile each time the page is entered.
  useEffect(() => {
    reload();
  }, [reload]);
  // Live identity state (email/username/gate/pending) — session claims go
  // stale after SSO-side changes, so both sensitive rows render from this.
  const [acct, setAcct] = useState(null);
  const accountLoad = useRef(0), accountMounted = useRef(true);
  const loadAcct = useCallback(async () => {
    const sequence = ++accountLoad.current;
    try {
      const fresh = await emailChangeGet();
      if (accountMounted.current && sequence === accountLoad.current) setAcct(fresh);
      return sequence === accountLoad.current ? fresh : null;
    } catch { return null; }
  }, []);
  useEffect(() => { accountMounted.current = true; loadAcct(); return () => { accountMounted.current = false; accountLoad.current++; }; }, [loadAcct]);

  // MFA status must reflect ACCOUNT ENROLLMENT (the /api/security toggle), NOT how
  // this session authenticated — the session amr can be pwd-only even with MFA on
  // (e.g. signed in before enabling it). null = loading, false = unavailable.
  const [sec, setSec] = useState(null);
  useEffect(() => { getSecurity().then(setSec).catch(() => setSec(false)); }, []);

  const p = user.profile;
  const mfaKnown = !!sec && typeof sec === 'object';
  const mfaOn = mfaKnown && !!sec.mfa?.enabled;
  const mfaFactors = mfaKnown ? (sec.mfa?.authenticators?.length ?? 0) + (sec.mfa?.passkeys?.length ?? 0) : 0;

  return (
    <>
      <h1>Profile</h1>
      <p className="sub">Your identity across DreamSSO apps.</p>

      <div className="card pad profile-head">
        <div className="avwrap">
          {p.picture ? (
            <img className="av-lg" src={avatarUrl(p.picture)} alt="" />
          ) : (
            <div className="av-lg">{initials(p.display_name || p.username)}</div>
          )}
          {can('profile.picture.set') && (
            <button
              className="av-cam"
              title="Change profile picture"
              aria-label="Change profile picture"
              onClick={() => setAvatarOpen(true)}
            >
              <Icon name="camera" size={16} />
            </button>
          )}
        </div>
        <div>
          <p className="pname">{p.display_name || p.username || 'Your account'}</p>
          {(acct?.username ?? p.username) && <p className="pmeta">@{acct?.username ?? p.username}</p>}
          {(acct?.email ?? p.email) && <p className="pmeta">{acct?.email ?? p.email}</p>}
        </div>
      </div>

      <div className="card">
        <EditableRow
          label="Display name"
          field="display_name"
          value={p.display_name}
          editable={can('profile.displayname.change')}
        />
        <EmailRow st={acct} reload={loadAcct} />
        <UsernameRow st={acct} reload={loadAcct} fallback={p.username} />
      </div>

      <div className="summary">
        <div className="lhs">
          <Icon name="shield-check" size={23} className={!mfaKnown ? 'lead-mut' : mfaOn ? 'lead-ok' : 'lead-warn'} />
          <div>
            <p style={{ margin: 0, fontSize: 14, fontWeight: 600 }}>
              {!mfaKnown
                ? 'Multi-factor authentication'
                : mfaOn
                  ? 'Multi-factor authentication is on'
                  : 'Multi-factor authentication is off'}
            </p>
            <p style={{ margin: '1px 0 0', fontSize: 13, color: 'var(--mut)' }}>
              {sec === null
                ? 'Checking…'
                : !mfaKnown
                  ? 'Review your settings in Security'
                  : mfaOn
                    ? mfaFactors
                      ? `Protected with ${mfaFactors} factor${mfaFactors === 1 ? '' : 's'}`
                      : 'Your account is protected with a second factor'
                    : 'Add a second factor to better protect your account'}
            </p>
          </div>
        </div>
        <NavLink to="/security" className="btn">
          Manage in Security
        </NavLink>
      </div>
      {avatarOpen && (
        <AvatarModal
          hasPicture={!!p.picture}
          onSaved={() => reload()}
          onClose={() => setAvatarOpen(false)}
        />
      )}
    </>
  );
}
