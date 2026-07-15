import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { changePassword, getStepupStatus } from '../api.js';
import Icon from '../components/Icon.jsx';
import PasswordRules, { passwordValid } from '../components/PasswordRules.jsx';
import StepUpModal from '../components/StepUpModal.jsx';
import SecurityGate from '../components/SecurityGate.jsx';

function passwordError(e) {
  switch (e.data?.error) {
    case 'weak_password':
      return 'New password must be at least 8 characters and mix character types.';
    default:
      return "Couldn't change your password. Please try again.";
  }
}

function Header({ nav }) {
  return (
    <>
      <button className="back" onClick={() => nav('/security')}>
        <Icon name="chevron" size={16} className="back-chev" />
        Security
      </button>
      <h1>Change password</h1>
      <p className="sub">Choose a new password. Changing it signs you out everywhere except this session.</p>
    </>
  );
}

// The form itself. Entry verification is handled by SecurityGate (challenge on
// ENTRY, fallback tier, 7-min buffer) so the change never interrupts at submit;
// the inner step-up here is only a backstop for a window that lapses while the
// form sits open.
function PasswordForm() {
  const nav = useNavigate();
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [saving, setSaving] = useState(false);
  const [err, setErr] = useState(null);
  const [done, setDone] = useState(false);
  const [stepup, setStepup] = useState(null); // { status, retry }

  const mismatch = confirm.length > 0 && next !== confirm;
  const canSubmit = passwordValid(next) && next === confirm && !saving;

  const doChange = async () => {
    setSaving(true);
    setErr(null);
    try {
      await changePassword({ new_password: next });
      setDone(true);
      setTimeout(() => nav('/security'), 1200);
    } catch (ex) {
      if (ex.message === 'unauthenticated') return;
      if (ex.code === 'step_up_required') {
        setStepup({ status: await getStepupStatus('fallback'), retry: doChange });
        return;
      }
      setErr(passwordError(ex));
    } finally {
      setSaving(false);
    }
  };

  const submit = (e) => {
    e.preventDefault();
    if (canSubmit) doChange();
  };

  return (
    <>
      <Header nav={nav} />

      {done ? (
        <div className="card pad notice-ok">
          <Icon name="check" size={18} />
          Password changed.
        </div>
      ) : (
        <form className="card pad form" onSubmit={submit}>
          <label className="field">
            <span>New password</span>
            <input
              className="input wide"
              type="password"
              autoComplete="new-password"
              value={next}
              onChange={(e) => setNext(e.target.value)}
            />
            <PasswordRules password={next} />
          </label>
          <label className="field">
            <span>Confirm new password</span>
            <input
              className="input wide"
              type="password"
              autoComplete="new-password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
            />
            {mismatch && <small className="fhint bad">Passwords don't match.</small>}
          </label>
          {err && <p className="err">{err}</p>}
          <div className="form-actions">
            <button className="btn btn-primary" type="submit" disabled={!canSubmit}>
              {saving ? 'Saving…' : 'Change password'}
            </button>
            <button className="btn" type="button" onClick={() => nav('/security')}>
              Cancel
            </button>
          </div>
        </form>
      )}

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

export default function PasswordPage() {
  const nav = useNavigate();
  return (
    <SecurityGate skeleton={<Header nav={nav} />}>
      <PasswordForm />
    </SecurityGate>
  );
}
