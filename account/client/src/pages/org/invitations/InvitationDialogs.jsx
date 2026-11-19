import { cloneElement, useEffect, useId, useLayoutEffect, useRef, useState } from 'react';
import InvitationIcon from './InvitationIcon.jsx';
import { CopyInvitationButton, InvitationButton, InvitationModal, InvitationPicker, useInvitationFeedback, useInvitationTime } from './InvitationControls.jsx';
import { formatInvitationTime, invitationError, invitationLink, limitInvitationNote, VALIDITY } from './invitationModel.js';
import { loadInvitation, loadInvitationRoles } from './invitationApi.js';
import { clearInvitationDraft, DEFAULT_INVITATION_FORM, writeInvitationDraft } from './invitationDraft.js';

export function CreateInvitationDialog({ actor, initialForm, onClose, onCreate }) {
  const id = useId(), modal = useRef(null), view = useRef(null), previousHeight = useRef(null), title = useRef(null), emailInput = useRef(null);
  const [form, setForm] = useState(() => ({ ...DEFAULT_INVITATION_FORM, ...initialForm }));
  const [draftNotice, setDraftNotice] = useState(initialForm ? 'Unsaved invitation restored in this tab. Review it before sending.' : '');
  const [roles, setRoles] = useState(null), [roleError, setRoleError] = useState(null), [error, setError] = useState(null), [emailError, setEmailError] = useState(null), [result, setResult] = useState(null), [pollError, setPollError] = useState(false);
  const feedback = useInvitationFeedback(), [busy, setBusy] = useState(false), locked = useRef(false), mounted = useRef(true), time = useInvitationTime();
  useEffect(() => {
    mounted.current = true; const controller = new AbortController();
    loadInvitationRoles(controller.signal).then((d) => {
      if (controller.signal.aborted) return;
      const assignable = (d.roles || []).filter((r) => r.editable); setRoles(assignable);
      setForm((f) => ({ ...f, role_slug: assignable.some((r) => r.slug === f.role_slug) ? f.role_slug : assignable.some((r) => r.slug === d.default_role) ? d.default_role : assignable[0]?.slug || '' }));
    }).catch((e) => { if (!controller.signal.aborted) { setRoles([]); setRoleError(invitationError(e)); } });
    return () => { mounted.current = false; controller.abort(); };
  }, []);
  useLayoutEffect(() => {
    if (!view.current) return;
    const height = view.current.getBoundingClientRect().height;
    if (previousHeight.current !== null) view.current.animate?.([{ height: previousHeight.current + 'px' }, { height: height + 'px' }], { duration: matchMedia('(prefers-reduced-motion: reduce)').matches ? 0 : 220, easing: 'cubic-bezier(.2,0,0,1)' });
    previousHeight.current = height;
    if (result) title.current?.focus({ preventScroll: true }); else emailInput.current?.focus({ preventScroll: true });
  }, [!!result]);
  useEffect(() => {
    if (!result || !['queued', 'sending'].includes(result.mail.state)) return undefined;
    const controller = new AbortController(); let pending = false;
    const timer = setInterval(async () => {
      if (pending || document.visibilityState !== 'visible') return;
      pending = true;
      try { const fresh = await loadInvitation(result.id, controller.signal); if (!controller.signal.aborted) { setResult((old) => old?.id === fresh.id ? fresh : old); setPollError(false); } }
      catch { if (!controller.signal.aborted) setPollError(true); }
      finally { pending = false; }
    }, 2000);
    return () => { clearInterval(timer); controller.abort(); };
  }, [result?.id, result?.mail.state]);
  const persist = (next) => {
    try { if (!writeInvitationDraft(sessionStorage, actor, next)) setDraftNotice('This tab could not retain edits for sign-in recovery. Keep it open while editing.'); }
    catch { setDraftNotice('This tab could not retain edits for sign-in recovery. Keep it open while editing.'); }
  };
  const set = (patch) => { const next = { ...form, ...patch }; setForm(next); persist(next); setError(null); if ('email' in patch) setEmailError(null); };
  const close = () => { try { clearInvitationDraft(sessionStorage, actor); } catch { /* best effort */ } onClose(); };
  const submit = async (event) => {
    event.preventDefault(); if (locked.current || !form.role_slug || !feedback.begin()) return;
    const email = form.email.trim().toLowerCase();
    if (form.delivery === 'email' && !email || email && (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254)) {
      feedback.reset(); setEmailError(form.delivery === 'email' && !email ? 'Enter the recipient’s email address.' : 'Enter a valid email address.'); emailInput.current?.focus(); return;
    }
    locked.current = true; setBusy(true); setError(null); time.close();
    persist({ ...form, email, note: form.note.trim() });
    try {
      const invite = await onCreate({ ...form, email, note: form.note.trim() });
      try { clearInvitationDraft(sessionStorage, actor); } catch { /* request receipt remains authoritative */ }
      if (!mounted.current) return;
      feedback.finish('done', () => { if (mounted.current) { locked.current = false; setBusy(false); setResult(invite); } });
    } catch (e) {
      if (!mounted.current) return;
      locked.current = false; setBusy(false); feedback.finish('fail');
      setError(e.code === 'request_storage_unavailable' ? 'This tab could not retain the request. Allow session storage, then try again.' : invitationError(e));
    }
  };
  const field = (label, control, hint, tag) => { const controlId = id + '-' + label.toLowerCase().replace(/\s+/g, '-'); return <div className="iv-field"><label className="iv-flabel" htmlFor={controlId}><span>{label}</span>{tag && <span className="iv-ftag">{tag}</span>}</label>{cloneElement(control, { id: controlId })}{hint && <span className="iv-fhint">{hint}</span>}</div>; };
  return <InvitationModal ref={modal} labelId={id + '-title'} initialFocus={emailInput} busy={busy} create onClose={close}>
    <div ref={view} className="iv-cp">{result ? <div className="iv-cp-view">
      <div className="iv-cp-head iv-res-head"><div className="iv-res-ic"><InvitationIcon name="tick"/></div><h2 ref={title} className="iv-cp-title" id={id + '-title'} tabIndex={-1}>Invitation created</h2><p className="iv-cp-sub">{result.role.label} · expires {formatInvitationTime(result.expiresAt)}</p></div>
      <div className="iv-cp-fields">
        {result.delivery === 'link' && <div className="iv-field"><span className="iv-flabel">Invitation link</span><div className="iv-linkbox"><span className="iv-keytext" title={invitationLink(result.code)}>{invitationLink(result.code)}</span><CopyInvitationButton label="Copy link" text={invitationLink(result.code)} className="iv-btn-primary"/></div></div>}
        <div className={'iv-ob ' + (result.delivery === 'link' ? 'iv-ob-neutral' : result.mail.state === 'sent' ? 'iv-ob-ok' : ['failed', 'unknown'].includes(result.mail.state) ? 'iv-ob-warn' : 'iv-ob-neutral')} role="status"><InvitationIcon name={result.delivery === 'link' ? 'link' : result.mail.state === 'failed' ? 'alert' : 'mail'}/>
          <div><strong>{result.delivery === 'link' ? 'No email sent' : result.mail.state === 'sent' ? 'Email sent to ' + result.email : result.mail.state === 'failed' ? 'Email not sent' : result.mail.state === 'unknown' ? 'Email send status unknown' : result.mail.state === 'sending' ? 'Sending email to ' + result.email : result.mail.state === 'queued' ? 'Email queued for ' + result.email : 'No email queued'}</strong>
            {result.delivery === 'link' ? result.email ? `Bound to ${result.email}; only that address can register.` : 'Not bound yet. The first registration email request binds an address permanently.'
              : result.mail.state === 'sent' ? 'Accepted by the mail service. Delivery isn’t tracked.' : ['failed', 'unknown'].includes(result.mail.state) ? `The invitation exists and is bound to ${result.email}. Check Details before sending again — the deadline won’t change.` : 'The invitation exists. Details will show when the mail service accepts or rejects the message.'}
          </div></div>
        <dl className="iv-kv"><div className="iv-kv-row"><dt>Recipient</dt><dd>{result.email ? <span className="iv-m-rcpt"><InvitationIcon name="lock" className="iv-ico-12"/>{result.email}</span> : 'Not bound'}</dd></div>
          <div className="iv-kv-row"><dt>Invitation code</dt><dd><code>{result.code}</code><CopyInvitationButton label="Copy code" text={result.code} className="iv-btn-xs"/></dd></div>
          <div className="iv-kv-row"><dt>Record ID</dt><dd><code>{result.id}</code><CopyInvitationButton label="Copy ID" text={result.id} className="iv-btn-xs"/></dd></div></dl>
        {pollError && <p className="iv-fhint iv-bad" role="alert">Couldn’t refresh the email status. Check Details before sending again.</p>}
      </div>
      <div className="iv-cp-foot"><p className="iv-cp-status"/><div className="iv-cp-btns"><button type="button" className="iv-btn" onClick={() => { feedback.reset(); setResult(null); set({ email: '', note: '' }); }}>Create another</button><button type="button" className={'iv-btn' + (result.delivery === 'email' ? ' iv-btn-primary' : '')} onClick={() => modal.current.close()}>Done</button></div></div>
    </div> : <form className="iv-cp-view" noValidate onSubmit={submit}>
      <div className="iv-cp-head"><h2 className="iv-cp-title" id={id + '-title'}>New invitation</h2><p className="iv-cp-sub">Each invitation creates one account.</p></div>
      <fieldset className="iv-cp-fields" disabled={busy}>
        {field('Delivery', <InvitationPicker label="Delivery" block value={form.delivery} disabled={busy} options={[{ value: 'email', label: 'Email', desc: 'Send the invitation to one address' }, { value: 'link', label: 'Copy link / invitation code', desc: 'Share a link or code yourself' }]} onChange={(delivery) => set({ delivery })}/>)}
        <div className="iv-field"><label className="iv-flabel" htmlFor={id + '-email'}><span>{form.delivery === 'email' ? 'Email address' : 'Bind to an email'}</span><span className={'iv-ftag' + (form.delivery === 'email' ? ' iv-req' : '')}>{form.delivery === 'email' ? 'Required' : 'Optional'}</span></label>
          <input ref={emailInput} id={id + '-email'} className={'iv-input iv-wide' + (emailError ? ' iv-bad' : '')} type="email" inputMode="email" autoComplete="off" autoCapitalize="none" spellCheck={false} placeholder="name@example.com" maxLength={254} value={form.email} onChange={(e) => set({ email: e.target.value })} onBlur={() => { const value = form.email.trim(); if (value && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) setEmailError('Enter a valid email address.'); }} aria-required={form.delivery === 'email'} aria-invalid={!!emailError} aria-describedby={id + '-email-help'}/>
          <span id={id + '-email-help'} className={'iv-fhint' + (emailError ? ' iv-bad' : '')}>{emailError || (form.delivery === 'email' ? 'The invitation is sent here and bound to this address for good.' : 'Leave empty and the first registration email request claims it — or bind it now.')}</span>
        </div>
        <div className="iv-grid2">{field('Role', <InvitationPicker label="Role" block disabled={busy || !roles?.length} value={form.role_slug} options={(roles || []).map((r) => ({ value: r.slug, label: r.label }))} onChange={(role_slug) => set({ role_slug })}/>, 'Only roles below your own.')}
          {field('Valid for', <InvitationPicker label="Valid for" block disabled={busy} value={String(form.validity_hours)} options={VALIDITY} onChange={(hours) => set({ validity_hours: Number(hours) })}/>, 'Fixed at creation; resending never extends it.')}</div>
        {field('Note', <input className="iv-input iv-wide" maxLength={120} autoComplete="off" placeholder="e.g. New support teammate" value={form.note} onChange={(e) => set({ note: limitInvitationNote(e.target.value) })}/>, 'Shown to authorized organization admins only.', 'Optional')}
        {roleError && <p className="iv-fhint iv-bad" role="alert">{roleError}</p>}{roles?.length === 0 && !roleError && <p className="iv-fhint iv-bad">No role sits below yours — you can’t create invitations.</p>}
        {draftNotice && <p className="iv-fhint" role="status">{draftNotice}</p>}
      </fieldset>
      <div className="iv-cp-foot"><p className={'iv-cp-status' + (error ? ' iv-err' : '')} role={error ? 'alert' : 'status'}><InvitationIcon name={error ? 'alert' : 'clock'} className="iv-ico-14"/><span>{error || `Expires about ${formatInvitationTime(Date.now() + form.validity_hours * 3600000)}`}</span></p><div className="iv-cp-btns"><button type="button" className="iv-btn" disabled={busy} onClick={() => modal.current.close()}>Cancel</button>
        <InvitationButton type="submit" label={form.delivery === 'email' ? 'Send invitation' : 'Create invitation'} phase={feedback.phase} busyLabel="Creating…" doneLabel="Created" failLabel="Not created" icon={form.delivery === 'email' ? 'mail' : 'link'} className="iv-btn-primary iv-cp-submit" disabled={!form.role_slug || busy}/></div></div>
    </form>}</div>
  </InvitationModal>;
}

export function RevokeInvitationDialog({ invite, onClose, onRevoke }) {
  const id = useId(), modal = useRef(null), cancel = useRef(null), feedback = useInvitationFeedback(), [busy, setBusy] = useState(false), [error, setError] = useState(null), [terminal, setTerminal] = useState(false), lock = useRef(false);
  const revoke = async () => {
    if (lock.current || terminal || !feedback.begin()) return; lock.current = true; setBusy(true); setError(null);
    try { await onRevoke(invite); setBusy(false); modal.current?.close(); }
    catch (e) { lock.current = false; setBusy(false); feedback.finish('fail'); setError(invitationError(e)); if (['already_used', 'invitation_gone', 'invitation_used', 'invitation_expired', 'invitation_revoked'].includes(e.code)) setTerminal(true); }
  };
  return <InvitationModal ref={modal} labelId={id} busy={busy} initialFocus={cancel} onClose={onClose}>
    <h2 className="iv-modal-title" id={id}>Revoke this invitation?</h2>
    <p className="iv-modal-msg"><code>{invite.code}</code> ({invite.note || invite.email || 'Shareable link'}) stops working immediately. Anyone partway through registering with it can’t finish. Accounts that already exist aren’t affected.</p>
    {error && <p className="iv-modal-err" role="alert">{error}</p>}
    <div className="iv-modal-actions"><InvitationButton label="Revoke" phase={feedback.phase} busyLabel="Revoking…" doneLabel="Revoked" failLabel="Try again" iconOnly className="iv-btn-danger iv-revoke-confirm" disabled={terminal} onClick={revoke}/><button ref={cancel} type="button" className="iv-btn" disabled={busy} onClick={() => modal.current.close()}>Cancel</button></div>
  </InvitationModal>;
}
