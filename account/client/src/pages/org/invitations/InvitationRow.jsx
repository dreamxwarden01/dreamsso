import { useEffect, useRef, useState } from 'react';
import InvitationIcon from './InvitationIcon.jsx';
import { CopyInvitationButton, InvitationButton, InvitationRelativeTime, useInvitationFeedback, useInvitationTime } from './InvitationControls.jsx';
import { formatInvitationTime, invitationError, invitationLink } from './invitationModel.js';

const STATUS = { active: ['Active', 'accent', 'clock'], used: ['Accepted', 'success', 'check'], expired: ['Expired', 'neutral', 'clock'], revoked: ['Revoked', 'neutral', 'ban'], invalid: ['Invalid', 'danger', 'alert'] };
const MAIL = { none: ['neutral', 'link', 'Link only'], queued: ['neutral', 'mail', 'Email queued'], sending: ['neutral', 'mail', 'Sending email'], sent: ['neutral', 'mail', 'Email sent'], failed: ['danger', 'alert', 'Send failed'], unknown: ['warn', 'alert', 'Send status unknown'] };
export function InvitationMailChip({ invite }) {
  const spec = invite.mail.state === 'none' && invite.email ? ['neutral', 'mail', 'Not emailed'] : MAIL[invite.mail.state];
  return <span className={'iv-chip iv-st-' + spec[0]}><InvitationIcon name={spec[1]} className="iv-ico-12"/>{spec[2]}</span>;
}
export function mailDetail(invite) {
  const when = invite.mail.at ? formatInvitationTime(invite.mail.at) : null;
  const attempts = invite.mail.attempts > 1 ? ` ${invite.mail.attempts} sends requested so far.` : '';
  switch (invite.mail.state) {
    case 'queued': return 'Queued for the mail service. Delivery is not yet confirmed.' + attempts;
    case 'sending': return 'The mail service request is in progress. Delivery is not yet confirmed.' + attempts;
    case 'sent': return `Accepted by the mail service${when ? ' ' + when : ''}. Delivery and opens aren’t tracked.${attempts}`;
    case 'failed': return `The mail service did not accept the last attempt${when ? ' at ' + when : ''}. The invitation and its binding are unchanged.${attempts}`;
    case 'unknown': return `The mail service did not confirm the last attempt${when ? ' at ' + when : ''}. Check before sending again.${attempts}`;
    default: return invite.email ? 'Not emailed — created as a link bound to this address.' : 'Shared as a link. The registration email goes out when someone claims it.';
  }
}
function outcome(invite) {
  switch (invite.status) {
    case 'used': return `Account ${invite.usedBy?.username ? '@' + invite.usedBy.username : ''}${invite.usedBy?.displayName ? ' (' + invite.usedBy.displayName + ')' : ''} created${invite.endedAt ? ' ' + formatInvitationTime(invite.endedAt) : ''}. The invitation can’t be used again.`;
    case 'expired': return `Reached its deadline unused on ${formatInvitationTime(invite.expiresAt)}. There’s no grace period.`;
    case 'revoked': return `Revoked${invite.revokedBy ? ' by ' + invite.revokedBy : ''}${invite.endedAt ? ' on ' + formatInvitationTime(invite.endedAt) : ''}.`;
    case 'invalid': return (invite.invalidReason || 'The invited role or its creator’s authorization is no longer available.') + ' Accounts that already exist aren’t affected.';
    default: return '';
  }
}
export default function InvitationRow({ invite, onResend, onRevoke }) {
  const [open, setOpen] = useState(false), [error, setError] = useState(null), [retryUntil, setRetryUntil] = useState(0), [doneLabel, setDoneLabel] = useState('Queued'), feedback = useInvitationFeedback(), time = useInvitationTime();
  const details = useRef(null), toggle = useRef(null), mounted = useRef(true);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  useEffect(() => { if (!retryUntil) return undefined; const timer = setTimeout(() => { setRetryUntil(0); setError(null); }, Math.max(0, retryUntil - Date.now())); return () => clearTimeout(timer); }, [retryUntil]);
  const active = invite.status === 'active', title = invite.note || invite.email || 'Shareable link', spec = STATUS[invite.status];
  const endedPrefix = { used: 'Accepted ', expired: 'Expired ', revoked: 'Revoked ', invalid: 'Invalidated ' }[invite.status];
  const resend = async () => {
    if (!invite.canResend || !active || retryUntil > Date.now() || !feedback.begin()) return;
    time.close(); setError(null);
    try { const fresh = await onResend(invite); if (mounted.current) {
      if (['queued', 'sending', 'sent'].includes(fresh.mail.state)) { setDoneLabel(fresh.mail.state === 'sent' ? 'Sent' : 'Queued'); feedback.finish('done'); }
      else { feedback.finish('fail'); setError(mailDetail(fresh)); }
    } }
    catch (e) { if (mounted.current) { feedback.finish('fail'); setError(invitationError(e));
      if (e.code === 'rate_limited' && Number.isSafeInteger(e.data?.retry_after) && e.data.retry_after > 0 && e.data.retry_after <= 86400) setRetryUntil(Date.now() + e.data.retry_after * 1000);
    } }
  };
  return <div className={'iv-inv-row' + (!active ? ' iv-is-ended' : '')} role="listitem" data-invitation-id={invite.id}>
    <div className="iv-inv-sum"><div className={'iv-inv-ic iv-st-' + spec[1]}><InvitationIcon name={spec[2]}/></div>
      <div className="iv-inv-main"><div className="iv-inv-top"><span className="iv-inv-title" title={title}>{title}</span><span className={'iv-tc-pill iv-st-' + spec[1]}>{spec[0]}</span></div>
        <div className="iv-inv-meta">{invite.email && invite.note ? <><span className="iv-m-rcpt"><InvitationIcon name="lock" className="iv-ico-12"/>{invite.email}</span><span className="iv-dot" aria-hidden="true">·</span></> : !invite.email ? <><span>{active ? 'Not bound yet' : 'Never claimed'}</span><span className="iv-dot" aria-hidden="true">·</span></> : null}
          <span>{invite.role.label}</span><span className="iv-dot" aria-hidden="true">·</span><span className="iv-code-chip"><span className="iv-sr-only">Code </span>{invite.code}</span>
        </div>
        <div className="iv-inv-meta">{active ? <><span>Expires <strong><InvitationRelativeTime timestamp={invite.expiresAt}/></strong></span><InvitationMailChip invite={invite}/></>
          : <span>{endedPrefix}<InvitationRelativeTime timestamp={invite.endedAt || invite.expiresAt}/>{invite.status === 'used' && invite.usedBy?.username ? ' · @' + invite.usedBy.username : invite.status === 'revoked' && invite.revokedBy ? ' by ' + invite.revokedBy : invite.status === 'expired' && !invite.email ? ' · never claimed' : ''}</span>}</div>
      </div>
      <div className="iv-inv-acts">{active && <CopyInvitationButton label="Copy link" icon="link" text={invitationLink(invite.code)}/>}
        <button ref={toggle} type="button" className="iv-btn iv-inv-toggle" aria-expanded={open} aria-controls={'iv-detail-' + invite.id} onClick={() => {
          time.close(); if (open && details.current?.contains(document.activeElement)) toggle.current.focus({ preventScroll: true }); setOpen(!open);
        }}>Details<InvitationIcon name="chev" className="iv-chev"/></button>
      </div>
    </div>
    <div ref={details} className="iv-inv-details" id={'iv-detail-' + invite.id} role="region" aria-label={'Details for ' + title} data-open={open} inert={!open}>
      <div className="iv-inv-details-clip"><div className="iv-inv-details-in">
        <dl className="iv-kv">
          <div className="iv-kv-row"><dt>Invitation code</dt><dd><code>{invite.code}</code><CopyInvitationButton label="Copy code" text={invite.code} className="iv-btn-xs"/></dd></div>
          <div className="iv-kv-row"><dt>Record ID</dt><dd><code>{invite.id}</code><CopyInvitationButton label="Copy ID" text={invite.id} className="iv-btn-xs"/></dd></div>
          <div className="iv-kv-row"><dt>Recipient</dt><dd>{invite.email ? <><span className="iv-m-rcpt"><InvitationIcon name="lock" className="iv-ico-12"/>{invite.email}</span><span className="iv-kv-sub">{invite.bindingSource === 'creation' ? 'Bound at creation — can’t be changed. A typo means revoke and reissue.' : 'Bound by the first registration email request — can’t be changed.'}</span></> : 'Not bound. The first eligible registration email request binds an address permanently.'}</dd></div>
          <div className="iv-kv-row"><dt>Role</dt><dd>{invite.role.label}{invite.status === 'invalid' && !invite.role.slug ? ' (deleted)' : ''}</dd></div>
          <div className="iv-kv-row"><dt>Created</dt><dd>{formatInvitationTime(invite.createdAt)} by {invite.createdBy}</dd></div>
          <div className="iv-kv-row"><dt>Deadline</dt><dd>{formatInvitationTime(invite.expiresAt)}{active && ' · fixed at creation'}</dd></div>
          <div className="iv-kv-row"><dt>Email</dt><dd><InvitationMailChip invite={invite}/><span className="iv-kv-sub">{mailDetail(invite)}</span></dd></div>
          {!active && <div className="iv-kv-row"><dt>Outcome</dt><dd>{outcome(invite)}</dd></div>}
          {invite.note && <div className="iv-kv-row"><dt>Note</dt><dd>{invite.note}</dd></div>}
        </dl>
        {active && <><div className="iv-det-acts">{invite.email && invite.canResend && <InvitationButton label={invite.mail.attempts ? 'Resend email' : 'Send email'} phase={feedback.phase} busyLabel="Queueing…" doneLabel={doneLabel} failLabel="Not queued" icon="mail" disabled={retryUntil > Date.now()} onClick={resend}/>}
          {invite.canRevoke && <button type="button" className="iv-btn iv-btn-danger" onClick={() => { time.close(); onRevoke(invite); }}>Revoke…</button>}</div>
          <p className="iv-det-hint">{invite.email ? `Sending again reuses this invitation, address and link. The deadline stays ${formatInvitationTime(invite.expiresAt)}.` : 'Share the link or code yourself. Holding them isn’t proof of an email address — the recipient still confirms one.'}</p></>}
        {error && <p className="iv-det-err" role="alert">{error}</p>}
      </div></div>
    </div>
  </div>;
}
