import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';
import { useAuth } from '../../context/AuthContext.jsx';
import InvitationIcon from './invitations/InvitationIcon.jsx';
import { InvitationPager, InvitationPicker, InvitationTimeProvider, useInvitationTime } from './invitations/InvitationControls.jsx';
import InvitationRow from './invitations/InvitationRow.jsx';
import { CreateInvitationDialog, RevokeInvitationDialog } from './invitations/InvitationDialogs.jsx';
import { createInvitation, resendInvitation, revokeInvitation } from './invitations/invitationApi.js';
import { authInterruption, cohortKey, invitationError } from './invitations/invitationModel.js';
import { mutationRequest, settleOperation } from './invitations/invitationOperations.js';
import { useInvitationList } from './invitations/useInvitationList.js';
import { readInvitationDraft } from './invitations/invitationDraft.js';
import './invitations/Invitations.css';

const SORTS = [{ value: 'created_at:desc', label: 'Created: newest first' }, { value: 'created_at:asc', label: 'Created: oldest first' }, { value: 'code:asc', label: 'Code: A–Z' }, { value: 'code:desc', label: 'Code: Z–A' }];
const SIZES = [10, 25, 100].map((n) => ({ value: String(n), label: n + ' per page' }));
function PlaceholderRows() {
  return <>{Array.from({ length: 10 }, (_, i) => <div className="iv-loading-placeholder" key={i} aria-hidden="true"><div className="iv-row-title-placeholder"/><div className="iv-row-meta-placeholder"/></div>)}</>;
}
export function InvitesSkeleton() {
  return <section className="iv-ui iv-page" aria-busy="true"><div className="iv-headrow"><div><h1>Invitations</h1><p className="sub">Each invitation creates exactly one new account.</p></div></div><div className="iv-inv-card"><PlaceholderRows/></div></section>;
}
export default function OrgInvitesPage() {
  const { user, can } = useAuth(), actor = user?.profile?.sub;
  if (typeof actor !== 'string' || !actor) return <InvitesSkeleton/>;
  return <InvitationTimeProvider key={actor}><InvitationsWorkspace actor={actor} canCreate={can('org.invites.create')}/></InvitationTimeProvider>;
}
function InvitationsWorkspace({ actor, canCreate }) {
  const { model, engine } = useInvitationList(), time = useInvitationTime();
  const initialDraft = useRef(undefined);
  if (initialDraft.current === undefined) { try { initialDraft.current = readInvitationDraft(sessionStorage, actor); } catch { initialDraft.current = null; } }
  const [creating, setCreating] = useState(() => !!initialDraft.current), [revoking, setRevoking] = useState(null), [widthVersion, setWidthVersion] = useState(0);
  const list = useRef(null), floor = useRef({ key: '', height: 0, width: 0 }), modalOpen = useRef(false);
  modalOpen.current = creating || !!revoking;
  const committed = model.data, cohort = model.committedQuery ? cohortKey(model.committedQuery) : '';
  useLayoutEffect(() => {
    const node = list.current; if (!node || !committed) return;
    const width = Math.round(node.getBoundingClientRect().width), key = cohort + '|' + width;
    if (floor.current.key !== key) floor.current = { key, height: 0, width };
    if (committed.items.length === committed.pageSize) {
      const natural = [...node.children].reduce((n, row) => {
        const details = row.querySelector('.iv-inv-details'); return n + row.getBoundingClientRect().height - (details?.getBoundingClientRect().height || 0);
      }, 0);
      floor.current.height = Math.max(floor.current.height, Math.ceil(natural));
    }
    node.style.minHeight = floor.current.height && committed.items.length ? floor.current.height + 'px' : '';
  }, [committed, cohort, widthVersion]);
  useEffect(() => {
    const observer = new ResizeObserver(() => { const width = Math.round(list.current?.getBoundingClientRect().width || 0); if (width && floor.current.width !== width) { floor.current.width = width; setWidthVersion((v) => v + 1); } });
    observer.observe(list.current); return () => observer.disconnect();
  }, []);
  useEffect(() => { if (model.overlay) time.close(); }, [model.overlay]);
  useEffect(() => {
    const timer = setInterval(() => {
      if (document.visibilityState !== 'visible' || modalOpen.current) return;
      const current = engine.current?.getState();
      if (!current || current.pending || !current.data) return;
      if (current.data.items.some((v) => ['queued', 'sending'].includes(v.mail.state))) engine.current.refresh({ quiet: true });
    }, 2000);
    const clock = setInterval(() => {
      window.dispatchEvent(new Event('invitation-clock'));
      const current = engine.current?.getState();
      if (document.visibilityState === 'visible' && !modalOpen.current && !current?.pending
        && current?.data?.items.some((v) => v.status === 'active' && Date.now() >= v.expiresAt)) engine.current.refresh({ quiet: true });
    }, 15000);
    return () => { clearInterval(timer); clearInterval(clock); };
  }, [engine]);
  const update = (patch, options) => { time.close(); engine.current?.update(patch, options); };
  const page = (number) => {
    const current = engine.current?.getState();
    if (!current?.data || !Number.isInteger(number) || number < 1 || number > current.data.pages || number === current.query.page) return;
    update({ page: number });
  };
  const mutate = useCallback(async (kind, invite, body = {}) => {
    time.close(); engine.current?.invalidate(); let operation;
    try {
      operation = await mutationRequest(actor, kind, invite?.id, body);
      const result = kind === 'create' ? await createInvitation({ ...body, request_id: operation.id })
        : kind === 'resend' ? await resendInvitation(invite.id, operation.id) : await revokeInvitation(invite.id, operation.id);
      settleOperation(operation); engine.current?.refresh(); return result;
    } catch (error) {
      settleOperation(operation, error);
      if (!authInterruption(error) && ['already_used', 'invitation_used', 'invitation_revoked', 'invitation_expired', 'invitation_gone'].includes(error.code)) engine.current?.refresh({ quiet: true });
      throw error;
    }
  }, [actor, engine, time.close]);
  const caption = model.query.status === 'current' ? 'Waiting to be used. Email status is shown separately — an invitation stays valid even if a send failed.'
    : model.query.status === 'history' ? 'Finished invitation records are retained. Nothing can be deleted from this view.' : 'All invitations, including finished records. Email status is separate from invitation status.';
  return <section className="iv-ui iv-page">
    <div className="iv-headrow"><div><h1>Invitations</h1><p className="sub">Each invitation creates exactly one new account.</p></div>
      {canCreate && <button type="button" className="iv-btn iv-btn-primary iv-new-btn" onClick={() => { time.close(); setCreating(true); }}><InvitationIcon name="plus" className="iv-ico-14"/>New invitation</button>}</div>
    <div className="iv-filterrow"><div className="iv-seg" role="group" aria-label="Show invitations">{['all', 'current', 'history'].map((status) => <button type="button" key={status} aria-pressed={model.query.status === status} onClick={() => update({ status, page: 1 })}>
      {status[0].toUpperCase() + status.slice(1)}<span className="iv-n">{committed?.counts[status]?.toLocaleString() ?? '—'}</span></button>)}</div></div>
    <div className="iv-list-toolbar"><label className="iv-search-field"><span className="iv-sr-only">Search invitations</span><input className="iv-input" type="search" autoComplete="off" maxLength={100} placeholder="Search code, email, note or record ID" value={model.query.query}
      onChange={(e) => update({ query: e.target.value, page: 1 }, { debounce: true })}/></label>
      <InvitationPicker label="Sort invitations" value={model.query.sort + ':' + model.query.order} options={SORTS} onChange={(value) => { const [sort, order] = value.split(':'); update({ sort, order, page: 1 }); }}/>
      <InvitationPicker label="Invitations per page" value={String(model.query.pageSize)} options={SIZES} onChange={(value) => update({ pageSize: Number(value), page: 1 })}/>
    </div>
    <p className="iv-filter-cap">{caption}</p>
    <InvitationPager position="top" data={committed} wantedPage={model.query.page} onPage={page}/>
    <p className={'iv-list-feedback' + (model.error ? ' iv-bad' : '')} role="status" aria-live="polite">{model.error ? <>{invitationError(model.error)}<button type="button" className="iv-btn" onClick={() => engine.current?.refresh()}>Retry</button></> : ''}</p>
    <div className="iv-inv-card" data-loading={model.overlay} aria-busy={model.pending}>
      <div ref={list} role="list" aria-label="Invitations" inert={model.overlay || !!model.error}>
        {!committed ? <PlaceholderRows/> : committed.items.length ? committed.items.map((invite) => <InvitationRow key={invite.id} invite={invite} onResend={(v) => mutate('resend', v)} onRevoke={setRevoking}/>) : <div className="iv-inv-empty">{model.query.query ? 'No invitations match this search.' : 'No invitations in this filter.'}</div>}
      </div>
      <div className="iv-list-loading-mask" aria-hidden="true"><div className="iv-list-loading-track"><span className="iv-list-loading-runner"/></div></div>
    </div>
    <InvitationPager position="bottom" data={committed} wantedPage={model.query.page} onPage={page}/>
    {creating && <CreateInvitationDialog actor={actor} initialForm={initialDraft.current} onClose={() => { initialDraft.current = null; setCreating(false); }} onCreate={(body) => mutate('create', null, body)}/>}
    {revoking && <RevokeInvitationDialog invite={revoking} onClose={() => setRevoking(null)} onRevoke={(invite) => mutate('revoke', invite)}/>}
  </section>;
}
