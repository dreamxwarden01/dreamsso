import { useCallback, useEffect, useRef, useState } from 'react';
import { useAuth } from '../../context/AuthContext.jsx';
import { orgApi } from '../../api.js';
import Icon from '../../components/Icon.jsx';
import Modal from '../../components/Modal.jsx';
import { Ph } from '../../components/Skeleton.jsx';
import { toast } from '../../components/Toast.jsx';
import { fmtAgo } from '../../format.js';
import { useFitRows } from './OrgUsersPage.jsx';

// Invitation codes: live codes + consumed records in one paginated list
// (page size fits the viewport, same hook as Users). Status states are
// distinct: Active / Used (permanent record) / Voided (kept 24h) / Expired
// (kept 24h past expiry). Create picks the invited org role (strictly below
// the creator) + validity; the result modal centers the code and offers the
// prefilled /register/start link. Own un-consumed codes are always voidable.
const fmtWhen = (iso) =>
  new Date(iso).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });

const VALIDITY = [
  { hours: 24, label: '24 hours' },
  { hours: 72, label: '3 days' },
  { hours: 168, label: '7 days' },
  { hours: 720, label: '30 days' },
];

function PlaceholderRows({ cardRef, count }) {
  return (
    <div className="card" ref={cardRef}>
      {Array.from({ length: count }).map((_, i) => (
        <div className="row" key={i}>
          <p className="row-title mono" style={{ margin: 0, minWidth: 150 }}><Ph w={120} /></p>
          <p className="k" style={{ margin: 0, fontSize: 12, flex: 1 }}><Ph w={190 + ((i * 31) % 60)} /></p>
          <span className="skeleton" style={{ width: 56, height: 20, borderRadius: 99 }} />
        </div>
      ))}
    </div>
  );
}

// Pane skeleton (also used by the org gate): static chrome for real, fitted rows shimmer.
export function InvitesSkeleton() {
  const { can } = useAuth();
  const { cardRef, pageSize } = useFitRows();
  return (
    <>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <h1 style={{ flex: 1 }}>Invitations</h1>
        {can('org.invites.create') && (
          <button className="btn btn-primary"><Icon name="plus" size={15} /> Create code</button>
        )}
      </div>
      <p className="sub">Invitation codes for new accounts — consumed codes stay on record.</p>
      <PlaceholderRows cardRef={cardRef} count={pageSize} />
    </>
  );
}

export default function OrgInvitesPage() {
  const { can } = useAuth();
  // `data` is sticky across page flips (pager stays; skeleton count matches).
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1); // 1-based
  const [err, setErr] = useState(null);
  const [creating, setCreating] = useState(false);
  const [created, setCreated] = useState(null); // { code, expires_at, invited_role }
  const [voiding, setVoiding] = useState(null); // code pending confirm
  const [busy, setBusy] = useState(false);
  const { cardRef, pageSize, measured } = useFitRows();

  const load = useCallback((pg, size) => {
    setLoading(true);
    orgApi('GET', `/invites?limit=${size}&offset=${(pg - 1) * size}`)
      .then((d) => { setData(d); setErr(null); setLoading(false); })
      .catch((e) => { if (e.message !== 'unauthenticated') { setErr(e.code || 'error'); setLoading(false); } });
  }, []);
  useEffect(() => {
    if (measured) load(page, pageSize);
  }, [page, pageSize, measured, load]);

  // A resize that changes the fit re-pages so the first visible row stays put.
  const prevSize = useRef(null);
  useEffect(() => {
    const prev = prevSize.current;
    prevSize.current = pageSize;
    if (prev && prev !== pageSize) setPage((cur) => Math.floor(((cur - 1) * prev) / pageSize) + 1);
  }, [pageSize]);

  const reload = () => load(page, pageSize);

  const doVoid = async () => {
    setBusy(true);
    try {
      await orgApi('DELETE', '/invites/' + voiding);
      toast.success('Invitation code voided.');
      setVoiding(null);
      reload();
    } catch (e) {
      if (e.message !== 'unauthenticated') {
        toast.error(e.code === 'already_used'
          ? "Can't void — this code was already used."
          : e.code === 'already_voided'
            ? 'This code was already voided.'
            : `Couldn't void the code. [${e.code || 'error'}]`);
        reload();
      }
      setVoiding(null);
    } finally {
      setBusy(false);
    }
  };

  const total = data?.total ?? 0;
  const pages = Math.max(1, Math.ceil(total / pageSize));
  const pageNums = (() => {
    const set = new Set([1, pages, page, page - 1, page + 1]);
    return [...set].filter((n) => n >= 1 && n <= pages).sort((a, b) => a - b);
  })();

  const now = Date.now();
  const statusOf = (v) => (v.used ? 'used' : v.voided ? 'voided' : Date.parse(v.expires_at) < now ? 'expired' : 'active');

  if (err && !data) return (<><h1>Invitations</h1><p className="err">Couldn't load. [{err}]</p></>);

  return (
    <>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <h1 style={{ flex: 1 }}>Invitations</h1>
        {can('org.invites.create') && (
          <button className="btn btn-primary" onClick={() => setCreating(true)}>
            <Icon name="plus" size={15} /> Create code
          </button>
        )}
      </div>
      <p className="sub">Invitation codes for new accounts — consumed codes stay on record.</p>

      {loading && (
        <PlaceholderRows
          cardRef={cardRef}
          count={data ? Math.min(pageSize, Math.max(1, (data.total ?? pageSize) - (page - 1) * pageSize)) : pageSize}
        />
      )}

      {!loading && data && (
        <div className="card" ref={cardRef}>
          {data.invites.length === 0 && (
            <div style={{ padding: '42px 0', textAlign: 'center' }}>
              <p className="k" style={{ margin: 0 }}>No invitation codes yet.</p>
            </div>
          )}
          {data.invites.map((v) => {
            const st = statusOf(v);
            return (
              <div className="row" key={v.code} style={st !== 'active' ? { opacity: st === 'used' ? 0.75 : 0.55 } : undefined}>
                <p className="row-title mono" style={{ margin: 0, minWidth: 150 }}>{v.code}</p>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <p className="k" style={{ margin: 0, fontSize: 12, overflowWrap: 'anywhere' }}>
                    {v.invited_role ? v.invited_role.label : 'default role'} · by {v.created_by_label} · {fmtAgo(v.created_at)}
                    {st === 'active' && <> · expires {fmtWhen(v.expires_at)}</>}
                    {v.use_count > 1 && st === 'active' && <> · {v.use_count}/3 uses</>}
                  </p>
                  {v.used && (
                    <p className="k" style={{ margin: 0, fontSize: 12 }}>
                      used by <strong>{v.used_username ?? v.used_by}</strong>
                      {v.used_display_name ? ` (${v.used_display_name})` : ''} · {fmtWhen(v.used_at)}
                    </p>
                  )}
                </div>
                {st === 'used' && <span className="pill">Used</span>}
                {st === 'voided' && <span className="pill pill-bad">Voided</span>}
                {st === 'expired' && <span className="pill pill-warn">Expired</span>}
                {st === 'active' && <span className="pill pill-ok">Active</span>}
                {v.can_void && st === 'active' && (
                  <button className="btn btn-danger" onClick={() => setVoiding(v.code)}>Void</button>
                )}
              </div>
            );
          })}
        </div>
      )}

      {data && total > 0 && (
        <div className="pager">
          <span style={{ marginRight: 'auto' }}>
            {(page - 1) * pageSize + 1}–{Math.min(page * pageSize, total)} of {total}
          </span>
          <button className="pbtn" disabled={page === 1} onClick={() => setPage((p) => p - 1)}>‹ Prev</button>
          {pageNums.map((n, i) => (
            <span key={n}>
              {i > 0 && n - pageNums[i - 1] > 1 && <span className="pdots">…</span>}
              <button className={'pnum' + (n === page ? ' on' : '')} onClick={() => setPage(n)}>{n}</button>
            </span>
          ))}
          <button className="pbtn" disabled={page === pages} onClick={() => setPage((p) => p + 1)}>Next ›</button>
        </div>
      )}

      {creating && (
        <CreateInviteModal
          onClose={() => setCreating(false)}
          onCreated={(d) => { setCreating(false); setCreated(d); reload(); }}
        />
      )}
      {created && <InviteResultModal invite={created} onClose={() => setCreated(null)} />}
      {voiding && (
        <Modal title="Void this code?" onClose={() => setVoiding(null)}>
          <p className="modal-msg">
            <span className="mono">{voiding}</span> stops working immediately — any half-finished
            registration using it dies with it. The voided code stays listed for 24 hours.
          </p>
          <div className="modal-actions">
            <button className="btn btn-danger" onClick={doVoid} disabled={busy}>{busy ? 'Voiding…' : 'Void code'}</button>
            <button className="btn" onClick={() => setVoiding(null)} disabled={busy}>Cancel</button>
          </div>
        </Modal>
      )}
    </>
  );
}

function CreateInviteModal({ onClose, onCreated }) {
  const [roles, setRoles] = useState(null);
  const [roleSlug, setRoleSlug] = useState('');
  const [validity, setValidity] = useState(72);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);

  useEffect(() => {
    orgApi('GET', '/roles')
      .then((d) => {
        // Strictly below the creator — the same assignable set as user-create.
        const assignable = d.roles.filter((r) => r.editable);
        setRoles(assignable);
        setRoleSlug(d.default_role && assignable.some((r) => r.slug === d.default_role)
          ? d.default_role
          : (assignable[0]?.slug ?? ''));
      })
      .catch(() => setRoles([]));
  }, []);

  const submit = async () => {
    if (!roleSlug || busy) return;
    setBusy(true);
    setErr(null);
    try {
      const d = await orgApi('POST', '/invites', { role_slug: roleSlug, validity_hours: validity });
      onCreated(d);
    } catch (e) {
      if (e.message !== 'unauthenticated') setErr(e.data?.errors ? Object.values(e.data.errors)[0] : e.code || 'error');
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal title="Create invitation code" onClose={onClose}>
      <div className="form">
        <label className="field"><span>Invited role</span>
          <select className="input fit" value={roleSlug} onChange={(e) => setRoleSlug(e.target.value)}>
            {(roles ?? []).map((r) => <option key={r.slug} value={r.slug}>{r.label} (level {r.level})</option>)}
          </select>
          <span className="fhint">Only roles below your own — the account starts with this role.</span>
        </label>
        <label className="field"><span>Valid for</span>
          <select className="input fit" value={validity} onChange={(e) => setValidity(Number(e.target.value))}>
            {VALIDITY.map((v) => <option key={v.hours} value={v.hours}>{v.label}</option>)}
          </select>
        </label>
        {roles && roles.length === 0 && (
          <p className="fhint bad">No role sits below yours — you can&rsquo;t create invitations.</p>
        )}
        {err && <p className="err">Couldn&rsquo;t create the code. [{err}]</p>}
        <div className="modal-actions">
          <button className="btn btn-primary" onClick={submit} disabled={busy || !roleSlug}>
            {busy ? 'Creating…' : 'Create code'}
          </button>
          <button className="btn" onClick={onClose} disabled={busy}>Cancel</button>
        </div>
      </div>
    </Modal>
  );
}

function InviteResultModal({ invite, onClose }) {
  const [copied, setCopied] = useState(null); // 'code' | 'link'
  const link = `${window.location.origin}/register/start?code=${invite.code}`;
  const copy = async (what, text) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(what);
      setTimeout(() => setCopied(null), 1500);
    } catch { /* clipboard blocked — the code is visible to select manually */ }
  };
  return (
    <Modal title="Invitation code created" onClose={onClose}>
      <p className="modal-msg">
        For a <strong>{invite.invited_role?.label ?? 'default role'}</strong> account ·
        expires {fmtWhen(invite.expires_at)}. Share the link — the code comes prefilled.
      </p>
      <div className="keyfield" style={{ marginBottom: 12 }}>
        <span className="keytext" style={{ letterSpacing: '.14em', textAlign: 'center', fontSize: 17 }}>{invite.code}</span>
      </div>
      <div className="modal-actions">
        <button className="btn btn-primary" onClick={() => copy('link', link)}>
          <Icon name="copy" size={14} /> {copied === 'link' ? 'Copied!' : 'Copy link'}
        </button>
        <button className="btn" onClick={() => copy('code', invite.code)}>
          <Icon name="copy" size={14} /> {copied === 'code' ? 'Copied!' : 'Copy code'}
        </button>
        <button className="btn" onClick={onClose}>Done</button>
      </div>
    </Modal>
  );
}
