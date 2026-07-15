import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext.jsx';
import { orgApi, avatarUrl } from '../../api.js';
import Icon from '../../components/Icon.jsx';
import Modal from '../../components/Modal.jsx';
import PasswordRules, { passwordValid } from '../../components/PasswordRules.jsx';
import { Ph } from '../../components/Skeleton.jsx';
import { initials } from '../../components/Avatar.jsx';

// Page size = how many rows fit between the card top and the reserved pager
// strip, measured from the real DOM (skeleton rows share the live rows'
// structure, so either is a valid probe). The gate-level skeleton uses the
// same hook, so its row count matches what the page will render.
const RESERVED_BELOW = 78; // card margin + pager + content bottom padding
export function useFitRows() {
  const cardRef = useRef(null);
  const [pageSize, setPageSize] = useState(() =>
    Math.max(4, Math.min(50, Math.floor((window.innerHeight - 240) / 64))));
  const [measured, setMeasured] = useState(false);
  useLayoutEffect(() => {
    const compute = () => {
      const card = cardRef.current;
      if (!card) return;
      const rowH = card.querySelector('.row')?.getBoundingClientRect().height || 64;
      const avail = window.innerHeight - card.getBoundingClientRect().top - RESERVED_BELOW;
      setPageSize(Math.max(4, Math.min(50, Math.floor(avail / rowH))));
      setMeasured(true);
    };
    compute();
    let t;
    const onResize = () => { clearTimeout(t); t = setTimeout(compute, 150); };
    window.addEventListener('resize', onResize);
    return () => { clearTimeout(t); window.removeEventListener('resize', onResize); };
  }, []);
  return { cardRef, pageSize, measured };
}

function PlaceholderCard({ cardRef, count }) {
  return (
    <div className="card" ref={cardRef}>
      {Array.from({ length: count }).map((_, i) => (
        <div className="row" key={i}>
          <span className="skeleton" style={{ width: 32, height: 32, borderRadius: '50%', flexShrink: 0 }} />
          <div style={{ flex: 1, minWidth: 0 }}>
            <p className="row-title" style={{ margin: 0 }}><Ph w={140 + ((i * 37) % 60)} /></p>
            <p className="k" style={{ margin: 0, fontSize: 12 }}><Ph w={100 + ((i * 23) % 50)} /></p>
          </div>
        </div>
      ))}
    </div>
  );
}

// Full-pane placeholder for the org gate: same chrome + a fitted placeholder
// card, so gate-loading and page-loading paint the same pixels.
export function UsersSkeleton() {
  const { can } = useAuth();
  const { cardRef, pageSize } = useFitRows();
  return (
    <>
      <h1>Users</h1>
      <p className="sub">Everyone at your privilege level or below — open a user to manage them.</p>
      <div style={{ display: 'flex', gap: 10, marginBottom: 12 }}>
        <input className="input grow" style={{ flex: 1, minWidth: 0 }} placeholder="Search name, username, or email" defaultValue="" readOnly />
        {can('org.users.create') && (
          <button className="btn btn-primary"><Icon name="plus" size={15} /> New user</button>
        )}
      </div>
      <PlaceholderCard cardRef={cardRef} count={pageSize} />
    </>
  );
}

// Sorted by privilege (level asc), then display name, then sub — the server
// enforces visibility (same-or-lower only) and editability (strictly lower).
// Equal-level rows and yourself render normally, just without the chevron.
export default function OrgUsersPage() {
  const { can } = useAuth();
  const nav = useNavigate();
  // `data` is sticky across page flips so the pager window stays rendered and
  // the skeleton knows exactly how many rows the incoming page will have.
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [query, setQuery] = useState('');
  const [page, setPage] = useState(1); // 1-based
  const [err, setErr] = useState(null);
  const [creating, setCreating] = useState(false);
  const { cardRef, pageSize, measured } = useFitRows();

  const load = useCallback((q, pg, size) => {
    setLoading(true);
    const params = new URLSearchParams({ limit: String(size), offset: String((pg - 1) * size) });
    if (q) params.set('query', q);
    orgApi('GET', '/users?' + params.toString())
      .then((d) => { setData(d); setErr(null); setLoading(false); })
      .catch((e) => { if (e.message !== 'unauthenticated') { setErr(e.code || 'error'); setLoading(false); } });
  }, []);
  // A new search resets to page 1; page changes reload in place. The first
  // fetch waits for the measured fit so we never load a size we won't show.
  useEffect(() => {
    if (!measured) return undefined;
    const t = setTimeout(() => load(query.trim(), page, pageSize), query && page === 1 ? 250 : 0);
    return () => clearTimeout(t);
  }, [query, page, pageSize, measured, load]);
  const onSearch = (v) => { setQuery(v); setPage(1); };

  // A resize that changes the fit re-pages so the first visible row stays put.
  const prevSize = useRef(null);
  useEffect(() => {
    const prev = prevSize.current;
    prevSize.current = pageSize;
    if (prev && prev !== pageSize) setPage((cur) => Math.floor(((cur - 1) * prev) / pageSize) + 1);
  }, [pageSize]);

  const total = data?.total ?? 0;
  const pages = Math.max(1, Math.ceil(total / pageSize));
  const pageNums = (() => {
    const set = new Set([1, pages, page, page - 1, page + 1]);
    return [...set].filter((n) => n >= 1 && n <= pages).sort((a, b) => a - b);
  })();

  const Row = (u) => (
    <div
      key={u.sub} className="row"
      style={{ cursor: u.editable ? 'pointer' : 'default' }}
      onClick={() => u.editable && nav('/organization/users/' + u.sub)}
    >
      {u.avatar ? (
        <img className="av-sm av-list" src={avatarUrl(u.avatar)} alt="" />
      ) : (
        <span className="av-sm av-list">{initials(u.display_name || u.username)}</span>
      )}
      <div style={{ flex: 1, minWidth: 0 }}>
        <p className="row-title" style={{ margin: 0 }}>
          {u.display_name || u.username}
          {u.me && <span className="pill" style={{ marginLeft: 8 }}>you</span>}
          {u.status !== 'active' && <span className="pill pill-warn" style={{ marginLeft: 8 }}>suspended</span>}
        </p>
        {/* role now lives where the email used to; email + MFA badges dropped */}
        <p className="k" style={{ margin: 0, fontSize: 12 }}>{u.username} · {u.role ? u.role.label : 'no role'}</p>
      </div>
      {u.editable && <Icon name="chevron" size={16} className="text-faint" />}
    </div>
  );

  return (
    <>
      <h1>Users</h1>
      <p className="sub">Everyone at your privilege level or below — open a user to manage them.</p>

      <div style={{ display: 'flex', gap: 10, marginBottom: 12 }}>
        <input
          className="input grow" style={{ flex: 1, minWidth: 0 }}
          placeholder="Search name, username, or email"
          value={query} onChange={(e) => onSearch(e.target.value)}
        />
        {can('org.users.create') && (
          <button className="btn btn-primary" onClick={() => setCreating(true)}>
            <Icon name="plus" size={15} /> New user
          </button>
        )}
      </div>
      {err && <p className="err">Couldn't load users. [{err}]</p>}

      {/* loading: the card + pager stay; placeholder rows mirror the REAL row
          structure (same elements -> same heights) and match the count the
          incoming page will actually have */}
      {loading && !err && (
        <PlaceholderCard
          cardRef={cardRef}
          count={data ? Math.min(pageSize, Math.max(1, (data.total ?? pageSize) - (page - 1) * pageSize)) : pageSize}
        />
      )}

      {!loading && data && (
        <div className="card" ref={cardRef}>
          {data.users.length === 0 && <div className="row"><p className="k">No matches.</p></div>}
          {data.users.map(Row)}
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

      {creating && <CreateUserModal onClose={() => setCreating(false)} onCreated={(sub) => nav('/organization/users/' + sub)} />}
    </>
  );
}

// videosite's AddUserModal, ported: decoy field absorbs credential autofill
// (hidden via position/opacity, not display:none), autocomplete off /
// one-time-code everywhere — an admin's browser must never offer to save
// someone else's password.
function CreateUserModal({ onClose, onCreated }) {
  const [f, setF] = useState({ username: '', display_name: '', email: '', password: '', confirm: '', org_role: '' });
  const [roles, setRoles] = useState(null);
  const [errs, setErrs] = useState({});
  const [busy, setBusy] = useState(false);
  const [topErr, setTopErr] = useState(null);
  const set = (patch) => { setF((cur) => ({ ...cur, ...patch })); setTopErr(null); };

  useEffect(() => {
    orgApi('GET', '/roles')
      .then((d) => {
        const assignable = d.roles.filter((r) => r.editable); // strictly below the actor
        setRoles(assignable);
        setF((cur) => ({ ...cur, org_role: d.default_role && assignable.some((r) => r.slug === d.default_role) ? d.default_role : (assignable[0]?.slug ?? '') }));
      })
      .catch(() => setRoles([]));
  }, []);

  const ready =
    /^[A-Za-z0-9_-]{3,20}$/.test(f.username) && f.display_name.trim() &&
    (!f.email || /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(f.email)) &&
    passwordValid(f.password) && f.confirm === f.password && f.org_role;

  const submit = async () => {
    if (!ready || busy) return;
    setBusy(true);
    try {
      const d = await orgApi('POST', '/users', {
        username: f.username.trim(), display_name: f.display_name.trim(),
        email: f.email.trim() || undefined, password: f.password, org_role: f.org_role,
      });
      onCreated(d.sub);
    } catch (e) {
      if (e.message === 'unauthenticated') return;
      if (e.data?.errors) setErrs(e.data.errors);
      else setTopErr(e.code || 'error');
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal title="New user" onClose={onClose}>
      <div style={{ position: 'absolute', opacity: 0, height: 0, width: 0, overflow: 'hidden' }} aria-hidden="true">
        <input type="text" name="fake_user_trap" autoComplete="username" tabIndex={-1} />
      </div>
      <div className="form">
        <label className="field"><span>Username</span>
          <input className={'input' + (errs.username ? ' bad' : '')} autoComplete="one-time-code" autoCapitalize="none"
            value={f.username} onChange={(e) => { set({ username: e.target.value.replace(/\s/g, '') }); setErrs((c) => ({ ...c, username: null })); }} />
          <span className="fhint">3-20 characters: letters, digits, - and _{errs.username ? ` — ${errs.username}` : ''}</span>
        </label>
        <label className="field"><span>Display name</span>
          <input className={'input' + (errs.display_name ? ' bad' : '')} autoComplete="one-time-code" value={f.display_name}
            onChange={(e) => { set({ display_name: e.target.value }); setErrs((c) => ({ ...c, display_name: null })); }} />
          {errs.display_name && <span className="fhint bad">{errs.display_name}</span>}
        </label>
        <label className="field"><span>Email (optional)</span>
          <input className={'input' + (errs.email ? ' bad' : '')} autoComplete="one-time-code" value={f.email}
            onChange={(e) => { set({ email: e.target.value.replace(/\s/g, '') }); setErrs((c) => ({ ...c, email: null })); }} />
          {errs.email && <span className="fhint bad">{errs.email}</span>}
        </label>
        <label className="field"><span>Organization role</span>
          <select className="input" value={f.org_role}
            onChange={(e) => { set({ org_role: e.target.value }); setErrs((c) => ({ ...c, org_role: null })); }}>
            {(roles ?? []).map((r) => <option key={r.slug} value={r.slug}>{r.label} (level {r.level})</option>)}
          </select>
          {errs.org_role && <span className="fhint bad">{errs.org_role}</span>}
        </label>
        {/* autoComplete="off" (videosite's AddUserModal): new-password would
            invite the browser's save/generate UI for SOMEONE ELSE'S password */}
        <label className="field"><span>Password</span>
          <input className="input" type="password" autoComplete="off" value={f.password}
            onChange={(e) => { set({ password: e.target.value.replace(/\s/g, '') }); setErrs((c) => ({ ...c, password: null })); }} />
          <PasswordRules password={f.password} />
          {errs.password && <span className="fhint bad">{errs.password}</span>}
        </label>
        <label className="field"><span>Confirm password</span>
          <input className="input" type="password" autoComplete="off" value={f.confirm}
            onChange={(e) => set({ confirm: e.target.value.replace(/\s/g, '') })} />
          {f.confirm && f.confirm !== f.password && <span className="fhint bad">Passwords do not match.</span>}
        </label>
        {topErr && <p className="err">Couldn't create the user. [{topErr}]</p>}
        <div className="modal-actions">
          <button className="btn btn-primary" disabled={!ready || busy} onClick={submit}>
            {busy ? 'Creating…' : 'Create user'}
          </button>
          <button className="btn" onClick={onClose} disabled={busy}>Cancel</button>
        </div>
      </div>
    </Modal>
  );
}
