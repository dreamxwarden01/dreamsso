import { useCallback, useEffect, useState } from 'react';
import { useAuth } from '../../context/AuthContext.jsx';
import { orgApi } from '../../api.js';
import Icon from '../../components/Icon.jsx';
import Modal from '../../components/Modal.jsx';
import { Ph, Skeleton } from '../../components/Skeleton.jsx';
import SaveBar from '../../components/SaveBar.jsx';
import { toast } from '../../components/Toast.jsx';

// Pane skeleton (also used by the org gate): static chrome for real, only
// the role rows shimmer.
export function RolesSkeleton() {
  return (
    <>
      <h1>Roles</h1>
      <p className="sub">Organization roles — smaller level = higher privilege, one per user.</p>
      <div className="card">
        {Array.from({ length: 4 }).map((_, i) => (
          <div className="row" key={i}>
            <p className="row-title" style={{ margin: 0, minWidth: 140 }}><Ph w={110 - i * 10} /></p>
            <p className="k" style={{ margin: 0, fontSize: 12 }}><Ph w={130} /></p>
          </div>
        ))}
      </div>
    </>
  );
}

// Org roles: multi-badge rows (system = undeletable; default = singular,
// movable), then the selected role's permission matrix + per-app defaults.
// Everything at-or-above the actor renders view-only.
export default function OrgRolesPage() {
  const { can } = useAuth();
  const [list, setList] = useState(null);
  const [sel, setSel] = useState(null); // slug
  const [detail, setDetail] = useState(null);
  const [err, setErr] = useState(null);
  const [creating, setCreating] = useState(false);

  const loadList = useCallback(() => orgApi('GET', '/roles').then((d) => {
    setList(d);
    setSel((cur) => cur ?? d.roles[0]?.slug ?? null);
  }).catch((e) => { if (e.message !== 'unauthenticated') setErr(e.code || 'error'); }), []);
  // keep=true refreshes IN PLACE after an action (no skeleton teardown);
  // switching roles still starts from the skeleton.
  const loadDetail = useCallback((slug, keep = false) => {
    if (!keep) setDetail(null);
    if (slug) orgApi('GET', '/roles/' + slug).then(setDetail).catch(() => setDetail(null));
  }, []);
  useEffect(() => { loadList(); }, [loadList]);
  useEffect(() => { loadDetail(sel); }, [sel, loadDetail]);

  const act = async (fn, okMsg) => {
    try {
      await fn();
      if (okMsg) toast.success(okMsg);
      await loadList();
      loadDetail(sel, true);
    } catch (e) {
      // step_up_required is handled by OrgGate's overlay re-verify (the sudo
      // window expired) — don't also flash a raw error toast.
      if (e.message !== 'unauthenticated' && e.code !== 'step_up_required') {
        const it = e.data?.item; // batch endpoints name the item that failed validation
        toast.error(`Couldn't save. [${e.code || 'error'}${it ? ` — ${it.key || it.client || it.type}` : ''}]`);
      }
    }
  };

  if (err && !list) return (<><h1>Roles</h1><p className="err">Couldn't load roles. [{err}]</p></>);
  if (!list) return <RolesSkeleton />;

  return (
    <>
      <h1>Roles</h1>
      <p className="sub">Organization roles — smaller level = higher privilege, one per user.</p>
      {err && <p className="err">Failed. [{err}]</p>}

      <div className="card" style={{ marginBottom: 14 }}>
        {list.roles.map((r) => (
          <div key={r.slug} className="row" style={{ cursor: 'pointer', background: sel === r.slug ? 'var(--blue-bg)' : undefined }}
            onClick={() => setSel(r.slug)}>
            <p className="row-title" style={{ margin: 0, minWidth: 140 }}>{r.label}</p>
            <p className="k" style={{ margin: 0, fontSize: 12 }}>level {r.level} · {r.members} member{r.members === 1 ? '' : 's'}</p>
            <span style={{ flex: 1 }} />
            {r.is_system && <span className="pill">system</span>}
            {r.slug === list.default_role && <span className="pill pill-ok">default</span>}
            {!r.editable && <span className="pill">view only</span>}
          </div>
        ))}
      </div>
      {can('org.roles.create') && (
        <div className="form-actions" style={{ marginBottom: 18 }}>
          <button className="btn btn-primary" onClick={() => setCreating(true)}><Icon name="plus" size={15} /> New role</button>
        </div>
      )}

      {sel && !detail && (
        <>
          <h2 className="section">Settings</h2>
          <div className="card pad"><div className="form">
            <label className="field"><span>Label</span><Skeleton w={360} h={36} r={8} /></label>
            <label className="field"><span>Level</span><Skeleton w={120} h={36} r={8} /></label>
          </div></div>
        </>
      )}
      {detail && <RoleDetail detail={detail} defaultRole={list.default_role} can={can} act={act} onDeleted={() => { setSel(null); loadList(); }} />}
      {creating && <CreateRoleModal onClose={() => setCreating(false)} onCreated={(slug) => { setCreating(false); loadList().then(() => setSel(slug)); }} />}
    </>
  );
}

function RoleDetail({ detail, defaultRole, can, act, onDeleted }) {
  const r = detail.role;
  const [label, setLabel] = useState(r.label);
  const [level, setLevel] = useState(String(r.level));
  // Staged app-defaults + permission changes -> ONE batch save; label/level
  // is separate role metadata with its own inline Save.
  const [pend, setPend] = useState({ permissions: {}, app_defaults: {} });
  const [busy, setBusy] = useState(false);
  useEffect(() => { setLabel(r.label); setLevel(String(r.level)); setPend({ permissions: {}, app_defaults: {} }); }, [detail]);
  const groups = [...new Set(detail.permissions.map((x) => x.group))];
  const appName = (app, id) => (id == null ? 'No access' : app.roles.find((x) => x.role_id === id)?.name ?? '#' + id);

  const stagePerm = (key, effect, orig) => setPend((c) => {
    const next = { ...c, permissions: { ...c.permissions } };
    if (effect === orig) delete next.permissions[key]; else next.permissions[key] = effect;
    return next;
  });
  const stageApp = (cid, val, orig) => setPend((c) => {
    const next = { ...c, app_defaults: { ...c.app_defaults } };
    if (val === orig) delete next.app_defaults[cid]; else next.app_defaults[cid] = val;
    return next;
  });

  const items = [];
  for (const [k, v] of Object.entries(pend.permissions)) items.push({ label: k.split('.').slice(-2).join('.'), value: v });
  for (const [cid, v] of Object.entries(pend.app_defaults)) {
    const app = detail.apps.find((x) => x.client_id === cid);
    items.push({ label: cid, value: v === 'inherit' ? 'inherit' : v === null ? 'No access' : app ? appName(app, v) : String(v) });
  }

  const saveAccess = async () => {
    setBusy(true);
    const body = {};
    if (Object.keys(pend.permissions).length) body.permissions = pend.permissions;
    if (Object.keys(pend.app_defaults).length) body.app_defaults = pend.app_defaults;
    // "pushed to apps", not "members notified" — the diff rides the event
    // channel to the affected applications; nobody gets an email.
    await act(() => orgApi('POST', `/roles/${r.slug}/access`, body), 'Role access saved — changes pushed to apps.');
    setBusy(false);
  };

  return (
    <>
      <h2 className="section">{r.label} — settings</h2>
      <div className="card pad">
        <div className="form">
          <label className="field"><span>Label</span>
            <input className="input wide" value={label} disabled={!r.editable || !can('org.roles.edit.rename')}
              onChange={(e) => setLabel(e.target.value)} />
          </label>
          <label className="field"><span>Level</span>
            <input className="input" style={{ width: 120 }} inputMode="numeric" value={level}
              disabled={!r.editable || !can('org.roles.edit.level')}
              onChange={(e) => setLevel(e.target.value.replace(/\D/g, ''))} />
            <span className="fhint">Smaller = higher privilege; must stay below your own level.</span>
          </label>
          <div className="form-actions">
            <button className="btn btn-primary"
              disabled={!r.editable || (label === r.label && level === String(r.level))}
              onClick={() => {
                const body = {};
                if (label !== r.label) body.label = label;
                if (level !== String(r.level)) body.level = Number(level);
                act(() => orgApi('PATCH', '/roles/' + r.slug, body), 'Role saved.');
              }}>
              Save
            </button>
            {can('org.roles.edit.default') && r.slug !== defaultRole && r.editable && (
              <button className="btn" onClick={() => act(() => orgApi('PUT', '/roles-default', { slug: r.slug }), 'Default role moved.')}>
                Make default
              </button>
            )}
            {can('org.roles.remove') && !r.is_system && r.editable && (
              <button className="btn btn-danger"
                onClick={() => act(() => orgApi('DELETE', '/roles/' + r.slug), 'Role deleted.').then(onDeleted)}>
                Delete
              </button>
            )}
          </div>
        </div>
        {r.is_system && <p className="fhint" style={{ margin: '12px 0 0' }}>System role: can&rsquo;t be deleted.</p>}
      </div>

      {detail.apps.length > 0 && (
        <>
          <h2 className="section">App defaults</h2>
          <div className="card">
            {detail.apps.map((app) => {
              const orig = app.org_default ? (app.org_default.role_id === null ? 'null' : String(app.org_default.role_id)) : 'inherit';
              const staged = pend.app_defaults[app.client_id];
              const cur = staged === undefined ? orig : staged === 'inherit' ? 'inherit' : staged === null ? 'null' : String(staged);
              return (
                <div className="row" key={app.client_id}>
                  <p className="k" style={{ minWidth: 120 }}>{app.name || app.client_id}</p>
                  {app.editable && can('org.roles.edit.permissions.app') ? (
                    <select className={'input fit' + (staged !== undefined ? ' staged' : '')}
                      value={cur}
                      onChange={(e) => {
                        const v = e.target.value;
                        const value = v === 'inherit' ? 'inherit' : v === 'null' ? null : Number(v);
                        const origValue = orig === 'inherit' ? 'inherit' : orig === 'null' ? null : Number(orig);
                        stageApp(app.client_id, value, origValue);
                      }}>
                      <option value="inherit">Inherit — {appName(app, app.catalog_default)} (app default)</option>
                      {app.roles.filter((x) => app.actor_level == null || x.level >= app.actor_level).map((x) => (
                        <option key={x.role_id} value={String(x.role_id)}>{x.name} (level {x.level})</option>
                      ))}
                      <option value="null">No access</option>
                    </select>
                  ) : (
                    <p className="k" style={{ margin: 0 }}>
                      {app.org_default ? appName(app, app.org_default.role_id) : `Inherit — ${appName(app, app.catalog_default)}`}
                      {!app.editable && <span className="fhint"> · view only</span>}
                    </p>
                  )}
                </div>
              );
            })}
          </div>
        </>
      )}

      <h2 className="section">Default permissions</h2>
      {groups.map((g) => (
        <div key={g}>
          <p className="k" style={{ fontSize: 12, margin: '8px 2px 6px', textTransform: 'uppercase', letterSpacing: '.03em' }}>{g}</p>
          <div className="card" style={{ marginBottom: 10 }}>
            {detail.permissions.filter((x) => x.group === g).map((perm) => {
              const staged = pend.permissions[perm.key];
              return (
                <div className="row" key={perm.key}>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <p className="row-title mono" style={{ margin: 0, fontSize: 12.5 }}>{perm.key}</p>
                    {perm.description && <p className="k" style={{ margin: 0, fontSize: 11.5 }}>{perm.description}</p>}
                  </div>
                  {perm.editable && can('org.roles.edit.permissions.acctPortal') ? (
                    <select className={'input fit' + (staged !== undefined ? ' staged' : '')}
                      value={staged ?? perm.effect}
                      onChange={(e) => stagePerm(perm.key, e.target.value, perm.effect)}>
                      <option value="grant">Grant</option>
                      <option value="deny">Deny</option>
                    </select>
                  ) : (
                    <span className="pill" title={perm.editable ? '' : "You don't hold this permission or the role outranks you"}>
                      {perm.effect}{perm.editable ? '' : ' · locked'}
                    </span>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      ))}
      <SaveBar items={items} busy={busy}
        onSave={saveAccess}
        onDiscard={() => setPend({ permissions: {}, app_defaults: {} })} />
    </>
  );
}

function CreateRoleModal({ onClose, onCreated }) {
  const [f, setF] = useState({ slug: '', label: '', level: '' });
  const [errs, setErrs] = useState({});
  const [busy, setBusy] = useState(false);
  const ready = /^[a-z][a-z0-9_-]{1,39}$/.test(f.slug) && f.label.trim() && /^\d{1,4}$/.test(f.level);
  const submit = async () => {
    setBusy(true);
    try {
      await orgApi('POST', '/roles', { slug: f.slug, label: f.label.trim(), level: Number(f.level) });
      onCreated(f.slug);
    } catch (e) {
      if (e.message !== 'unauthenticated') setErrs(e.data?.errors ?? { _: e.code || 'error' });
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal title="New role" onClose={onClose}>
      <div className="form">
        <label className="field"><span>Slug</span>
          <input className="input" value={f.slug} autoCapitalize="none"
            onChange={(e) => setF({ ...f, slug: e.target.value.toLowerCase().replace(/[^a-z0-9_-]/g, '') })} />
          <span className={'fhint' + (errs.slug ? ' bad' : '')}>{errs.slug || 'lowercase letters, digits, - and _ (2-40)'}</span>
        </label>
        <label className="field"><span>Label</span>
          <input className="input" value={f.label} onChange={(e) => setF({ ...f, label: e.target.value })} />
          {errs.label && <span className="fhint bad">{errs.label}</span>}
        </label>
        <label className="field"><span>Level</span>
          <input className="input" style={{ width: 120 }} inputMode="numeric" value={f.level}
            onChange={(e) => setF({ ...f, level: e.target.value.replace(/\D/g, '') })} />
          <span className={'fhint' + (errs.level ? ' bad' : '')}>{errs.level || 'smaller = higher privilege; must be below your own'}</span>
        </label>
        <p className="fhint">Starts with the default role&rsquo;s permissions and app roles — tune them after.</p>
        {errs._ && <p className="err">Couldn't create. [{errs._}]</p>}
        <div className="modal-actions">
          <button className="btn btn-primary" disabled={!ready || busy} onClick={submit}>{busy ? 'Creating…' : 'Create role'}</button>
          <button className="btn" onClick={onClose} disabled={busy}>Cancel</button>
        </div>
      </div>
    </Modal>
  );
}
