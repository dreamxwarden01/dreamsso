import { useCallback, useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext.jsx';
import { orgApi, avatarUrl } from '../../api.js';
import Icon from '../../components/Icon.jsx';
import Modal from '../../components/Modal.jsx';
import ActionChallengeModal from '../../components/ActionChallengeModal.jsx';
import PasswordRules, { passwordValid } from '../../components/PasswordRules.jsx';
import { Ph, Skeleton } from '../../components/Skeleton.jsx';
import { initials } from '../../components/Avatar.jsx';
import SaveBar from '../../components/SaveBar.jsx';
import { toast } from '../../components/Toast.jsx';

const SECTIONS = ['Profile', 'Security', 'Sessions', 'Access'];
const DEVICE_ICON = { desktop: 'laptop', mobile: 'phone', tablet: 'tablet' };
// The org sessions endpoint returns `device` as a parsed object
// { name, browser, os, type } (deviceName.ts parseDevice). Rendering the object
// as a JSX child throws React #31; read its label. Tolerate the older string
// shape in case a session predates the parser change.
const deviceLabel = (d) => (typeof d === 'string' ? d : (d?.name || 'Unknown device'));
const deviceType = (d) => (d && typeof d === 'object' ? d.type : undefined);
const fmtDate = (iso) => (iso ? new Date(iso).toLocaleDateString([], { year: 'numeric', month: 'short', day: 'numeric' }) : '—');
const fmtWhen = (iso) => (iso ? new Date(iso).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : 'never');

// Loading: keep the fixed chrome (back link, header frame, section rail) and
// skeleton only the variable parts (name, badges, section body). Exported so
// the org gate can paint the same pixels while the step-up check runs.
export function UserDetailSkeleton() {
  return (
    <>
      <span className="linklike" style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
        <Icon name="chevron" size={14} style={{ transform: 'rotate(180deg)' }} /> Users
      </span>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, margin: '10px 0 4px' }}>
        <span className="skeleton" style={{ width: 41, height: 41, borderRadius: '50%', flexShrink: 0 }} />
        <div style={{ flex: 1, minWidth: 0 }}>
          <h1 style={{ margin: 0 }}><Ph w={180} /></h1>
          <p className="sub" style={{ margin: 0 }}><Ph w={220} /></p>
        </div>
      </div>
      <div className="org-detail-body">
        <div className="org-secnav">
          {SECTIONS.map((s) => <button key={s} className={'org-sn' + (s === 'Profile' ? ' on' : '')} disabled>{s}</button>)}
        </div>
        <div className="org-detail-main">
          <div className="card pad"><div className="form">
            {['Display name', 'Email', 'Username'].map((l) => (
              <label className="field" key={l}><span>{l}</span><Skeleton w={360} h={36} r={8} /></label>
            ))}
          </div></div>
        </div>
      </div>
    </>
  );
}

// The user detail page: content-local section rail (the approved "second
// sidebar"), everything view-only-mirrored client-side and enforced server-side.
export default function OrgUserDetailPage() {
  const { sub } = useParams();
  const { can } = useAuth();
  const [d, setD] = useState(null);
  const [err, setErr] = useState(null);
  const [sec, setSec] = useState('Profile');

  const load = useCallback(() => {
    orgApi('GET', '/users/' + sub)
      .then(setD)
      .catch((e) => { if (e.message !== 'unauthenticated') setErr(e.status === 404 ? 'not_found' : e.code || 'error'); });
  }, [sub]);
  useEffect(() => { load(); }, [load]);

  // Success -> green toast; failures rethrow so each section can decide
  // between a field-adjacent message and a red toast.
  const act = async (fn, okMsg) => {
    try {
      await fn();
      if (okMsg) toast.success(okMsg);
      load();
      return true;
    } catch (e) {
      // unauthenticated bounces to login; step_up_required is handled by OrgGate's
      // overlay re-verify — both resolve to a silent false so callers don't toast.
      if (e.message === 'unauthenticated' || e.code === 'step_up_required') return false;
      throw e;
    }
  };

  if (err === 'not_found') {
    return (
      <>
        <Link to="/organization/users" className="linklike"><Icon name="chevron" size={14} style={{ transform: 'rotate(180deg)' }} /> Users</Link>
        <p className="err" style={{ marginTop: 12 }}>This user isn't visible to you (equal or higher privilege, or gone).</p>
      </>
    );
  }
  if (err) return <p className="err">Couldn't load. [{err}]</p>;

  if (!d) return <UserDetailSkeleton />;

  const p = d.profile;
  return (
    <>
      <Link to="/organization/users" className="linklike" style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
        <Icon name="chevron" size={14} style={{ transform: 'rotate(180deg)' }} /> Users
      </Link>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, margin: '10px 0 4px' }}>
        {p.avatar ? (
          <img className="av-sm" style={{ width: 40, height: 40 }} src={avatarUrl(p.avatar)} alt="" />
        ) : (
          <span className="av-sm" style={{ width: 40, height: 40, fontSize: 14 }}>{initials(p.display_name || p.username)}</span>
        )}
        <div style={{ flex: 1, minWidth: 0 }}>
          <h1 style={{ margin: 0 }}>{p.display_name || p.username}</h1>
          <p className="sub" style={{ margin: 0 }}>{p.username}{p.email ? ` · ${p.email}` : ''}</p>
        </div>
        {p.status !== 'active' && <span className="pill pill-warn">suspended</span>}
        <span className="pill">{d.org_role ? d.org_role.label : 'no role'}</span>
      </div>

      <div className="org-detail-body">
        <div className="org-secnav">
          {SECTIONS.map((s) => (
            <button key={s} className={'org-sn' + (sec === s ? ' on' : '')} onClick={() => setSec(s)}>{s}</button>
          ))}
        </div>
        <div className="org-detail-main">
          {sec === 'Profile' && <ProfileSection d={d} can={can} act={act} />}
          {sec === 'Security' && <SecuritySection d={d} can={can} act={act} />}
          {sec === 'Sessions' && <SessionsSection sub={sub} can={can} act={act} />}
          {sec === 'Access' && <AccessSection d={d} can={can} act={act} />}
        </div>
      </div>
    </>
  );
}

function ProfileSection({ d, can, act }) {
  const p = d.profile;
  const [f, setF] = useState({ display_name: p.display_name ?? '', email: p.email ?? '', username: p.username });
  const [errs, setErrs] = useState({});
  const [busy, setBusy] = useState(false);
  useEffect(() => setF({ display_name: p.display_name ?? '', email: p.email ?? '', username: p.username }), [p]);

  const dirty =
    (can('org.users.edit.displayname') && f.display_name !== (p.display_name ?? '')) ||
    (can('org.users.edit.email') && f.email !== (p.email ?? '')) ||
    (can('org.users.edit.username') && f.username !== p.username);

  const save = async () => {
    setBusy(true);
    setErrs({});
    const body = {};
    if (can('org.users.edit.displayname') && f.display_name !== (p.display_name ?? '')) body.display_name = f.display_name;
    if (can('org.users.edit.email') && f.email !== (p.email ?? '')) body.email = f.email;
    if (can('org.users.edit.username') && f.username !== p.username) body.username = f.username;
    try {
      await act(() => orgApi('PATCH', '/users/' + p.sub, body), 'Profile saved.');
    } catch (e) {
      if (e.data?.errors) setErrs(e.data.errors);
      else setErrs({ _: e.code || 'error' });
    } finally {
      setBusy(false);
    }
  };

  // Client-side format mirror of the create modal (same rules as the server):
  // a malformed value greys Save and shows the hint without a round trip.
  const fmtErrs = {
    display_name: f.display_name.trim() && f.display_name.trim().length <= 100 ? null : 'Required, max 100 chars',
    email: !f.email || /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(f.email) ? null : 'Enter a valid email address',
    username: /^[A-Za-z0-9_-]{3,20}$/.test(f.username) ? null : '3-20 characters: letters, digits, - and _',
  };
  const formatOk = !fmtErrs.display_name && !fmtErrs.email && !fmtErrs.username;

  return (
    <div className="card pad">
      <div className="org-profile-flex">
      <div className="org-profile-av">
        {p.avatar ? (
          <img className="av-lg" src={avatarUrl(p.avatar)} alt="" />
        ) : (
          <div className="av-lg">{initials(p.display_name || p.username)}</div>
        )}
        {p.avatar && can('org.users.edit.profilePicture.remove') && (
          <button className="linklike" disabled={busy}
            onClick={() => act(() => orgApi('DELETE', `/users/${p.sub}/avatar`), 'Profile picture removed.').catch(() => {})}>
            Remove profile picture
          </button>
        )}
      </div>
      <div className="form" style={{ flex: 1, minWidth: 0 }}>
        <label className="field"><span>Display name</span>
          <input className={'input wide' + ((errs.display_name || fmtErrs.display_name) ? ' bad' : '')}
            value={f.display_name} disabled={!can('org.users.edit.displayname')}
            onChange={(e) => { setF({ ...f, display_name: e.target.value }); setErrs((c) => ({ ...c, display_name: null })); }} />
          {(errs.display_name || fmtErrs.display_name) && <span className="fhint bad">{errs.display_name || fmtErrs.display_name}</span>}
        </label>
        <label className="field"><span>Email {p.email ? '' : '(none)'}</span>
          <input className={'input wide' + ((errs.email || fmtErrs.email) ? ' bad' : '')}
            value={f.email} disabled={!can('org.users.edit.email')}
            onChange={(e) => { setF({ ...f, email: e.target.value.replace(/\s/g, '') }); setErrs((c) => ({ ...c, email: null })); }} />
          {(errs.email || fmtErrs.email) && <span className="fhint bad">{errs.email || fmtErrs.email}</span>}
        </label>
        <label className="field"><span>Username</span>
          <input className={'input wide' + ((errs.username || fmtErrs.username) ? ' bad' : '')}
            value={f.username} disabled={!can('org.users.edit.username')}
            onChange={(e) => { setF({ ...f, username: e.target.value.replace(/\s/g, '') }); setErrs((c) => ({ ...c, username: null })); }} />
          {(errs.username || fmtErrs.username) && <span className="fhint bad">{errs.username || fmtErrs.username}</span>}
        </label>
        <p className="k" style={{ fontSize: 12, margin: 0 }}>Created {fmtDate(p.created_at)} · {p.sub}</p>
        {errs._ && <p className="err">Couldn't save. [{errs._}]</p>}
        <div className="form-actions">
          <button className="btn btn-primary" disabled={!dirty || busy || !formatOk} onClick={save}>{busy ? 'Saving…' : 'Save changes'}</button>
          {p.status === 'active'
            ? can('org.users.edit.deactivate') && (
                <button className="btn btn-danger" disabled={busy}
                  onClick={() => act(() => orgApi('POST', `/users/${p.sub}/suspend`, {}), 'Suspended — all sessions signed out.').catch(() => {})}>
                  Suspend
                </button>
              )
            : can('org.users.edit.reactivate') && (
                <button className="btn" disabled={busy}
                  onClick={() => act(() => orgApi('POST', `/users/${p.sub}/reactivate`, {}), 'Reactivated.').catch(() => {})}>
                  Reactivate
                </button>
              )}
        </div>
      </div>
      </div>
    </div>
  );
}

function SecuritySection({ d, can, act }) {
  const p = d.profile;
  const s = d.security;
  const [pw, setPw] = useState('');
  const [confirm, setConfirm] = useState('');
  const [busy, setBusy] = useState(false);
  const [pwErr, setPwErr] = useState(null);
  const [challenge, setChallenge] = useState(false); // ActionChallengeModal open
  const [confirmReset, setConfirmReset] = useState(false);

  const setPassword = async () => {
    setBusy(true);
    setPwErr(null);
    try {
      await act(() => orgApi('POST', `/users/${p.sub}/password`, { password: pw }), 'Password set — the user was signed out everywhere.');
      setPw(''); setConfirm('');
    } catch (e) {
      setPwErr(e.code || 'error');
    } finally {
      setBusy(false);
    }
  };

  const resetMfa = async (actionToken) => {
    setChallenge(false);
    setConfirmReset(false);
    try {
      await act(
        () => orgApi('POST', `/users/${p.sub}/mfa/reset`, actionToken ? { action_token: actionToken } : {}),
        'MFA reset — all factors removed, toggle off.',
      );
    } catch (e) {
      if (e.code === 'action_challenge_required') setChallenge(true);
      else setPwErr(e.code || 'error');
    }
  };

  return (
    <>
      {can('org.users.edit.password') && (
        <>
          <h2 className="section">Password</h2>
          <div className="card pad">
            <div className="form">
              <div style={{ position: 'absolute', opacity: 0, height: 0, width: 0, overflow: 'hidden' }} aria-hidden="true">
                <input type="text" name="fake_user_trap" autoComplete="username" tabIndex={-1} />
              </div>
              <p className="k" style={{ fontSize: 12, margin: 0 }}>
                Last changed {fmtDate(s.password_changed_at)}. Setting a new password signs the user out of <strong>every</strong> session.
              </p>
              {/* autoComplete="off" (videosite's AddUserModal): new-password would
                  invite the browser's save/generate UI for SOMEONE ELSE'S password */}
              <label className="field"><span>New password</span>
                <input className="input wide" type="password" autoComplete="off" value={pw}
                  onChange={(e) => { setPw(e.target.value.replace(/\s/g, '')); setPwErr(null); }} />
                <PasswordRules password={pw} />
              </label>
              <label className="field"><span>Confirm</span>
                <input className="input wide" type="password" autoComplete="off" value={confirm}
                  onChange={(e) => setConfirm(e.target.value.replace(/\s/g, ''))} />
                {confirm && confirm !== pw && <span className="fhint bad">Passwords do not match.</span>}
              </label>
              <div className="form-actions">
                <button className="btn btn-primary" disabled={busy || !passwordValid(pw) || confirm !== pw} onClick={setPassword}>
                  {busy ? 'Saving…' : 'Set password'}
                </button>
                <button className="btn" disabled={busy || !p.email}
                  title={p.email ? '' : 'No email on file'}
                  onClick={() => act(() => orgApi('POST', `/users/${p.sub}/password/send-reset`, {}), 'Reset link sent.').catch((e) => setPwErr(e.code || 'error'))}>
                  Send reset link
                </button>
              </div>
              {pwErr && <p className="err">Failed. [{pwErr}]</p>}
            </div>
          </div>
        </>
      )}

      {can('org.users.edit.mfa.view') && (
        <>
          <h2 className="section">Multi-factor authentication</h2>
          <div className="card">
            <div className="row">
              <p className="k">Account MFA</p>
              <span className={'pill' + (s.mfa_enabled ? ' pill-ok' : '')}>{s.mfa_enabled ? 'On' : 'Off'}</span>
              {s.mfa_enabled && can('org.users.edit.mfa.disable') && (
                <button className="btn" onClick={() => act(() => orgApi('POST', `/users/${p.sub}/mfa/disable`, {}), 'MFA turned off.').catch(() => {})}>
                  Turn off
                </button>
              )}
            </div>
            {s.totp.map((t) => (
              <div className="row" key={'t' + t.id}>
                <p className="k"><Icon name="qr" size={15} /> Authenticator · {t.label || 'unnamed'}</p>
                <p className="text-faint" style={{ margin: 0, fontSize: 12 }}>used {fmtWhen(t.last_used_at)}</p>
              </div>
            ))}
            {s.passkeys.map((k) => (
              <div className="row" key={'p' + k.id}>
                <p className="k"><Icon name="key" size={15} /> Passkey · {k.label || 'unnamed'}</p>
                <p className="text-faint" style={{ margin: 0, fontSize: 12 }}>used {fmtWhen(k.last_used_at)}</p>
              </div>
            ))}
            {s.totp.length + s.passkeys.length === 0 && <div className="row"><p className="k">No factors enrolled.</p></div>}
          </div>
          {can('org.users.edit.mfa.reset') && (
            <div className="form-actions" style={{ marginTop: 10 }}>
              <button className="btn btn-danger" onClick={() => setConfirmReset(true)}>Reset MFA…</button>
              <span className="fhint">Lockout recovery only: removes every factor and turns the toggle off.</span>
            </div>
          )}
        </>
      )}

      {confirmReset && (
        <Modal title="Reset MFA?" onClose={() => setConfirmReset(false)}>
          <p className="modal-msg">
            This removes <strong>all</strong> of {p.display_name || p.username}&rsquo;s authenticators and passkeys and turns MFA off.
            Only for account lockout. Enrollment happens again on their own device.
          </p>
          <div className="modal-actions">
            <button className="btn btn-danger" onClick={() => resetMfa()}>Reset MFA</button>
            <button className="btn" onClick={() => setConfirmReset(false)}>Cancel</button>
          </div>
        </Modal>
      )}
      {challenge && (
        <ActionChallengeModal
          action="mfa.reset" targetSub={p.sub}
          onToken={(tok) => resetMfa(tok)}
          onCancel={() => setChallenge(false)}
        />
      )}
    </>
  );
}

function SessionsSection({ sub, can, act }) {
  const [data, setData] = useState(null);
  const load = useCallback(() => {
    orgApi('GET', `/users/${sub}/sessions`).then(setData).catch(() => setData({ sessions: [] }));
  }, [sub]);
  useEffect(() => { load(); }, [load]);
  if (!can('org.users.edit.sessions.view')) return <p className="sub">You can't view this user's sessions.</p>;
  if (!data) return (
    <div className="card">
      {Array.from({ length: 2 }).map((_, i) => (
        <div className="row" key={i}>
          <div style={{ flex: 1, minWidth: 0 }}>
            <p className="row-title" style={{ margin: 0 }}><Ph w={150 - i * 20} /></p>
            <p className="k" style={{ margin: 0, fontSize: 12 }}><Ph w={230} /></p>
          </div>
          {can('org.users.edit.sessions.terminate') && <button className="btn" disabled>Sign out</button>}
        </div>
      ))}
    </div>
  );
  return (
    <>
      <div className="card">
        {data.sessions.length === 0 && <div className="row"><p className="k">No active sessions.</p></div>}
        {data.sessions.map((s) => (
          <div className="row" key={s.sid}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12, flex: 1, minWidth: 0 }}>
              <Icon name={DEVICE_ICON[deviceType(s.device)] || 'devices'} size={20} />
              <div style={{ minWidth: 0 }}>
                <p className="row-title" style={{ margin: 0 }}>{deviceLabel(s.device)}</p>
                <p className="k" style={{ margin: 0, fontSize: 12 }}>
                  {s.country ? s.country + ' · ' : ''}signed in {fmtWhen(s.auth_time)} · active {fmtWhen(s.last_seen)}
                </p>
              </div>
            </div>
            {can('org.users.edit.sessions.terminate') && (
              <button className="btn" onClick={() => act(() => orgApi('DELETE', `/users/${sub}/sessions/${s.sid}`)).then(load).catch(() => {})}>
                Sign out
              </button>
            )}
          </div>
        ))}
      </div>
      {can('org.users.edit.sessions.terminate') && data.sessions.length > 0 && (
        <div className="form-actions" style={{ marginTop: 10 }}>
          <button className="btn btn-danger"
            onClick={() => act(() => orgApi('POST', `/users/${sub}/sessions/terminate-all`, {}), 'All sessions signed out.').then(load).catch(() => {})}>
            Sign out everywhere
          </button>
        </div>
      )}
    </>
  );
}

function AccessSection({ d, can, act }) {
  const p = d.profile;
  const [roles, setRoles] = useState(null);
  const [busy, setBusy] = useState(false);
  // Staged changes — nothing is written until the save bar's Save fires ONE
  // batch request (validated in full server-side, applied atomically).
  const [pend, setPend] = useState({ org_role: undefined, permissions: {}, app_roles: {} });
  useEffect(() => {
    if (can('org.roles.view')) orgApi('GET', '/roles').then(setRoles).catch(() => setRoles(null));
  }, [can]);
  useEffect(() => { setPend({ org_role: undefined, permissions: {}, app_roles: {} }); }, [d]);

  const groups = [...new Set(d.permissions.map((x) => x.group))];
  const canOverride = can('org.users.edit.permissions.acctPortal');
  const noAccessLabel = 'No access';
  const roleName = (app, id) => (id == null ? noAccessLabel : app.roles.find((r) => r.role_id === id)?.name ?? `#${id}`);

  const stagePerm = (key, effect, orig) =>
    setPend((c) => {
      const next = { ...c, permissions: { ...c.permissions } };
      if (effect === orig) delete next.permissions[key];
      else next.permissions[key] = effect;
      return next;
    });
  const stageApp = (clientId, val, orig) =>
    setPend((c) => {
      const next = { ...c, app_roles: { ...c.app_roles } };
      if (val === orig) delete next.app_roles[clientId];
      else next.app_roles[clientId] = val;
      return next;
    });

  const items = [];
  if (pend.org_role !== undefined) {
    const r = roles?.roles.find((x) => x.slug === pend.org_role);
    items.push({ label: 'org role', value: r ? r.label : pend.org_role });
  }
  for (const [k, v] of Object.entries(pend.permissions)) items.push({ label: k.split('.').slice(-2).join('.'), value: v });
  for (const [cid, v] of Object.entries(pend.app_roles)) {
    const app = d.app_roles.find((x) => x.client_id === cid);
    items.push({ label: cid, value: v === 'inherit' ? 'inherit' : v === null ? noAccessLabel : app ? roleName(app, v) : String(v) });
  }

  const save = async () => {
    setBusy(true);
    const body = {};
    if (pend.org_role !== undefined) body.org_role = pend.org_role;
    if (Object.keys(pend.permissions).length) body.permissions = pend.permissions;
    if (Object.keys(pend.app_roles).length) body.app_roles = pend.app_roles;
    try {
      await act(() => orgApi('POST', `/users/${p.sub}/access`, body), 'Access changes saved.');
    } catch (e) {
      const it = e.data?.item; // the batch endpoint names the item that failed validation
      toast.error(`Couldn't save. [${e.code || 'error'}${it ? ` — ${it.key || it.client || it.type}` : ''}]`);
    } finally {
      setBusy(false);
    }
  };

  const curRole = pend.org_role ?? d.org_role?.slug ?? '';

  return (
    <>
      <h2 className="section">Organization role</h2>
      <div className="card pad">
        {canOverride && roles ? (
          <select
            className={'input fit' + (pend.org_role !== undefined ? ' staged' : '')}
            value={curRole}
            onChange={(e) => setPend((c) => ({ ...c, org_role: e.target.value === (d.org_role?.slug ?? '') ? undefined : e.target.value }))}
          >
            {d.org_role && !roles.roles.some((r) => r.editable && r.slug === d.org_role.slug) && (
              <option value={d.org_role.slug}>{d.org_role.label} (level {d.org_role.level})</option>
            )}
            {roles.roles.filter((r) => r.editable).map((r) => (
              <option key={r.slug} value={r.slug}>{r.label} (level {r.level})</option>
            ))}
          </select>
        ) : (
          <p className="k" style={{ margin: 0 }}>{d.org_role ? `${d.org_role.label} (level ${d.org_role.level})` : 'No role'}</p>
        )}
        <p className="fhint" style={{ marginTop: 8 }}>One role per user. You can only assign roles below your own.</p>
      </div>

      {d.app_roles.length > 0 && can('org.users.edit.permissions.app') && (
        <>
          <h2 className="section">App roles</h2>
          <div className="card">
            {d.app_roles.map((app) => {
              const orig = app.override ? (app.override.role_id === null ? 'null' : String(app.override.role_id)) : 'inherit';
              const staged = pend.app_roles[app.client_id];
              const cur = staged === undefined ? orig : staged === 'inherit' ? 'inherit' : staged === null ? 'null' : String(staged);
              const inheritedFrom = app.org_default ? 'org role default' : 'app default';
              const inheritedVal = app.org_default ? app.org_default.role_id : app.catalog_default;
              return (
                <div className="row" key={app.client_id}>
                  <p className="k" style={{ minWidth: 120 }}>{app.name || app.client_id}</p>
                  {app.editable ? (
                    <select
                      className={'input fit' + (staged !== undefined ? ' staged' : '')}
                      value={cur}
                      onChange={(e) => {
                        const v = e.target.value;
                        const value = v === 'inherit' ? 'inherit' : v === 'null' ? null : Number(v);
                        const origValue = orig === 'inherit' ? 'inherit' : orig === 'null' ? null : Number(orig);
                        stageApp(app.client_id, value, origValue);
                      }}
                    >
                      <option value="inherit">Inherit — {roleName(app, inheritedVal)} (via {inheritedFrom})</option>
                      {app.roles.filter((r) => app.actor_level == null || r.level >= app.actor_level).map((r) => (
                        <option key={r.role_id} value={String(r.role_id)}>{r.name} (level {r.level})</option>
                      ))}
                      <option value="null">{noAccessLabel}</option>
                    </select>
                  ) : (
                    <p className="k" style={{ margin: 0 }}>
                      {roleName(app, app.effective.role_id)} <span className="fhint">above your level — view only</span>
                    </p>
                  )}
                </div>
              );
            })}
          </div>
        </>
      )}

      <h2 className="section">Permission overrides</h2>
      {groups.map((g) => (
        <div key={g}>
          <p className="k" style={{ fontSize: 12, margin: '8px 2px 6px', textTransform: 'uppercase', letterSpacing: '.03em' }}>{g}</p>
          <div className="card" style={{ marginBottom: 10 }}>
            {d.permissions.filter((x) => x.group === g).map((perm) => {
              const orig = perm.override ?? 'inherit';
              const staged = pend.permissions[perm.key];
              return (
                <div className="row" key={perm.key}>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <p className="row-title mono" style={{ margin: 0, fontSize: 12.5 }}>{perm.key}</p>
                    {perm.description && <p className="k" style={{ margin: 0, fontSize: 11.5 }}>{perm.description}</p>}
                  </div>
                  <span className="fhint">role: {perm.role_effect}</span>
                  {canOverride && perm.editable ? (
                    <select
                      className={'input fit' + (staged !== undefined ? ' staged' : '')}
                      value={staged ?? orig}
                      onChange={(e) => stagePerm(perm.key, e.target.value, orig)}
                    >
                      <option value="inherit">Inherit</option>
                      <option value="grant">Grant</option>
                      <option value="deny">Deny</option>
                    </select>
                  ) : (
                    <span className="pill" title="You don't hold this permission">
                      {orig}{perm.editable ? '' : ' · locked'}
                    </span>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      ))}
      <SaveBar
        items={items} busy={busy}
        onSave={save}
        onDiscard={() => setPend({ org_role: undefined, permissions: {}, app_roles: {} })}
      />
    </>
  );
}
