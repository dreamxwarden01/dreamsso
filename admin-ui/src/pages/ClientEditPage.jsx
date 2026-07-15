import { useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import {
  listClients, createClient, updateClient, disableClient, enableClient, deleteClient,
} from '../api.js';
import Icon from '../Icon.jsx';
import { SkelInput, Ph } from '../Skel.jsx';
// The SHARED normalization module — the same file the admin API runs server-side.
import {
  normalizeHostname, normalizePath, normalizeSlug, normalizeName, composeUrl, decomposeUrl,
} from '../../../src/clientNormalize.ts';

const SCOPES = ['openid', 'profile', 'email'];
// First-party path conventions (the "fill standard paths" helper).
const STD = { callback: '/auth/callback', events: '/backchannel/events', jwks: '/.well-known/jwks.json' };

function Field({ label, note, error, children }) {
  return (
    <label className="field">
      <span>
        {label} {note && <span className="note">({note})</span>}
      </span>
      {children}
      {error && <span className="ferr">{error}</span>}
    </label>
  );
}

function Modal({ title, children, onClose }) {
  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" role="dialog" aria-modal="true" onClick={(e) => e.stopPropagation()}>
        <h3 className="modal-title">{title}</h3>
        {children}
      </div>
    </div>
  );
}

const emptyForm = {
  client_id: '', name: '', hostname: '', redirect_paths: [''], events_path: '',
  key_mode: 'uri', jwks_path: '', jwks_text: '',
  allowed_scopes: [...SCOPES], is_first_party: true, entry_policy: 'opt_in',
};

// What "dirty" compares (the submittable surface of the form).
const surface = (f) => JSON.stringify([
  f.name, f.hostname, f.redirect_paths, f.events_path,
  f.key_mode, f.jwks_path, f.jwks_text, f.allowed_scopes, f.is_first_party, f.entry_policy,
]);

export default function ClientEditPage() {
  const { id } = useParams(); // undefined for /clients/new
  const isNew = !id;
  const nav = useNavigate();

  const [row, setRow] = useState(null); // server row (edit mode)
  const [f, setF] = useState(isNew ? emptyForm : null);
  const [snap, setSnap] = useState(isNew ? surface(emptyForm) : null);
  const [errs, setErrs] = useState({});
  const [busy, setBusy] = useState(false);
  const [loadErr, setLoadErr] = useState(false);
  const [saveErr, setSaveErr] = useState(null);
  const [modal, setModal] = useState(null); // 'disable' | 'enable' | 'delete'
  const [deleteConfirm, setDeleteConfirm] = useState('');
  // jwks_uri that doesn't live on the client's hostname (e.g. a dev loopback) —
  // shown as-is; entering a path replaces it, leaving blank keeps it.
  const [externalJwksUri, setExternalJwksUri] = useState(null);

  const load = () =>
    listClients()
      .then((d) => {
        const c = d.clients.find((x) => x.client_id === id);
        if (!c) return setLoadErr(true);
        const jwksPath = c.jwks_uri ? decomposeUrl(c.jwks_uri, c.hostname) : null;
        setExternalJwksUri(c.jwks_uri && !jwksPath ? c.jwks_uri : null);
        const form = {
          client_id: c.client_id,
          name: c.name,
          hostname: c.hostname,
          redirect_paths: c.redirect_paths.length ? c.redirect_paths : [''],
          events_path: c.events_path ?? '',
          key_mode: c.jwks_uri ? 'uri' : 'inline',
          jwks_path: jwksPath ?? '',
          // Show the registered public JWKS (it's public material) — an empty
          // box here read as "no key configured".
          jwks_text: c.jwks ? JSON.stringify(c.jwks, null, 2) : '',
          allowed_scopes: c.allowed_scopes,
          is_first_party: c.is_first_party,
          entry_policy: c.entry_policy,
        };
        setRow(c);
        setF(form);
        setSnap(surface(form));
        setErrs({});
      })
      .catch((e) => {
        if (e.message !== 'unauthenticated') setLoadErr(true);
      });
  useEffect(() => {
    if (!isNew) load();
  }, [id]);

  const set = (patch) => setF((cur) => ({ ...cur, ...patch }));
  const setErr = (key, msg) => setErrs((cur) => ({ ...cur, [key]: msg || undefined }));

  // --- blur normalization (shared rules; red border on error) ---
  const blurSlug = () => {
    const r = normalizeSlug(f.client_id);
    set({ client_id: r.value });
    setErr('client_id', r.error);
  };
  const blurName = () => {
    const r = normalizeName(f.name);
    set({ name: r.value });
    setErr('name', r.error);
  };
  const blurHostname = () => {
    const r = normalizeHostname(f.hostname);
    set({ hostname: r.value });
    setErr('hostname', r.error);
    // A hostname change can validate/invalidate already-entered paths — re-check.
    if (!r.error) {
      f.redirect_paths.forEach((p, i) => {
        if (p) setErr(`redirect_paths.${i}`, normalizePath(p, r.value, { required: true }).error);
      });
      if (f.events_path) setErr('events_path', normalizePath(f.events_path, r.value).error);
      if (f.jwks_path) setErr('jwks_path', normalizePath(f.jwks_path, r.value).error);
    }
  };
  const blurPath = (key, i) => {
    const raw = i == null ? f[key] : f.redirect_paths[i];
    const required = key === 'redirect_paths';
    const r = normalizePath(raw, f.hostname, { required });
    if (i == null) set({ [key]: r.value });
    else set({ redirect_paths: f.redirect_paths.map((p, j) => (j === i ? r.value : p)) });
    setErr(i == null ? key : `redirect_paths.${i}`, r.error);
  };
  const blurJwksText = () => {
    if (!f.jwks_text.trim()) return setErr('jwks', null);
    try {
      const j = JSON.parse(f.jwks_text);
      if (!Array.isArray(j.keys) || j.keys.length === 0) throw new Error();
      setErr('jwks', null);
    } catch {
      setErr('jwks', 'Must be a JWKS JSON object with a non-empty "keys" array');
    }
  };

  const fillStandard = () => {
    set({
      redirect_paths: [STD.callback],
      events_path: STD.events,
      ...(f.key_mode === 'uri' && !externalJwksUri ? { jwks_path: STD.jwks } : {}),
    });
    setErrs((cur) => {
      const next = { ...cur };
      Object.keys(next).forEach((k) => {
        if (k.startsWith('redirect_paths') || k === 'events_path' || k === 'jwks_path') delete next[k];
      });
      return next;
    });
  };

  // --- validity + dirty gating ---
  const hasErrors = Object.values(errs).some(Boolean);
  const keyOk =
    f && (f.key_mode === 'uri'
      ? !!f.jwks_path || !!externalJwksUri
      : !!f.jwks_text.trim() || !!row?.has_inline_jwks);
  const requiredOk =
    f && f.name && f.hostname && f.redirect_paths.some((p) => p) && keyOk && (!isNew || f.client_id);
  const dirty = f && surface(f) !== snap;
  const canSave = !busy && !hasErrors && requiredOk && (isNew || dirty);

  const buildBody = () => {
    const body = {
      name: f.name,
      hostname: f.hostname,
      redirect_paths: f.redirect_paths.filter((p) => p),
      events_path: f.events_path || null,
      allowed_scopes: f.allowed_scopes,
      is_first_party: f.is_first_party,
      entry_policy: f.entry_policy,
    };
    // The selected radio is the MODE applied on save: fetch = jwks_uri active
    // (the server snapshots the fetched keys into jwks for the paste view);
    // paste = keys pinned inline, jwks_uri cleared -> automatic fetch off.
    if (f.key_mode === 'uri') {
      if (f.jwks_path) {
        body.jwks_uri = composeUrl(f.hostname, f.jwks_path);
        // jwks omitted: the server keeps/refreshes the fetched snapshot itself
      } else if (isNew) {
        body.jwks_uri = null;
        body.jwks = null;
      } // edit + blank path + external uri -> omit, PATCH keeps the current value
    } else {
      if (f.jwks_text.trim()) {
        body.jwks = JSON.parse(f.jwks_text);
        body.jwks_uri = null;
      } else if (isNew) {
        body.jwks = null;
        body.jwks_uri = null;
      } else {
        body.jwks_uri = null; // blank box: keep the stored keys, but fetch goes off
      }
    }
    return body;
  };

  const save = async () => {
    setBusy(true);
    setSaveErr(null);
    try {
      if (isNew) {
        const body = { client_id: f.client_id, ...buildBody() };
        // create requires explicit key material
        if (body.jwks_uri === undefined) body.jwks_uri = null;
        if (body.jwks === undefined) body.jwks = null;
        await createClient(body);
        nav('/clients/' + encodeURIComponent(f.client_id), { replace: true });
      } else {
        await updateClient(id, buildBody());
        await load();
      }
    } catch (e) {
      if (e.message === 'unauthenticated') return;
      if (e.status === 422 && e.data?.errors) setErrs((cur) => ({ ...cur, ...e.data.errors }));
      else if (e.status === 409) setErr('client_id', 'This client ID is already taken');
      else setSaveErr(`Couldn't save. [${e.data?.error || 'http_' + e.status}]`);
    } finally {
      setBusy(false);
    }
  };

  const lifecycle = async (action) => {
    setBusy(true);
    setSaveErr(null);
    try {
      if (action === 'disable') await disableClient(id);
      if (action === 'enable') await enableClient(id);
      if (action === 'delete') {
        await deleteClient(id);
        nav('/', { replace: true });
        return;
      }
      setModal(null);
      await load();
    } catch (e) {
      if (e.message !== 'unauthenticated') setSaveErr(`Action failed. [${e.data?.error || 'http_' + e.status}]`);
      setModal(null);
    } finally {
      setBusy(false);
    }
  };

  if (loadErr) {
    return (
      <>
        <button className="back" onClick={() => nav('/clients')}>
          <Icon name="chevron" size={15} className="back-chev" />
          Clients
        </button>
        <p className="err">Couldn't load this client.</p>
      </>
    );
  }
  if (!f) {
    // Field-mirroring skeleton (edit mode only — "new" initializes instantly):
    // real labels/notes/buttons, shimmer only the name and input values.
    return (
      <>
        <button className="back" onClick={() => nav('/clients')}>
          <Icon name="chevron" size={15} className="back-chev" />
          Clients
        </button>
        <h1><Ph w={220} /></h1>
        <p className="sub">OIDC client registration.</p>
        <div className="card pad">
          <div className="form">
            <div className="grid2">
              <Field label="Client ID"><SkelInput /></Field>
              <Field label="Display name"><SkelInput /></Field>
            </div>
            <div className="inline-row">
              <div className="grow">
                <Field label="Hostname" note="https only — no scheme, path, or port"><SkelInput /></Field>
              </div>
              <button className="btn" style={{ marginTop: 22 }} disabled>Fill standard paths</button>
            </div>
            <Field label="Redirect paths" note="the app's callback endpoint — exact match"><SkelInput /></Field>
            <Field label="Back-channel events path" note="logout + role changes; optional"><SkelInput /></Field>
            <div className="grid2">
              <Field label="Allowed scopes"><SkelInput width={200} /></Field>
              <Field label="Trust &amp; entry"><SkelInput width={200} /></Field>
            </div>
          </div>
        </div>
      </>
    );
  }

  return (
    <>
      <button className="back" onClick={() => nav('/clients')}>
        <Icon name="chevron" size={15} className="back-chev" />
        Clients
      </button>
      <h1>
        {isNew ? 'Register client' : row?.name}{' '}
        {!isNew && row?.is_system && <span className="pill pill-mut">System</span>}{' '}
        {!isNew &&
          (row?.disabled_at ? <span className="pill pill-warn">Disabled</span> : <span className="pill pill-ok">Active</span>)}
      </h1>
      <p className="sub">{isNew ? 'Register an application to sign in through DreamSSO.' : 'OIDC client registration.'}</p>

      <div className="card pad">
        <div className="form">
          <div className="grid2">
            {isNew ? (
              <Field label="Client ID" note="immutable — lowercase slug" error={errs.client_id}>
                <input
                  className={'input mono' + (errs.client_id ? ' bad' : '')}
                  value={f.client_id}
                  placeholder="e.g. videosite"
                  onChange={(e) => { set({ client_id: e.target.value }); setErr('client_id', null); }}
                  onBlur={blurSlug}
                />
              </Field>
            ) : (
              <Field label="Client ID">
                <span className="locked-val mono">
                  {f.client_id}
                  <Icon name="lock" size={13} className="chev" style={{ marginLeft: 'auto' }} />
                </span>
                <span className="hint">Can't be changed after creation</span>
              </Field>
            )}
            <Field label="Display name" error={errs.name}>
              <input
                className={'input' + (errs.name ? ' bad' : '')}
                value={f.name}
                onChange={(e) => { set({ name: e.target.value }); setErr('name', null); }}
                onBlur={blurName}
              />
            </Field>
          </div>

          <div className="inline-row">
            <div className="grow">
              <Field label="Hostname" note="https only — no scheme, path, or port" error={errs.hostname}>
                <input
                  className={'input mono' + (errs.hostname ? ' bad' : '')}
                  value={f.hostname}
                  placeholder="app.dreamxwarden.ca"
                  onChange={(e) => { set({ hostname: e.target.value }); setErr('hostname', null); }}
                  onBlur={blurHostname}
                />
              </Field>
            </div>
            <button className="btn" style={{ marginTop: 22 }} onClick={fillStandard} disabled={!f.hostname || !!errs.hostname}>
              Fill standard paths
            </button>
          </div>

          <Field label="Redirect paths" note="the app's callback endpoint — exact match" error={errs.redirect_paths}>
            {f.redirect_paths.map((p, i) => (
              <div className="uri-row" key={i}>
                <div style={{ flex: 1 }}>
                  <input
                    className={'input mono' + (errs[`redirect_paths.${i}`] ? ' bad' : '')}
                    value={p}
                    placeholder="/auth/callback"
                    onChange={(e) => {
                      set({ redirect_paths: f.redirect_paths.map((x, j) => (j === i ? e.target.value : x)) });
                      setErr(`redirect_paths.${i}`, null);
                    }}
                    onBlur={() => blurPath('redirect_paths', i)}
                  />
                  {errs[`redirect_paths.${i}`] && <span className="ferr">{errs[`redirect_paths.${i}`]}</span>}
                </div>
                {f.redirect_paths.length > 1 && (
                  <button
                    className="iconbtn"
                    title="Remove"
                    aria-label="Remove redirect path"
                    onClick={() => {
                      set({ redirect_paths: f.redirect_paths.filter((_, j) => j !== i) });
                      setErr(`redirect_paths.${i}`, null);
                    }}
                  >
                    <Icon name="trash" size={15} />
                  </button>
                )}
              </div>
            ))}
            <button className="addlink" onClick={() => set({ redirect_paths: [...f.redirect_paths, ''] })}>
              <Icon name="plus" size={12} />
              Add path
            </button>
          </Field>

          <Field label="Back-channel events path" note="logout + role changes; optional" error={errs.events_path}>
            <input
              className={'input mono' + (errs.events_path ? ' bad' : '')}
              value={f.events_path}
              placeholder="/api/backchannel-logout"
              onChange={(e) => { set({ events_path: e.target.value }); setErr('events_path', null); }}
              onBlur={() => blurPath('events_path')}
            />
          </Field>

          <div className="field">
            <span>Client key</span>
            <div className="radio-line" style={{ marginBottom: 8 }}>
              <label>
                <input type="radio" checked={f.key_mode === 'uri'} onChange={() => set({ key_mode: 'uri' })} />
                Fetch from jwks_uri
              </label>
              <label>
                <input type="radio" checked={f.key_mode === 'inline'} onChange={() => set({ key_mode: 'inline' })} />
                Paste public JWKS
              </label>
            </div>
            {/* mode flips on save — call it out when the selection differs from the saved mode */}
            {!isNew && f.key_mode !== (row?.jwks_uri ? 'uri' : 'inline') && (
              <p className="hint" style={{ marginBottom: 8 }}>
                {f.key_mode === 'uri'
                  ? 'Saving turns ON automatic key fetching from this URL.'
                  : 'Saving pins these keys and turns OFF automatic fetching from the jwks_uri.'}
              </p>
            )}
            {f.key_mode === 'uri' ? (
              <>
                <input
                  className={'input mono' + (errs.jwks_path ? ' bad' : '')}
                  value={f.jwks_path}
                  placeholder="/.well-known/jwks.json"
                  onChange={(e) => { set({ jwks_path: e.target.value }); setErr('jwks_path', null); }}
                  onBlur={() => blurPath('jwks_path')}
                />
                {errs.jwks_path && <span className="ferr">{errs.jwks_path}</span>}
                {externalJwksUri && !f.jwks_path && (
                  <p className="hint">
                    Currently external: <span className="mono">{externalJwksUri}</span> — enter a path to replace it, or
                    leave blank to keep.
                  </p>
                )}
              </>
            ) : (
              <>
                <textarea
                  className={'input mono' + (errs.jwks ? ' bad' : '')}
                  value={f.jwks_text}
                  placeholder='{"keys":[{"kty":"OKP","crv":"Ed25519", ...}]}'
                  onChange={(e) => { set({ jwks_text: e.target.value }); setErr('jwks', null); }}
                  onBlur={blurJwksText}
                />
                {errs.jwks && <span className="ferr">{errs.jwks}</span>}
                {row?.jwks_uri && f.jwks_text.trim() && (
                  <p className="hint">These are the keys last fetched from the jwks_uri.</p>
                )}
                {row?.has_inline_jwks && !f.jwks_text.trim() && (
                  <p className="hint">Leaving this blank keeps the currently registered keys.</p>
                )}
              </>
            )}
          </div>

          <div className="grid2">
            <div className="field">
              <span>Allowed scopes</span>
              <div className="checks">
                {SCOPES.map((s) => (
                  <label key={s}>
                    <input
                      type="checkbox"
                      checked={f.allowed_scopes.includes(s)}
                      disabled={s === 'openid'}
                      onChange={(e) =>
                        set({
                          allowed_scopes: e.target.checked
                            ? [...f.allowed_scopes, s]
                            : f.allowed_scopes.filter((x) => x !== s),
                        })
                      }
                    />
                    {s}
                  </label>
                ))}
              </div>
            </div>
            <div className="field">
              <span>Trust &amp; entry</span>
              <div className="checks">
                <label>
                  <input
                    type="checkbox"
                    checked={f.is_first_party}
                    onChange={(e) => set({ is_first_party: e.target.checked })}
                  />
                  First-party
                </label>
                <label>
                  Entry:&nbsp;
                  <select
                    className="input"
                    style={{ width: 'auto', padding: '4px 8px' }}
                    value={f.entry_policy}
                    onChange={(e) => set({ entry_policy: e.target.value })}
                  >
                    <option value="opt_in">opt_in</option>
                    <option value="baseline">baseline</option>
                  </select>
                </label>
              </div>
            </div>
          </div>

          {saveErr && <p className="err">{saveErr}</p>}
          <div className="form-actions">
            <button className="btn btn-primary" onClick={save} disabled={!canSave}>
              {busy ? 'Saving…' : isNew ? 'Register client' : 'Save changes'}
            </button>
            {!isNew && !dirty && <span className="dirty-note">No unsaved changes</span>}
          </div>
        </div>
      </div>

      {!isNew && row?.is_system && (
        <div className="card pad">
          <p style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <Icon name="lock" size={14} className="chev" />
            System client — the account portal is part of DreamSSO itself, so this registration can't be disabled
            or deleted.
          </p>
        </div>
      )}
      {!isNew && !row?.is_system && (
        <div className="card pad danger-zone">
          <p className="dz-title">Danger zone</p>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 14 }}>
            <p>
              Disabling blocks all sign-ins for this app immediately. A client must be disabled before it can be
              deleted — deletion is permanent and removes its registration and grants.
            </p>
            <span style={{ display: 'flex', gap: 8, flexShrink: 0 }}>
              {row?.disabled_at ? (
                <button className="btn" onClick={() => setModal('enable')} disabled={busy}>
                  Enable
                </button>
              ) : (
                <button className="btn btn-danger" onClick={() => setModal('disable')} disabled={busy}>
                  Disable
                </button>
              )}
              <button
                className="btn btn-danger"
                onClick={() => { setDeleteConfirm(''); setModal('delete'); }}
                disabled={busy || !row?.disabled_at}
                title={row?.disabled_at ? undefined : 'Disable first'}
              >
                Delete…
              </button>
            </span>
          </div>
        </div>
      )}

      {modal === 'disable' && (
        <Modal title={`Disable ${row?.name}?`} onClose={() => setModal(null)}>
          <p className="modal-msg">
            All sign-ins to this application stop immediately. Existing app sessions are not terminated.
          </p>
          <div className="modal-actions">
            <button className="btn btn-danger" onClick={() => lifecycle('disable')} disabled={busy}>
              {busy ? 'Disabling…' : 'Disable'}
            </button>
            <button className="btn" onClick={() => setModal(null)} disabled={busy}>
              Cancel
            </button>
          </div>
        </Modal>
      )}
      {modal === 'enable' && (
        <Modal title={`Enable ${row?.name}?`} onClose={() => setModal(null)}>
          <p className="modal-msg">Sign-ins to this application resume immediately.</p>
          <div className="modal-actions">
            <button className="btn btn-primary" onClick={() => lifecycle('enable')} disabled={busy}>
              {busy ? 'Enabling…' : 'Enable'}
            </button>
            <button className="btn" onClick={() => setModal(null)} disabled={busy}>
              Cancel
            </button>
          </div>
        </Modal>
      )}
      {modal === 'delete' && (
        <Modal title={`Delete ${row?.name}?`} onClose={() => setModal(null)}>
          <p className="modal-msg">
            This permanently deletes the registration, its keys, and all related grants.{' '}
            <strong>This cannot be undone.</strong> Type <span className="mono">{id}</span> to confirm.
          </p>
          <input
            className="input mono"
            value={deleteConfirm}
            autoFocus
            placeholder={id}
            onChange={(e) => setDeleteConfirm(e.target.value)}
          />
          <div className="modal-actions">
            <button
              className="btn btn-danger"
              onClick={() => lifecycle('delete')}
              disabled={busy || deleteConfirm !== id}
            >
              {busy ? 'Deleting…' : 'Delete permanently'}
            </button>
            <button className="btn" onClick={() => setModal(null)} disabled={busy}>
              Cancel
            </button>
          </div>
        </Modal>
      )}
    </>
  );
}
