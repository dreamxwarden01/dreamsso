import { useEffect, useRef, useState } from 'react';
import { Link, useNavigate, useParams, useOutletContext } from 'react-router-dom';
import {
  listClients, createClient, updateClient, disableClient, enableClient, deleteClient, apiErrorMessage, beforeAuthBounce,
} from '../api.js';
import Icon from '../Icon.jsx';
import { writeClientDraft, readClientDraft, restoreClientDraft, clearClientDraft, clientDraftAuthUncertain, settleClientDraft, rebaseClientDraftForm, observeClientDraftSettlement } from '../clientDraft.js';
import { ClientErrorContext, ErrorInput, ErrorGroup, OutcomePanel, SaveButton, useSaveFeedback, useScrollReserve } from '../SaveFeedback.jsx';
import { feedbackTechnical, keyFieldFeedback } from '../saveFeedback.js';
import { SkelInput, Ph } from '../Skel.jsx';
import { normalizeClientErrors, activeClientErrors, hasBlockingClientErrors, clientErrorsForDisplay,
  clearEditedServerErrors, changedClientFields, missingClientFields, removeRedirectErrors, clientErrorLabel } from '../clientFormErrors.js';
// The SHARED normalization module — the same file the admin API runs server-side.
import {
  normalizeHostname, normalizePath, normalizeSlug, normalizeName, composeUrl, decomposeUrl,
} from '../../../src/clientNormalize.ts';

const SCOPES = ['openid', 'profile', 'email'];
// First-party path conventions (the "fill standard paths" helper).
const STD = { callback: '/auth/callback', events: '/backchannel/events', jwks: '/.well-known/jwks.json' };

function Field({ label, note, children }) {
  return (
    <label className="field">
      <span>
        {label} {note && <span className="note">({note})</span>}
      </span>
      {children}
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
  f.client_id, f.name, f.hostname, f.redirect_paths, f.events_path,
  f.key_mode, f.jwks_path, f.jwks_text, f.allowed_scopes, f.is_first_party, f.entry_policy,
]);

function clientFormFromRow(c) {
  const jwksPath = c.jwks_uri ? decomposeUrl(c.jwks_uri, c.hostname) : null;
  return {
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
}

export default function ClientEditPage() {
  const { id } = useParams(); // undefined for /clients/new
  const { subject } = useOutletContext();
  return <ClientEditForm key={JSON.stringify([subject, id ?? 'new'])} id={id} subject={subject} />;
}

function ClientEditForm({ id, subject }) {
  const isNew = !id;
  const draftRoute = isNew ? 'new' : 'client:' + id;
  const baseForm = useRef(emptyForm);
  const draftState = useRef(null);
  const draftDisabled = useRef(false);
  const recoveredObservation = useRef(null);
  const [draftSettled, setDraftSettled] = useState(false);
  const stopRecoveredObservation = () => {
    recoveredObservation.current?.();
    recoveredObservation.current = null;
    if (draftState.current) draftState.current.restoredOperationId = null;
  };
  const [draftNotice, setDraftNotice] = useState('');
  const [draftStorageNotice, setDraftStorageNotice] = useState('');
  const [draftOmitted, setDraftOmitted] = useState([]);
  const draftWarning = (result) => [
    result.restored.length ? 'Unsaved edits restored in this tab. Review them before saving.' : '',
    result.conflicts.length ? 'Some edits were discarded because the registration changed. Review the current server values.' : '',
    result.discarded ? 'The registration is disabled; its draft was discarded.' : '',
    result.uncertain ? 'The previous result could not be confirmed. Check the client list or current registration before manually trying again.' : '',
  ].filter(Boolean).join(' ');
  const restore = (current, disabled = false) => {
    const d = readClientDraft({ owner: subject, route: draftRoute });
    const result = restoreClientDraft(d, current, { isNew, disabled });
    setDraftNotice(draftWarning(result));
    setDraftOmitted(result.discarded ? [] : result.omitted);
    if (result.discarded || result.conflicts.length) clearClientDraft(subject, draftRoute);
    stopRecoveredObservation();
    setDraftSettled(false);
    const pending = !result.discarded && d?.operationId;
    if (pending) recoveredObservation.current = observeClientDraftSettlement({ owner: subject, route: draftRoute, operationId: pending }, (event) => {
      const current = draftState.current;
      if (!current || current.restoredOperationId !== pending) return;
      stopRecoveredObservation();
      setSaveUncertain(event.uncertain);
      if (event.success) {
        draftDisabled.current = true;
        draftState.current = null;
        setDraftSettled(true);
        setDraftOmitted([]);
        setDraftStorageNotice('');
        setDraftNotice('The previous action completed successfully. Check the client list or reload this registration before making another change.');
      } else {
        draftState.current = { ...current, operationId: null, restoredOperationId: null,
          uncertain: event.uncertain, priorUnknown: event.uncertain };
        setDraftNotice(draftWarning({ ...result, uncertain: event.uncertain }));
      }
    });
    return { ...result, restoredOperationId: pending || null, createdAt: result.discarded ? undefined : d?.savedAt };
  };
  const nav = useNavigate();
  const mounted = useRef(true);
  const loadSequence = useRef(0);
  useEffect(() => {
    mounted.current = true;
    return () => { mounted.current = false; stopRecoveredObservation(); };
  }, []);

  const [row, setRow] = useState(null); // server row (edit mode)
  const [f, setF] = useState(isNew ? emptyForm : null);
  const latestForm = useRef(f);
  latestForm.current = f;
  const [snap, setSnap] = useState(isNew ? surface(emptyForm) : null);
  const [errs, setErrs] = useState({});
  const [serverErrs, setServerErrs] = useState({});
  const [busy, setBusy] = useState(false); // lifecycle actions only
  const feedback = useSaveFeedback();
  const scrollReserve = useScrollReserve();
  const [outcomeErrors, setOutcomeErrors] = useState({});
  const [technical, setTechnical] = useState('');
  const [outcomeOpen, setOutcomeOpen] = useState(false);
  const [outcomeKind, setOutcomeKind] = useState('save');
  const [alertMessage, setAlertMessage] = useState('');
  const saveLocked = feedback.state === 'pending' || feedback.state === 'success';
  const formLocked = busy || saveLocked;
  const [loadErr, setLoadErr] = useState(null);
  const [saveErr, setSaveErr] = useState(null);
  const [saveUncertain, setSaveUncertain] = useState(false);
  const [existingClientId, setExistingClientId] = useState(null);
  const [modal, setModal] = useState(null); // 'disable' | 'enable' | 'delete'
  const [deleteConfirm, setDeleteConfirm] = useState('');
  // jwks_uri that doesn't live on the client's hostname (e.g. a dev loopback) —
  // shown as-is; entering a path replaces it, leaving blank keeps it.
  const [externalJwksUri, setExternalJwksUri] = useState(null);

  const persistDraft = (bounce) => {
    const current = draftState.current;
    if (!current?.form || draftDisabled.current) return;
    const mutationPath = isNew ? '/clients' : '/clients/' + encodeURIComponent(id);
    current.uncertain = clientDraftAuthUncertain(current.uncertain, bounce, mutationPath, current.priorUnknown);
    const result = writeClientDraft({ owner: subject, route: draftRoute, ...current, operationId: current.operationId ?? current.restoredOperationId ?? null });
    if (result.savedAt !== undefined) current.createdAt = result.savedAt;
    setDraftStorageNotice(result.reason === 'expired'
      ? 'Draft recovery has expired. Keep this page open until you save, or copy the public configuration before signing in again.'
      : result.reason === 'size' ? 'This draft is too large for sign-in recovery. Keep this page open until you save.'
      : !result.saved && result.reason !== 'empty'
        ? 'Draft recovery is unavailable in this tab. Keep this page open until you save; these edits may be lost when you sign in again.'
        : result.omitted.length
          ? `These fields cannot be kept for sign-in recovery: ${result.omitted.map((key) => clientErrorLabel(key === 'jwks_text' ? 'jwks' : key)).join(', ')}. Re-enter them after returning. Their current values are unchanged.` : '');
  };
  const beginMutation = () => {
    stopRecoveredObservation();
    setDraftSettled(false);
    const operation = { id: crypto.randomUUID(), priorUnknown: Boolean(draftState.current?.uncertain) };
    draftDisabled.current = false;
    draftState.current = { ...draftState.current, form: f, base: baseForm.current, externalJwksUri,
      operationId: operation.id, priorUnknown: operation.priorUnknown, uncertain: true };
    persistDraft();
    return operation;
  };
  const settleMutation = (operation, success, uncertain = false) => {
    settleClientDraft({ owner: subject, route: draftRoute, operationId: operation.id, success, uncertain });
    if (draftState.current?.operationId !== operation.id) return;
    if (success) {
      draftDisabled.current = true;
      draftState.current = null;
    } else {
      draftState.current = { ...draftState.current, operationId: null,
        uncertain: Boolean(operation.priorUnknown || uncertain), priorUnknown: Boolean(operation.priorUnknown || uncertain) };
    }
  };
  useEffect(() => {
    const off = beforeAuthBounce(persistDraft);
    window.addEventListener('pagehide', persistDraft);
    return () => { off(); window.removeEventListener('pagehide', persistDraft); };
  }, [subject, draftRoute]);

  const load = ({ recover = true } = {}) => {
    const sequence = ++loadSequence.current;
    setLoadErr(null);
    setF(null);
    return listClients()
      .then((d) => {
        if (!mounted.current || sequence !== loadSequence.current) return;
        const c = d.clients.find((x) => x.client_id === id);
        if (!c) {
          const error = new Error('client_not_found');
          error.code = 'client_not_found';
          error.status = 404;
          throw error;
        }
        const jwksPath = c.jwks_uri ? decomposeUrl(c.jwks_uri, c.hostname) : null;
        setExternalJwksUri(c.jwks_uri && !jwksPath ? c.jwks_uri : null);
        const form = clientFormFromRow(c);
        baseForm.current = form;
        const recovered = recover ? restore(form, Boolean(c.disabled_at)) : restoreClientDraft(null, form);
        draftDisabled.current = false;
        draftState.current = { form: recovered.form, base: form, externalJwksUri: c.jwks_uri && !jwksPath ? c.jwks_uri : null, uncertain: recovered.uncertain, priorUnknown: recovered.priorUnknown, operationId: null, restoredOperationId: recovered.restoredOperationId, omitted: recovered.omitted, createdAt: recovered.createdAt };
        setRow(c);
        setF(recovered.form);
        setSnap(surface(form));
        setErrs({});
        setServerErrs({});
        setSaveErr(null);
        setSaveUncertain(recovered.uncertain);
        setOutcomeOpen(false);
        setOutcomeErrors({});
        setTechnical('');
        setAlertMessage('');
      })
      .catch((e) => {
        if (!mounted.current || sequence !== loadSequence.current) return;
        if (e.code === 'client_not_found') {
          clearClientDraft(subject, draftRoute);
          draftState.current = null;
        }
        if (!['unauthenticated', 'step_up_required'].includes(e.code || e.message)) setLoadErr(e);
      });
  };
  useEffect(() => {
    if (!isNew) load();
    else {
      const recovered = restore(emptyForm);
      draftState.current = { form: recovered.form, base: emptyForm, uncertain: recovered.uncertain, priorUnknown: recovered.priorUnknown, operationId: null, restoredOperationId: recovered.restoredOperationId, omitted: recovered.omitted, createdAt: recovered.createdAt };
      setF(recovered.form);
      setSaveUncertain(recovered.uncertain);
    }
  }, [id, subject]);

  const set = (patch) => {
    const changed = changedClientFields(f, patch);
    if (Object.keys(changed).length === 0) return;
    stopRecoveredObservation();
    setDraftSettled(false);
    const next = { ...f, ...changed };
    draftDisabled.current = false;
    draftState.current = { ...draftState.current, form: next, base: baseForm.current, externalJwksUri, operationId: null, uncertain: draftState.current?.uncertain ?? false, omitted: (draftState.current?.omitted ?? []).filter((key) => !Object.hasOwn(changed, key)) };
    setDraftOmitted((keys) => keys.filter((key) => !Object.hasOwn(changed, key)));
    persistDraft();
    latestForm.current = next;
    setF(next);
    setServerErrs((cur) => clearEditedServerErrors(cur, changed));
    if (Object.hasOwn(changed, 'client_id')) setExistingClientId(null);
    // The last outcome stays readable while individual field marks clear.
  };
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
  const displayErrs = clientErrorsForDisplay(errs, serverErrs);
  const summaryErrors = clientErrorsForDisplay(activeClientErrors(errs, f?.key_mode), serverErrs);
  const hasErrors = hasBlockingClientErrors(errs, f?.key_mode);
  const missing = missingClientFields(f, { isNew, externalJwksUri, hasInlineJwks: row?.has_inline_jwks });
  const requiredOk = Boolean(f) && missing.length === 0;
  const dirty = f && surface(f) !== snap;
  const canSave = !busy && feedback.state === 'idle' && !hasErrors && requiredOk && draftOmitted.length === 0 && !draftSettled && (isNew || dirty);
  const panelErrors = { ...outcomeErrors, ...activeClientErrors(errs, f?.key_mode) };
  const errorItems = Object.entries(panelErrors).filter(([, message]) => message);
  const errorMarks = Object.fromEntries(errorItems.flatMap(([key, message], index) =>
    summaryErrors[key] === message ? [[key, { number: index + 1, id: `rp-error-${index + 1}` }]] : []));
  const showOutcome = outcomeOpen || hasErrors;
  const canFocusError = (key) => {
    if (key === 'jwks') return f?.key_mode === 'inline';
    if (key === 'jwks_path') return f?.key_mode === 'uri';
    if (key === 'client_id') return isNew;
    const path = /^redirect_paths\.(\d+)$/.exec(key);
    if (path) return Number(path[1]) < (f?.redirect_paths.length || 0);
    return ['name', 'hostname', 'redirect_paths', 'events_path', 'allowed_scopes', 'is_first_party', 'entry_policy'].includes(key);
  };
  const focusField = (key) => {
    const input = [...document.querySelectorAll('[data-error-key]')].find((node) => node.dataset.errorKey === key);
    if (input && !input.disabled) input.focus();
  };


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
    if (!canSave || !feedback.begin()) return;
    ++loadSequence.current;
    // A reload while a mutation is in flight must retain its ambiguous outcome.
    const operation = beginMutation();
    setOutcomeKind('save');
    setOutcomeOpen(false);
    setOutcomeErrors({});
    setTechnical('');
    setAlertMessage('');
    setSaveErr(null);
    setSaveUncertain(false);
    setExistingClientId(null);
    setServerErrs({});
    try {
      if (isNew) {
        const body = { client_id: f.client_id, ...buildBody() };
        // create requires explicit key material
        if (body.jwks_uri === undefined) body.jwks_uri = null;
        if (body.jwks === undefined) body.jwks = null;
        const created = await createClient(body);
        settleMutation(operation, true);
        if (!mounted.current) return;
        setDraftNotice(''); setDraftStorageNotice('');
        feedback.finish('success', () => {
          if (mounted.current) nav('/clients/' + encodeURIComponent(created.client.client_id), { replace: true });
        }, true);
      } else {
        await updateClient(id, buildBody());
        settleMutation(operation, true);
        if (!mounted.current) return;
        baseForm.current = f;
        setDraftNotice(''); setDraftStorageNotice('');
        setSnap(surface(f));
        // Refresh server metadata without replacing the successful form with a skeleton.
        const sequence = ++loadSequence.current;
        listClients().then((data) => {
          if (!mounted.current || sequence !== loadSequence.current) return;
          const current = data.clients.find((client) => client.client_id === id);
          if (current) {
            const canonical = clientFormFromRow(current);
            const rebased = rebaseClientDraftForm(latestForm.current ?? f, f, canonical);
            baseForm.current = canonical;
            latestForm.current = rebased;
            setF(rebased);
            setSnap(surface(canonical));
            if (draftState.current) {
              draftState.current = { ...draftState.current, form: rebased, base: canonical };
              persistDraft();
            }
            setRow(current);
            const path = current.jwks_uri ? decomposeUrl(current.jwks_uri, current.hostname) : null;
            setExternalJwksUri(current.jwks_uri && !path ? current.jwks_uri : null);
          }
        }).catch(() => { /* The save itself succeeded; metadata refresh is optional. */ });
        feedback.finish('success');
      }
    } catch (e) {
      settleMutation(operation, false, Boolean(e.uncertain));
      if (!mounted.current) return;
      if (['unauthenticated', 'step_up_required'].includes(e.code || e.message)) { feedback.reset(); return; }
      setSaveUncertain(Boolean(draftState.current?.uncertain));
      setTechnical(feedbackTechnical(e));
      setOutcomeOpen(true);
      setOutcomeErrors({});
      setAlertMessage(e.uncertain ? 'The save result could not be confirmed. Details follow the save button.'
        : "Couldn't save. Details follow the save button.");
      feedback.finish('error');
      if (e.status === 422 && e.data?.errors) {
        const fieldErrors = normalizeClientErrors(e.data.errors);
        setServerErrs(fieldErrors);
        setOutcomeErrors(fieldErrors);
        setSaveErr(Object.keys(fieldErrors).length
          ? "Couldn't save. Review the errors below, then try again."
          : `Couldn't save. ${apiErrorMessage(e)}`);
      } else if (isNew && e.status === 409 && (e.code === 'client_id_taken' || e.data?.error === 'client_id_taken')) {
        setExistingClientId(normalizeSlug(f.client_id).value);
        setServerErrs({ client_id: 'This client ID is already taken' });
        setOutcomeErrors({ client_id: 'This client ID is already taken' });
        setSaveErr("Couldn't save. This client ID is already taken. Open its existing registration or choose another ID.");
      } else {
        setSaveUncertain(Boolean(draftState.current?.uncertain));
        setSaveErr(e.uncertain
          ? `The save result could not be confirmed. ${apiErrorMessage(e)}`
          : `Couldn't save. ${apiErrorMessage(e)}`);
      }
    }
  };

  const lifecycle = async (action) => {
    if (busy || feedback.state !== 'idle') return;
    const operation = beginMutation();
    setOutcomeKind('action');
    setBusy(true);
    setSaveErr(null);
    setSaveUncertain(false);
    setOutcomeOpen(false);
    setOutcomeErrors({});
    setTechnical('');
    setAlertMessage('');
    try {
      if (action === 'disable') await disableClient(id);
      if (action === 'enable') await enableClient(id);
      if (action === 'delete') {
        await deleteClient(id);
        settleMutation(operation, true);
        if (!mounted.current) return;
        nav('/', { replace: true });
        return;
      }
      settleMutation(operation, true);
      if (!mounted.current) return;
      setModal(null);
      await load();
    } catch (e) {
      settleMutation(operation, false, Boolean(e.uncertain));
      if (!mounted.current) return;
      if (!['unauthenticated', 'step_up_required'].includes(e.code || e.message)) {
        setOutcomeOpen(true);
        setTechnical(feedbackTechnical(e));
        setAlertMessage(e.uncertain ? 'The action result could not be confirmed. Details follow the save button.' : 'Action failed. Details follow the save button.');
        setSaveUncertain(Boolean(draftState.current?.uncertain));
        setSaveErr(e.uncertain
          ? `The action result could not be confirmed. ${apiErrorMessage(e)}`
          : `Action failed. ${apiErrorMessage(e)}`);
      }
      setModal(null);
    } finally {
      if (mounted.current) setBusy(false);
    }
  };

  if (loadErr) {
    return (
      <>
        <button className="back" onClick={() => nav('/clients')}>
          <Icon name="chevron" size={15} className="back-chev" />
          Clients
        </button>
        <p className="err" role="alert">Couldn't load this client. {loadErr.code === 'client_not_found'
          ? 'This client registration could not be found.' : apiErrorMessage(loadErr)}</p>
        {saveUncertain && <p className="err">{saveErr}</p>}
        <button className="btn" onClick={load}>Retry</button>
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
            <ErrorGroup errorKey="redirect_paths">
          <Field label="Redirect paths" note="the app's callback endpoint — exact match"><SkelInput /></Field>
            </ErrorGroup>
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

      <ClientErrorContext.Provider value={errorMarks}>
      <div className="card pad rp-client-form">
        <fieldset className="form" disabled={formLocked} aria-busy={formLocked} style={{ border: 0, padding: 0, margin: 0, minWidth: 0 }}>
          <div className="grid2">
            {isNew ? (
              <Field label="Client ID" note="immutable — lowercase slug" error={displayErrs.client_id}>
                <ErrorInput
                  className={'input mono' + (errorMarks.client_id ? ' bad' : '')}
                  errorKey="client_id"
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
            <Field label="Display name" error={displayErrs.name}>
              <ErrorInput
                className={'input' + (errorMarks.name ? ' bad' : '')}
                errorKey="name"
                  value={f.name}
                onChange={(e) => { set({ name: e.target.value }); setErr('name', null); }}
                onBlur={blurName}
              />
            </Field>
          </div>

          <div className="inline-row">
            <div className="grow">
              <Field label="Hostname" note="https only — no scheme, path, or port" error={displayErrs.hostname}>
                <ErrorInput
                  className={'input mono'}
                  errorKey="hostname"
                  value={f.hostname}
                  placeholder="app.dreamxwarden.ca"
                  onChange={(e) => { set({ hostname: e.target.value }); setErr('hostname', null); }}
                  onBlur={blurHostname}
                />
              </Field>
            </div>
            <button className="btn" style={{ marginTop: 22 }} onClick={fillStandard} disabled={!f.hostname || !!displayErrs.hostname}>
              Fill standard paths
            </button>
          </div>

          <ErrorGroup errorKey="redirect_paths">
          <Field label="Redirect paths" note="the app's callback endpoint — exact match" error={displayErrs.redirect_paths}>
            {f.redirect_paths.map((p, i) => (
              <div className="uri-row" key={i}>
                <div style={{ flex: 1 }}>
                  <ErrorInput
                    className={'input mono'}
                    errorKey={`redirect_paths.${i}`}
                    value={p}
                    placeholder="/auth/callback"
                    onChange={(e) => {
                      set({ redirect_paths: f.redirect_paths.map((x, j) => (j === i ? e.target.value : x)) });
                      setErr(`redirect_paths.${i}`, null);
                      setErr('redirect_paths', null);
                    }}
                    onBlur={() => blurPath('redirect_paths', i)}
                  />
                </div>
                {f.redirect_paths.length > 1 && (
                  <button
                    className="iconbtn"
                    title="Remove"
                    aria-label="Remove redirect path"
                    onClick={() => {
                      set({ redirect_paths: f.redirect_paths.filter((_, j) => j !== i) });
                      setErrs((cur) => removeRedirectErrors(cur, i));
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

          </ErrorGroup>
          <Field label="Back-channel events path" note="logout + role changes; optional" error={displayErrs.events_path}>
            <ErrorInput
              className={'input mono'}
              errorKey="events_path"
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
                <ErrorInput type="radio" checked={f.key_mode === 'uri'} onChange={() => set({ key_mode: 'uri' })} />
                Fetch from jwks_uri
              </label>
              <label>
                <ErrorInput type="radio" checked={f.key_mode === 'inline'} onChange={() => set({ key_mode: 'inline' })} />
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
                <ErrorInput
                  className={'input mono'}
                  errorKey="jwks_path"
                  value={f.jwks_path}
                  placeholder="/.well-known/jwks.json"
                  onChange={(e) => { set({ jwks_path: e.target.value }); setErr('jwks_path', null); }}
                  onBlur={() => blurPath('jwks_path')}
                />
                {externalJwksUri && !f.jwks_path && (
                  <p className="hint">
                    Currently external: <span className="mono">{externalJwksUri}</span> — enter a path to replace it, or
                    leave blank to keep.
                  </p>
                )}
              </>
            ) : (
              <>
                <ErrorInput as="textarea"
                  className={'input mono'}
                  errorKey="jwks"
                  value={f.jwks_text}
                  placeholder='{"keys":[{"kty":"OKP","crv":"Ed25519", ...}]}'
                  onChange={(e) => { set({ jwks_text: e.target.value }); setErr('jwks', null); }}
                  onBlur={blurJwksText}
                />
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
              <ErrorGroup errorKey="allowed_scopes" className="checks">
                {SCOPES.map((s) => (
                  <label key={s}>
                    <ErrorInput
                      type="checkbox"
                      checked={f.allowed_scopes.includes(s)}
                      disabled={s === 'openid'}
                      onChange={(e) => {
                        set({
                          allowed_scopes: e.target.checked
                            ? [...f.allowed_scopes, s]
                            : f.allowed_scopes.filter((x) => x !== s),
                        });
                        setErr('allowed_scopes', null);
                      }}
                    />
                    {s}
                  </label>
                ))}
              </ErrorGroup>
            </div>
            <div className="field">
              <span>Trust &amp; entry</span>
              <div className="checks">
                <ErrorGroup errorKey="is_first_party"><label>
                  <ErrorInput
                    type="checkbox"
                    checked={f.is_first_party}
                    onChange={(e) => { set({ is_first_party: e.target.checked }); setErr('is_first_party', null); }}
                  />
                  First-party
                </label></ErrorGroup>
                <ErrorGroup errorKey="entry_policy"><label>
                  Entry:&nbsp;
                  <select
                    className="input"
                    style={{ width: 'auto', padding: '4px 8px' }}
                    value={f.entry_policy}
                    onChange={(e) => { set({ entry_policy: e.target.value }); setErr('entry_policy', null); }}
                  >
                    <option value="opt_in">opt_in</option>
                    <option value="baseline">baseline</option>
                  </select>
                </label></ErrorGroup>
              </div>
            </div>
          </div>

        </fieldset>
          <div className="form-actions rp-form-actions">
            <SaveButton state={feedback.state} label={isNew ? 'Register client' : 'Save changes'}
              disabled={!canSave} onClick={save} describedBy={'rp-action-note' + (showOutcome ? ' rp-outcome-title' : '')} />
            <span className="rp-action-note" id="rp-action-note">
              {draftSettled ? 'Previous action confirmed. Check the registration before editing.' : draftOmitted.length > 0 ? 'Re-enter the omitted fields or discard this draft.' : missing.length > 0 ? `Required: ${missing.join(', ')}.`
                : hasErrors ? 'Correct the marked fields before saving.'
                  : !isNew && !dirty ? 'No unsaved changes' : ''}
            </span>
          </div>
          <OutcomePanel open={showOutcome && feedback.state !== 'pending'}
            title={saveUncertain ? 'Could not confirm the result' : saveErr ? (outcomeKind === 'action' ? 'Action failed' : "Couldn't save") : 'Review these fields'}
            technical={technical} reserve={scrollReserve.reserve} release={scrollReserve.release}>
            {saveErr && <p>{saveErr}</p>}
            {saveUncertain && isNew && <p><Link to="/clients">Check the client list</Link> before trying again; the registration may already exist.</p>}
            {saveUncertain && !isNew && <p><button className="btn" onClick={load} disabled={formLocked}>Reload registration</button></p>}
            {existingClientId && <p><Link to={'/clients/' + encodeURIComponent(existingClientId)}>Open existing registration</Link></p>}
            {errorItems.length > 0 && <ol className="rp-error-list">{errorItems.map(([key, message], index) => (
              <li key={key} id={`rp-error-${index + 1}`} className={errorMarks[key] ? '' : 'rp-error-edited'}>
                <span className="rp-error-number" aria-hidden="true">{index + 1}</span>
                <div>{canFocusError(key) ? <button type="button" className="rp-error-link" onClick={() => focusField(key)}>{clientErrorLabel(key)}</button> : <strong>{clientErrorLabel(key)}</strong>}
                  {!errorMarks[key] && <span className="rp-edited-tag">Edited</span>}
                  <p>{keyFieldFeedback(key, message).message}</p></div>
              </li>
            ))}</ol>}
          </OutcomePanel>
      <div className="rp-draft-recovery" role="status" style={{ marginTop: 14 }}>
        {draftNotice && <p>{draftNotice}</p>}
        {draftOmitted.length > 0 && <p>Some fields could not be kept safely: {draftOmitted.map((key) => clientErrorLabel(key === 'jwks_text' ? 'jwks' : key)).join(', ')}. Re-enter these fields before saving; public keys and URL values must be reviewed.</p>}
        {draftStorageNotice && <p>{draftStorageNotice}</p>}
        {draftSettled && <p><Link to="/clients">Check the client list</Link>{!isNew && <> or <button className="btn" onClick={load}>Reload registration</button></>}</p>}
        <button className="btn" disabled={formLocked || (!dirty && !draftNotice)} onClick={() => {
          stopRecoveredObservation();
          setDraftSettled(false);
          const cleared = clearClientDraft(subject, draftRoute);
          draftDisabled.current = true;
          draftState.current = null;
          setDraftNotice(''); setDraftStorageNotice(cleared ? '' : 'The saved draft could not be removed. Close this tab to discard its recovery data.'); setDraftOmitted([]);
          setErrs({}); setServerErrs({}); setSaveErr(null); setSaveUncertain(false);
          setOutcomeOpen(false); setOutcomeErrors({}); setTechnical(''); setAlertMessage('');
          if (isNew) { setF(emptyForm); baseForm.current = emptyForm; setSnap(surface(emptyForm)); }
          else load({ recover: false });
        }}>Discard unsaved edits</button>
      </div>


          <div className="rp-sr-only" role="status">{feedback.state === 'pending' ? (isNew ? 'Registering client…' : 'Saving changes…') : feedback.state === 'success' ? (isNew ? 'Client registered.' : 'Changes saved.') : ''}</div>
          <div className="rp-sr-only" role="alert">{feedback.state === 'pending' ? '' : alertMessage}</div>
      </div>

      </ClientErrorContext.Provider>

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
                <button className="btn" onClick={() => setModal('enable')} disabled={busy || feedback.state !== 'idle'}>
                  Enable
                </button>
              ) : (
                <button className="btn btn-danger" onClick={() => setModal('disable')} disabled={busy || feedback.state !== 'idle'}>
                  Disable
                </button>
              )}
              <button
                className="btn btn-danger"
                onClick={() => { setDeleteConfirm(''); setModal('delete'); }}
                disabled={busy || feedback.state !== 'idle' || !row?.disabled_at}
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
            <button className="btn btn-danger" onClick={() => lifecycle('disable')} disabled={busy || feedback.state !== 'idle'}>
              {busy ? 'Disabling…' : 'Disable'}
            </button>
            <button className="btn" onClick={() => setModal(null)} disabled={busy || feedback.state !== 'idle'}>
              Cancel
            </button>
          </div>
        </Modal>
      )}
      {modal === 'enable' && (
        <Modal title={`Enable ${row?.name}?`} onClose={() => setModal(null)}>
          <p className="modal-msg">Sign-ins to this application resume immediately.</p>
          <div className="modal-actions">
            <button className="btn btn-primary" onClick={() => lifecycle('enable')} disabled={busy || feedback.state !== 'idle'}>
              {busy ? 'Enabling…' : 'Enable'}
            </button>
            <button className="btn" onClick={() => setModal(null)} disabled={busy || feedback.state !== 'idle'}>
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
          <ErrorInput
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
              disabled={busy || feedback.state !== 'idle' || deleteConfirm !== id}
            >
              {busy ? 'Deleting…' : 'Delete permanently'}
            </button>
            <button className="btn" onClick={() => setModal(null)} disabled={busy || feedback.state !== 'idle'}>
              Cancel
            </button>
          </div>
        </Modal>
      )}
      <div ref={scrollReserve.spacer} aria-hidden="true" />
    </>
  );
}
