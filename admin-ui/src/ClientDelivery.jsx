import { useEffect, useRef, useState } from 'react';
import { apiErrorMessage, getClientDelivery, recoverClientDelivery } from './api.js';
import { SaveButton, useSaveFeedback } from './SaveFeedback.jsx';
import { clearRecovery, deliveryOutcome, pendingRecovery, recoveryMessage, recoveryRequest, retainRecovery } from './clientDelivery.js';

const uncertainMessage = 'Recovery may already be queued. Resync access retries the same request; it does not replay old access grants.';

export default function ClientDelivery({ client, owner, locked, dirty, onBusyChange }) {
  const [summary, setSummary] = useState(null), [loading, setLoading] = useState(true);
  const [message, setMessage] = useState(''), [failed, setFailed] = useState(false), [readError, setReadError] = useState(false);
  const feedback = useSaveFeedback(), mounted = useRef(true), generation = useRef(0), messageKind = useRef('');
  const load = async () => {
    const current = ++generation.current;
    setLoading(true); setReadError(false);
    try {
      const result = await getClientDelivery(client.client_id);
      if (mounted.current && generation.current === current) {
        setSummary(result.delivery);
        if (messageKind.current === 'read') { setMessage('Delivery status refreshed.'); setFailed(false); messageKind.current = ''; }
      }
    } catch (error) {
      if (!mounted.current || generation.current !== current) return;
      if (!['unauthenticated', 'step_up_required'].includes(error.code)) {
        messageKind.current = 'read'; setReadError(true); setMessage(`Delivery status unavailable. ${apiErrorMessage(error)}`); setFailed(true);
      }
    } finally {
      if (mounted.current && generation.current === current) setLoading(false);
    }
  };
  useEffect(() => {
    mounted.current = true;
    try { if (pendingRecovery(sessionStorage, owner, client.client_id)) { messageKind.current = 'operation'; setMessage(uncertainMessage); } }
    catch { /* a read-only summary does not require session storage */ }
    void load();
    return () => { mounted.current = false; generation.current++; };
  }, [owner, client]);

  const recover = async () => {
    if (locked || loading || readError || !summary?.can_recover || !feedback.begin()) return;
    messageKind.current = 'operation'; setMessage('Resynchronizing access…'); setFailed(false); onBusyChange(true);
    // Fence any earlier GET so it cannot overwrite the POST's committed summary.
    generation.current++;
    try {
      let requestId;
      try { requestId = recoveryRequest(sessionStorage, owner, client.client_id); }
      catch { throw Object.assign(new Error('recovery_storage_unavailable'), { code: 'recovery_storage_unavailable', status: 0 }); }
      const result = await recoverClientDelivery(client.client_id, requestId);
      try { clearRecovery(sessionStorage, owner, client.client_id); } catch { /* a stale receipt still replays safely */ }
      if (!mounted.current) return;
      setSummary(result.delivery); setReadError(false); setMessage(recoveryMessage(result.recovery));
      feedback.finish('success');
    } catch (error) {
      if (!retainRecovery(error)) { try { clearRecovery(sessionStorage, owner, client.client_id); } catch { /* best effort */ } }
      if (!mounted.current) return;
      if (['unauthenticated', 'step_up_required'].includes(error.code)) { feedback.reset(); return; }
      setFailed(true);
      setMessage(error.code === 'recovery_storage_unavailable'
        ? 'This tab could not retain the recovery request. Allow session storage, then try again.'
        : error.uncertain ? uncertainMessage : `Could not resynchronize access. ${apiErrorMessage(error)}`);
      feedback.finish('error');
    } finally { if (mounted.current) onBusyChange(false); }
  };

  const unavailable = loading || readError || !summary;
  const stateNote = summary?.state === 'paused' ? 'Delivery is paused while this app is disabled.'
    : summary?.state === 'unconfigured' ? 'Save a notification endpoint to resume delivery.'
    : 'Retries sign-outs and queues current access state. Previous access grants are not replayed.';
  const note = dirty ? 'Save or discard registration changes before resynchronizing access.' : stateNote;
  return <section className="card pad" aria-labelledby="client-delivery-title">
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 14 }}>
      <p className="card-title" id="client-delivery-title">Notification delivery</p>
      <button className="btn" onClick={load} disabled={locked || loading || feedback.state !== 'idle'}>Refresh</button>
    </div>
    <dl style={{ display: 'grid', gridTemplateColumns: 'repeat(4, minmax(0, 1fr))', gap: 12, margin: '18px 0', fontSize: 13 }}>
      {['pending', 'paused', 'dead', 'delivered'].map((key) => <div key={key}>
        <dt style={{ color: 'var(--mut)', textTransform: 'capitalize', marginBottom: 5 }}>{{pending:'Queued',paused:'Paused',dead:'Failed',delivered:'Delivered'}[key]}</dt>
        <dd style={{ margin: 0, fontVariantNumeric: 'tabular-nums', fontWeight: 600 }}>{unavailable ? '—' : summary.counts[key].toLocaleString()}</dd>
      </div>)}
    </dl>
    <p className="note" style={{ minHeight: '3em', margin: '0 0 14px', fontSize: 12, lineHeight: 1.5 }}>
      Counts cover retained notifications; delivered history is kept for 30 days.<br />
      {unavailable ? (loading ? 'Loading delivery status…' : 'Delivery status unavailable.') : summary.last_outcome
        ? <>{deliveryOutcome(summary.last_outcome.code)} {summary.last_outcome.at && <time dateTime={summary.last_outcome.at}>{new Date(summary.last_outcome.at).toLocaleString()}</time>}</>
        : 'No delivery outcome recorded.'}
    </p>
    <div className="form-actions" style={{ flexWrap: 'wrap', alignItems: 'flex-start' }}>
      <SaveButton state={feedback.state} label="Resync access" disabled={locked || unavailable || !summary?.can_recover}
        onClick={recover} describedBy="client-delivery-note client-delivery-feedback" />
      <span className="rp-action-note" id="client-delivery-note" style={{ flex: '1 1 240px' }}>{note}</span>
    </div>
    <div id="client-delivery-feedback" role={failed ? 'alert' : 'status'} aria-live={failed ? 'assertive' : 'polite'}
      style={{ height: '4.5em', marginTop: 12, overflowY: 'auto', overflowWrap: 'anywhere', fontSize: 13, lineHeight: 1.5, color: failed ? 'var(--danger)' : 'var(--mut)' }}>
      {message}
    </div>
  </section>;
}
