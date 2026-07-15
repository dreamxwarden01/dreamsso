import { useCallback, useEffect, useState } from 'react';
import { useOutletContext } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext.jsx';
import { getOrgLogs, clearOrgLogs } from '../../api.js';
import { Ph } from '../../components/Skeleton.jsx';

// The server stores and serves UTC only; grouping is pure presentation in the
// viewer's local timezone.
function bucketOf(iso) {
  const d = new Date(iso);
  const now = new Date();
  const day = (x) => new Date(x.getFullYear(), x.getMonth(), x.getDate()).getTime();
  const days = Math.round((day(now) - day(d)) / 86400000);
  if (days <= 0) return 'Today';
  if (days === 1) return 'Yesterday';
  if (days <= 7) return 'Previous 7 days';
  if (days <= 30) return 'Previous 30 days';
  return 'Earlier';
}
const fmtTime = (iso) =>
  new Date(iso).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });

// First group of placeholder entries — shared by the pane's own loading state
// and the gate-level skeleton.
function LogsPlaceholderGroup() {
  return (
    <>
      <h2 className="section">Today</h2>
      <div className="card">
        {Array.from({ length: 5 }).map((_, i) => (
          <div className="row" key={i}>
            <p className="k" style={{ fontSize: 13, flex: 1, minWidth: 0, margin: 0 }}><Ph w={`${55 - i * 5}%`} /></p>
            <p className="text-faint" style={{ margin: 0, fontSize: 12 }}><Ph w={70} /></p>
          </div>
        ))}
      </div>
    </>
  );
}

// Full-pane placeholder for the org gate: static controls chrome (inert) +
// the placeholder group, matching what the live pane paints while loading.
export function LogsSkeleton() {
  const { can } = useAuth();
  return (
    <>
      <h1>Logs</h1>
      <p className="sub">Organization audit log — who did what, newest first. Cleared entries are hidden, never deleted.</p>
      <div style={{ display: 'flex', alignItems: 'center', gap: 14, marginBottom: 12 }}>
        <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 13, color: 'var(--mut)' }}>
          <input type="checkbox" defaultChecked={false} />
          Show cleared
        </label>
        {can('org.logs.clear') && <button className="btn" disabled>Clear selected</button>}
      </div>
      <LogsPlaceholderGroup />
    </>
  );
}

export default function OrgLogsPage() {
  const { can } = useAuth();
  const { recheckStepup } = useOutletContext() ?? {};
  const [entries, setEntries] = useState(null);
  const [cursor, setCursor] = useState(null);
  const [includeCleared, setIncludeCleared] = useState(false);
  const [sel, setSel] = useState(() => new Set());
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);

  const load = useCallback(async (showCleared, after) => {
    try {
      const d = await getOrgLogs({ includeCleared: showCleared, cursor: after || undefined });
      setEntries((cur) => (after && cur ? [...cur, ...d.entries] : d.entries));
      setCursor(d.next_cursor);
      setErr(null);
    } catch (e) {
      if (e.message !== 'unauthenticated') setErr(e.code || 'error');
    }
  }, []);
  useEffect(() => {
    setEntries(null);
    setSel(new Set());
    load(includeCleared);
  }, [includeCleared, load]);

  const toggle = (id) =>
    setSel((cur) => {
      const next = new Set(cur);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  const doClear = async () => {
    setBusy(true);
    setErr(null);
    try {
      await clearOrgLogs([...sel]);
      setSel(new Set());
      await load(includeCleared);
    } catch (e) {
      if (e.message === 'unauthenticated') return;
      if (e.code === 'step_up_required') {
        recheckStepup?.(); // sudo window expired mid-session — re-verify
      } else {
        setErr(e.code || 'error');
      }
    } finally {
      setBusy(false);
    }
  };

  const canClear = can('org.logs.clear');

  return (
    <>
      <h1>Logs</h1>
      <p className="sub">Organization audit log — who did what, newest first. Cleared entries are hidden, never deleted.</p>

      <div style={{ display: 'flex', alignItems: 'center', gap: 14, marginBottom: 12 }}>
        <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 13, color: 'var(--mut)' }}>
          <input type="checkbox" checked={includeCleared} onChange={(e) => setIncludeCleared(e.target.checked)} />
          Show cleared
        </label>
        {canClear && (
          <button className="btn" disabled={busy || sel.size === 0} onClick={doClear}>
            {busy ? 'Clearing…' : `Clear selected${sel.size ? ` (${sel.size})` : ''}`}
          </button>
        )}
      </div>
      {err && <p className="err">Couldn't {busy ? 'clear' : 'load'} the log. [{err}]</p>}

      {!entries && <LogsPlaceholderGroup />}
      {entries && entries.length === 0 && (
        <div className="card"><div className="row"><p className="k">No log entries{includeCleared ? '' : ' (try “Show cleared”)'}.</p></div></div>
      )}

      {entries && entries.length > 0 && (() => {
        const groups = [];
        for (const e of entries) {
          const b = bucketOf(e.created_at);
          if (!groups.length || groups[groups.length - 1].label !== b) groups.push({ label: b, items: [] });
          groups[groups.length - 1].items.push(e);
        }
        return groups.map((g) => (
          <div key={g.label}>
            <h2 className="section">{g.label}</h2>
            <div className="card" style={{ marginBottom: 14 }}>
              {g.items.map((e) => (
                <div className="row" key={e.id} style={e.cleared_at ? { opacity: 0.55 } : undefined}>
                  {canClear && !e.cleared_at && (
                    <input type="checkbox" checked={sel.has(e.id)} onChange={() => toggle(e.id)} />
                  )}
                  {/* overflowWrap: detail JSON is one giant unbreakable token —
                      without it the line escapes the card (under the timestamp) */}
                  <p className="k" style={{ fontSize: 13, flex: 1, minWidth: 0, overflowWrap: 'anywhere' }}>
                    <strong>{e.actor_label}</strong> · {e.action}
                    {e.target_label ? <> · {e.target_label}</> : null}
                    {e.detail && Object.keys(e.detail).length > 0 && (
                      <span className="text-faint"> · {JSON.stringify(e.detail)}</span>
                    )}
                    {e.cleared_at && <span className="pill" style={{ marginLeft: 8 }}>cleared</span>}
                  </p>
                  <p className="text-faint" style={{ margin: 0, fontSize: 12, whiteSpace: 'nowrap' }}>{fmtTime(e.created_at)}</p>
                </div>
              ))}
            </div>
          </div>
        ));
      })()}

      {cursor && (
        <button className="btn" onClick={() => load(includeCleared, cursor)}>Load more</button>
      )}
    </>
  );
}
