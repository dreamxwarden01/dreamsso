import { useEffect, useState } from 'react';

// Top-center toast rack: `toast.success(msg)` / `toast.error(msg)` from
// anywhere — green/red, fades in, auto-dismisses with a fade out. Module-level
// dispatch (no context plumbing); <Toaster /> mounts once in App.
let dispatch = null;
let nextId = 1;

export const toast = {
  success: (msg) => dispatch?.({ kind: 'ok', msg }),
  error: (msg) => dispatch?.({ kind: 'err', msg }),
};

const SHOW_MS = 3200; // visible time before the fade-out starts
const FADE_MS = 400;

export function Toaster() {
  const [list, setList] = useState([]);

  useEffect(() => {
    dispatch = (t) => {
      const id = nextId++;
      setList((cur) => [...cur, { ...t, id, leaving: false }]);
      setTimeout(() => setList((cur) => cur.map((x) => (x.id === id ? { ...x, leaving: true } : x))), SHOW_MS);
      setTimeout(() => setList((cur) => cur.filter((x) => x.id !== id)), SHOW_MS + FADE_MS);
    };
    return () => { dispatch = null; };
  }, []);

  if (!list.length) return null;
  return (
    <div className="toasts">
      {list.map((t) => (
        <div key={t.id} className={'toast ' + (t.kind === 'ok' ? 'toast-ok' : 'toast-err') + (t.leaving ? ' out' : '')}>
          {t.msg}
        </div>
      ))}
    </div>
  );
}
