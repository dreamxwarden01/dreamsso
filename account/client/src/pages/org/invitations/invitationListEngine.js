import { DEFAULT_QUERY, queryKey } from './invitationModel.js';

// The same dispatcher serves search, page retargeting and quiet mail-status
// polls. Dependencies make timings, aborts and stale-response tests deterministic.
export function createInvitationListEngine({ request, publish, now = () => performance.now(), schedule = setTimeout, cancel = clearTimeout }) {
  let state = { data: null, committedQuery: null, query: { ...DEFAULT_QUERY }, pending: false, overlay: false, error: null };
  let generation = 0, timer = null, maskTimer = null, controller = null, lastDispatch = -Infinity, disposed = false;
  const cache = new Map();
  const emit = (patch) => { state = { ...state, ...patch }; if (!disposed) publish(state); };
  const stop = () => { generation++; cancel(timer); cancel(maskTimer); timer = null; maskTimer = null; controller?.abort(); controller = null; };
  const commit = (data, query) => {
    const canonical = { ...query, page: data.page, pageSize: data.pageSize };
    emit({ data, committedQuery: canonical, query: canonical, pending: false, overlay: false, error: null });
    cache.delete(queryKey(canonical)); cache.set(queryKey(canonical), { at: now(), data });
    while (cache.size > 3) cache.delete(cache.keys().next().value);
  };
  const load = (query, { debounce = false, force = false, quiet = false } = {}) => {
    if (disposed) return;
    const wasVisible = state.overlay;
    stop(); const current = generation, requested = { ...query }; state = { ...state, query: requested };
    const key = queryKey(requested), hit = cache.get(key);
    if (!force && hit && now() - hit.at < 15000) { cache.delete(key); cache.set(key, hit); commit(hit.data, requested); return; }
    emit({ pending: true, error: null, overlay: quiet ? false : wasVisible });
    if (!quiet && !wasVisible) maskTimer = schedule(() => { if (current === generation && state.pending) emit({ overlay: true }); }, 100);
    timer = schedule(async () => {
      if (current !== generation || disposed) return;
      lastDispatch = now(); controller = new AbortController();
      try {
        const data = await request(requested, controller.signal);
        if (current !== generation || disposed) return;
        cancel(maskTimer); commit(data, requested);
      } catch (error) {
        if (current !== generation || disposed) return;
        cancel(maskTimer); emit({ pending: false, overlay: false, error });
      }
    }, Math.max(debounce ? 500 : 0, 750 - (now() - lastDispatch), 0));
  };
  return { getState: () => state, load,
    update(patch, options) { load({ ...state.query, ...patch }, options); },
    refresh(options = {}) { if (options.quiet && state.pending) return; load(state.query, { ...options, force: true }); },
    invalidate() { stop(); cache.clear(); emit({ query: state.committedQuery ? { ...state.committedQuery } : state.query, pending: false, overlay: false }); },
    dispose() { stop(); disposed = true; cache.clear(); },
  };
}
