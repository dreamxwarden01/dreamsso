import test from 'node:test';
import assert from 'node:assert/strict';
import { createInvitationListEngine } from './invitationListEngine.js';
import { DEFAULT_QUERY } from './invitationModel.js';
function fixture() {
  let time = 0, next = 0; const jobs = new Map(), requests = [], states = [];
  const engine = createInvitationListEngine({ now: () => time, schedule: (fn, delay) => { const id = ++next; jobs.set(id, { fn, at: time + delay }); return id; }, cancel: (id) => jobs.delete(id),
    request: (query, signal) => new Promise((resolve, reject) => requests.push({ query, signal, resolve, reject, at: time })), publish: (s) => states.push(s) });
  const flush = async () => { for (let i = 0; i < 5; i++) await Promise.resolve(); };
  const advance = async (target) => { for (;;) { const first = [...jobs].filter(([, j]) => j.at <= target).sort((a, b) => a[1].at - b[1].at)[0]; if (!first) break; const [id, job] = first; jobs.delete(id); time = job.at; job.fn(); await flush(); } time = target; };
  return { engine, jobs, requests, states, advance, flush };
}
const page = (number = 1, size = 10) => ({ items: [{ id: 'page-' + number, mail: { state: 'none' } }], page: number, pageSize: size, pages: Math.ceil(49 / size), total: 49, counts: { all: 49, current: 10, history: 39 } });

test('search debounce and dispatch spacing coalesce requests; quiet mail polls cannot interrupt user intent', async () => {
  const f = fixture(); f.engine.load({ ...DEFAULT_QUERY, query: 'a' }, { debounce: true });
  await f.advance(100); assert.equal(f.engine.getState().overlay, true); f.engine.refresh({ quiet: true });
  await f.advance(200); f.engine.update({ query: 'alex' }, { debounce: true }); assert.equal(f.engine.getState().overlay, true, 'retargeting keeps an existing overlay');
  await f.advance(699); assert.equal(f.requests.length, 0); await f.advance(700); assert.equal(f.requests.length, 1); assert.equal(f.requests[0].query.query, 'alex');
  f.engine.update({ page: 2 }); assert.equal(f.requests[0].signal.aborted, true);
  f.requests[0].resolve(page()); await f.flush(); assert.equal(f.engine.getState().data, null);
  await f.advance(1450); assert.equal(f.requests.length, 2); assert.equal(f.requests[1].at - f.requests[0].at, 750);
  f.requests[1].resolve(page(2)); await f.flush(); assert.equal(f.engine.getState().data.page, 2); assert.equal(f.engine.getState().overlay, false); f.engine.dispose();
});
test('committed page size/range survives pending retargets and error retry keeps its requested page', async () => {
  const f = fixture(); f.engine.load(DEFAULT_QUERY); await f.advance(0); f.requests[0].resolve(page(3)); await f.flush();
  f.engine.update({ page: 1, pageSize: 25 }); assert.equal(f.engine.getState().query.pageSize, 25); assert.equal(f.engine.getState().data.pageSize, 10); assert.equal(f.engine.getState().data.page, 3);
  await f.advance(750); f.requests[1].resolve(page(1, 25)); await f.flush();
  f.engine.update({ page: 2 }); await f.advance(1500); f.requests[2].reject({ code: 'network_error' }); await f.flush();
  assert.equal(f.engine.getState().query.page, 2); assert.equal(f.engine.getState().data.page, 1); assert.equal(f.engine.getState().data.pageSize, 25);
  f.engine.refresh(); await f.advance(2250); assert.equal(f.requests[3].query.page, 2); f.requests[3].resolve(page(2, 25)); await f.flush(); f.engine.dispose();
});
test('fresh cache commits once without a loading flash, and only three pages are retained', async () => {
  const f = fixture();
  for (let n = 1; n <= 5; n++) { f.engine.load({ ...DEFAULT_QUERY, page: n }); await f.advance((n - 1) * 750); f.requests.at(-1).resolve(page(n)); await f.flush(); }
  const calls = f.requests.length, states = f.states.length; f.engine.update({ page: 4 });
  assert.equal(f.requests.length, calls); assert.equal(f.states.length, states + 1); assert.equal(f.engine.getState().pending, false); assert.equal(f.engine.getState().data.page, 4);
  f.engine.update({ page: 1 }); assert.equal(f.engine.getState().pending, true); await f.advance(3750); assert.equal(f.requests.length, calls + 1); f.engine.dispose();
});
test('dispose aborts work, cancels both timers and rejects stale completion without a late paint', async () => {
  const f = fixture(); f.engine.load(DEFAULT_QUERY); await f.advance(0); const count = f.states.length;
  f.engine.dispose(); assert.equal(f.requests[0].signal.aborted, true); assert.equal(f.jobs.size, 0);
  f.requests[0].resolve(page()); await f.flush(); assert.equal(f.states.length, count);
});
test('a mutation invalidation restores committed controls when cancelling a debounced search or pending page', async () => {
  const f = fixture(); f.engine.load(DEFAULT_QUERY); await f.advance(0); f.requests[0].resolve(page()); await f.flush();
  f.engine.update({ query: 'new search', page: 1 }, { debounce: true }); assert.equal(f.engine.getState().pending, true);
  f.engine.invalidate(); assert.deepEqual(f.engine.getState().query, f.engine.getState().committedQuery); assert.equal(f.engine.getState().query.query, '');
  assert.equal(f.engine.getState().pending, false); assert.equal(f.engine.getState().overlay, false); await f.advance(750); assert.equal(f.requests.length, 1);
  f.engine.update({ page: 2 }); await f.advance(750); assert.equal(f.requests.length, 2);
  f.engine.invalidate(); assert.equal(f.requests[1].signal.aborted, true); assert.equal(f.engine.getState().query.page, 1);
  f.requests[1].resolve(page(2)); await f.flush(); assert.equal(f.engine.getState().data.page, 1); assert.equal(f.engine.getState().query.page, 1); f.engine.dispose();
});
