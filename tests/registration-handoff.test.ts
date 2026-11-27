import assert from 'node:assert/strict';
import test from 'node:test';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import ts from 'typescript';

const ticket = 'A'.repeat(43);
const sid = '11111111-1111-4111-8111-111111111111';
const sub = '22222222-2222-4222-8222-222222222222';
const root = new URL('../', import.meta.url);
function load(file: string, dependencies: Record<string, unknown>, globals = {}) {
  const exports: any = {};
  const code = ts.transpileModule(readFileSync(new URL(file, root), 'utf8'), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, esModuleInterop: true },
  }).outputText;
  vm.runInNewContext(code, { exports, require(name: string) { assert.ok(Object.hasOwn(dependencies, name), name); return dependencies[name]; },
    Date, Buffer, console: { warn() {} }, ...globals }, { filename: file });
  return exports;
}

function receiptFixture() {
  let now = 1_800_000_000_000;
  const values = new Map<string, { raw: string; expiresAt: number }>();
  const calls: any[] = [];
  const helpers = load('src/registrationHandoff.ts', {
    'node:crypto': crypto,
    './redis.js': { redis: {
      async set(key: string, raw: string, ex: string, seconds: number, nx: string) {
        calls.push(['set', key, raw, ex, seconds, nx]);
        if (!values.has(key)) values.set(key, { raw, expiresAt: now + seconds * 1000 });
        return 'OK';
      },
      async get(key: string) {
        calls.push(['get', key]); const item = values.get(key);
        return item && item.expiresAt > now ? item.raw : null;
      },
    } },
  }, { Date: { now: () => now } });
  return { ...helpers, calls, values, advance: (ms: number) => { now += ms; } };
}

test('registration recovery stores only a hashed-ticket reference, exact session binding and fixed expiry', async () => {
  const f = receiptFixture(); await f.rememberRegistrationHandoff(ticket, { sid, sub });
  const call = f.calls[0]; assert.equal(call[0], 'set');
  assert.equal(call[1], 'reg:handoff:' + crypto.createHash('sha256').update(ticket).digest('hex'));
  assert.ok(!JSON.stringify(call).includes(ticket)); assert.deepEqual(call.slice(3), ['EX', 60, 'NX']);
  const first = await f.readRegistrationHandoff(ticket); assert.equal(first.sid, sid); assert.equal(first.sub, sub);
  f.advance(59000); assert.equal((await f.readRegistrationHandoff(ticket)).expiresAt, first.expiresAt);
  assert.equal(f.calls.filter((x: any[]) => x[0] === 'set').length, 1, 'reads must not refresh expiry');
  f.advance(1000); assert.equal(await f.readRegistrationHandoff(ticket), null);
});

test('malformed tickets/receipts fail closed without leaking parse details or extending state', async () => {
  const f = receiptFixture(); assert.equal(await f.readRegistrationHandoff('short'), null); assert.equal(f.calls.length, 0);
  await assert.rejects(f.rememberRegistrationHandoff(ticket, { sid: 'not-a-session', sub }), /invalid_handoff_receipt/);
  await f.rememberRegistrationHandoff(ticket, { sid, sub }); const key = f.calls[0][1];
  for (const raw of ['{', 'null', '{}', JSON.stringify({ sid, sub, expiresAt: 0 }), JSON.stringify({ sid, sub, expiresAt: 1_800_000_600_000 })]) {
    f.values.set(key, { raw, expiresAt: 1_800_000_060_000 });
    assert.equal(await f.readRegistrationHandoff(ticket), null);
  }
});

function routeFixture(options: any = {}) {
  const routes = new Map<string, Function>(), calls: any[] = [], warnings: any[] = [];
  const receipt = options.receipt === undefined ? { sid, sub } : options.receipt;
  const live = options.session === undefined ? { sid, userSub: sub } : options.session;
  load('src/routes/register.ts', {
    express: { Router: () => Object.fromEntries(['get', 'post', 'head'].map(method => [method, (path: string, handler: Function) => routes.set(method + ':' + path, handler)])) },
    'node:crypto': crypto, argon2: {}, uuidv7: {}, '../db.js': { pool: {} },
    '../config.js': { config: { issuer: 'https://sso.example.test', accountPortalUrl: 'https://account.example.test' } },
    '../settings.js': { getSetting: async (_key: string, fallback: string) => fallback, hasSetting: () => false },
    '../oidc/sessions.js': {
      createSession: async () => { calls.push(['createSession']); return { sid }; },
      loadSession: async () => { calls.push(['loadSession']); return live; }, clientGeo: () => ({}),
    },
    '../oidc/transactions.js': { createTxn: async (data: any) => { calls.push(['createTxn', data]); return 'synthetic-kmsi'; } },
    '../email.js': {}, '../emailTemplates.js': {},
    '../events.js': { kickDrain: () => { calls.push(['kickDrain']); } },
    '../views.js': { renderErrorPage: (_nonce: string, data: any) => { calls.push(['errorPage', data]); return data.title; } },
    './security.js': {}, './reset.js': {}, '../audit.js': {}, '../registration.js': {}, '../rbac/roleChanges.js': {},
    '../invitations.js': {}, '../invitationMail.js': {}, '../registrationStore.js': {}, '../identityConflicts.js': {},
    '../passwordReset.js': { redeemLoginTicket: async (value: string) => {
      calls.push(['redeem', value]); return options.fresh ? { sub, userLabel: 'Example', amr: ['email'], acr: 'urn:example:1fa' } : null;
    } },
    '../registrationHandoff.js': {
      readRegistrationHandoff: async (value: string) => { calls.push(['receiptRead', value]); return receipt; },
      rememberRegistrationHandoff: async (value: string, binding: any) => {
        calls.push(['receiptWrite', value, binding]); if (options.receiptWriteFails) throw new Error('private-error-detail');
      },
    },
  }, { console: { warn: (...args: unknown[]) => warnings.push(args) } });
  return { calls, warnings, async request(method = 'get') {
    const res = { statusCode: 200, headers: {} as Record<string, string>, body: '', location: '',
      setHeader(name: string, value: string) { this.headers[name] = value; return this; },
      status(value: number) { this.statusCode = value; return this; }, send(value: string) { this.body = value; return this; }, end() { return this; },
      redirect(value: string) { calls.push(['redirect', value]); this.statusCode = 302; this.location = value; return this; },
    };
    await routes.get(method + ':/welcome')!({ method: method.toUpperCase(), query: { ticket }, headers: {}, cookies: {}, ip: '127.0.0.1' }, res);
    return res;
  } };
}

test('first welcome consumes once and stores the exact session receipt before its KMSI redirect', async () => {
  const f = routeFixture({ fresh: true }); const r = await f.request();
  assert.equal(r.statusCode, 302); assert.equal(r.location, '/login?txn=synthetic-kmsi');
  assert.equal(r.headers['Cache-Control'], 'no-store');
  assert.deepEqual(f.calls.map((x: any[]) => x[0]), ['redeem', 'createSession', 'createTxn', 'receiptWrite', 'redirect']);
  assert.deepEqual(JSON.parse(JSON.stringify(f.calls[3][2])), { sid, sub });
});

test('same-browser replay continues only an existing live matching SID and subject, without new authority', async () => {
  const f = routeFixture(); const r = await f.request();
  assert.equal(r.statusCode, 302); assert.equal(r.location, 'https://account.example.test/auth/login');
  assert.equal(r.headers['Cache-Control'], 'no-store'); assert.equal(r.body, '');
  assert.deepEqual(f.calls.map((x: any[]) => x[0]), ['redeem', 'receiptRead', 'loadSession', 'redirect']);
});

for (const [name, options] of [
  ['missing receipt', { receipt: null }], ['missing, revoked or expired session', { session: null }],
  ['different SID for same subject', { session: { sid: 'other-session', userSub: sub } }],
  ['different subject for same SID', { session: { sid, userSub: 'other-user' } }],
] as const) test('expired welcome still fails closed for ' + name, async () => {
  const f = routeFixture(options); const r = await f.request();
  assert.equal(r.statusCode, 400); assert.equal(r.body, 'Link expired'); assert.equal(r.location, '');
  assert.ok(!f.calls.some((x: any[]) => ['createSession', 'createTxn', 'receiptWrite'].includes(x[0])));
  assert.ok(!JSON.stringify(f.warnings).includes(ticket));
  assert.ok(!JSON.stringify(f.warnings).includes(sid));
  assert.ok(!JSON.stringify(f.warnings).includes(sub));
});

test('receipt storage failure cannot replace the already successful first sign-in', async () => {
  const f = routeFixture({ fresh: true, receiptWriteFails: true }); const r = await f.request();
  assert.equal(r.statusCode, 302); assert.equal(r.location, '/login?txn=synthetic-kmsi');
  assert.deepEqual(f.warnings, [['registration_handoff_receipt_unavailable']]);
});

test('HEAD welcome does not redeem a ticket, create a session, or inspect a receipt', async () => {
  const f = routeFixture({ fresh: true }); const r = await f.request('head');
  assert.equal(r.statusCode, 204); assert.equal(r.headers['Cache-Control'], 'no-store'); assert.deepEqual(f.calls, []);
});
