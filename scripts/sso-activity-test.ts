// E2E for RP activity reporting — POST /internal/session-activity.
//   auth: no/garbage assertion -> 401; well-formed assertion required
//   validation: malformed sid -> 400
//   happy path: live session -> 204 and last_seen advances
//   clamp: a future last_seen must NOT push the session past the idle window
//   monotonic: an older last_seen must not move it backwards
//   gone: unknown sid / idle-expired / absolute-expired -> 410 + SIGNED verdict
//   scoping: a session whose clients[] lacks our client -> 410 (can't keep
//            another RP's session alive)
// Every session row this makes is created and removed by the test.
// Run: npx tsx scripts/sso-activity-test.ts
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { SignJWT, importJWK, jwtVerify, createRemoteJWKSet } from 'jose';
import { pool } from '../src/db.js';

const SSO = 'https://sso-dev.dreamxwarden.ca';
const CLIENT = 'videosite';
const USER = 'tester';
const URL_ = SSO + '/internal/session-activity';
const KEY_FILE = path.join(process.cwd(), '.videosite-client-key.json');

let fail = 0;
const ok = (c: boolean, label: string, extra = '') => {
  console.log(`${c ? '✓' : '✗ FAIL'}  ${label}${extra ? '  ' + extra : ''}`);
  if (!c) fail++;
};

const raw = JSON.parse(fs.readFileSync(KEY_FILE, 'utf8'));
const privJwk = raw.keys?.[0] ?? raw;
const key = await importJWK(privJwk, 'EdDSA');

async function assertion(): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({})
    .setProtectedHeader({ alg: 'EdDSA', kid: privJwk.kid })
    .setIssuer(CLIENT).setSubject(CLIENT).setAudience(SSO)
    .setIssuedAt(now).setExpirationTime(now + 60).setJti(crypto.randomUUID())
    .sign(key);
}

async function report(body: Record<string, unknown>) {
  const r = await fetch(URL_, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  const text = await r.text();
  let json: any = null;
  try { json = JSON.parse(text); } catch { /* 204 has no body */ }
  return { status: r.status, json };
}

const withAssertion = async (extra: Record<string, unknown>) => report({
  client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
  client_assertion: await assertion(),
  ...extra,
});

const { rows: [{ sub }] } = await pool.query('SELECT sub FROM identities WHERE username = $1', [USER]);

// Make a session row we fully control. lastSeenAgo/createdAgo are intervals.
const made: string[] = [];
async function mkSession(opts: { lastSeen?: string; createdAt?: string; clients?: string[]; persistent?: boolean } = {}) {
  const { rows: [row] } = await pool.query<{ sid: string }>(
    `INSERT INTO sessions (user_sub, token_hash, amr, expires_at, clients, persistent, last_seen, created_at)
     VALUES ($1, $2, '{pwd}', now() + interval '30 days', $3, $4,
             now() - $5::interval, now() - $6::interval)
     RETURNING sid`,
    [sub, crypto.randomBytes(32), opts.clients ?? [CLIENT], opts.persistent ?? true,
     opts.lastSeen ?? '1 hour', opts.createdAt ?? '1 hour'],
  );
  made.push(row.sid);
  return row.sid;
}
const lastSeenOf = async (sid: string) => (await pool.query<{ last_seen: Date }>(
  'SELECT last_seen FROM sessions WHERE sid = $1', [sid])).rows[0]?.last_seen;

console.log('\n--- auth + validation ---');
let r = await report({ sid: crypto.randomUUID() });
ok(r.status === 401 && r.json?.error === 'invalid_client', 'no assertion -> 401 invalid_client', `got ${r.status}`);

r = await report({
  client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
  client_assertion: 'x.y.z', sid: crypto.randomUUID(),
});
ok(r.status === 401 && r.json?.error === 'invalid_client', 'garbage assertion -> 401', `got ${r.status}`);

r = await withAssertion({ sid: 'not-a-uuid' });
ok(r.status === 400 && r.json?.error === 'invalid_sid', 'malformed sid -> 400 invalid_sid', `got ${r.status}`);

console.log('\n--- gone (410) + signed verdict ---');
const ghost = crypto.randomUUID();
r = await withAssertion({ sid: ghost });
ok(r.status === 410 && r.json?.error === 'session_invalid', 'unknown sid -> 410 session_invalid', `got ${r.status}`);
ok(typeof r.json?.verdict === 'string' && r.json.verdict.split('.').length === 3, '410 carries a JWT verdict');

// The verdict must verify against the SSO's published keys — this is what makes
// the RP's destructive action safe to take.
const jwks = createRemoteJWKSet(new URL(SSO + '/jwks'));
try {
  const { payload, protectedHeader } = await jwtVerify(r.json.verdict, jwks, { issuer: SSO, audience: CLIENT });
  ok(payload.status === 'invalid', 'verdict verifies + status=invalid');
  ok(payload.sid === ghost, 'verdict names the reported sid');
  ok(protectedHeader.typ === 'verdict+jwt', 'verdict typ is verdict+jwt', String(protectedHeader.typ));
} catch (e) {
  ok(false, 'verdict signature verifies', (e as Error).message);
}

console.log('\n--- happy path ---');
const live = await mkSession({ lastSeen: '1 hour' });
const before = await lastSeenOf(live);
r = await withAssertion({ sid: live, last_seen: Date.now() });
ok(r.status === 204, 'live session -> 204', `got ${r.status}`);
const after = await lastSeenOf(live);
ok(after! > before!, 'last_seen advanced', `${before?.toISOString()} -> ${after?.toISOString()}`);
ok(Math.abs(after!.getTime() - Date.now()) < 60_000, 'last_seen is ~now');

console.log('\n--- clamping + monotonicity ---');
const clampS = await mkSession({ lastSeen: '1 hour' });
await withAssertion({ sid: clampS, last_seen: Date.now() + 400 * 24 * 3600 * 1000 }); // ~400 days ahead
const clamped = await lastSeenOf(clampS);
ok(clamped!.getTime() <= Date.now() + 60_000, 'a future last_seen is clamped to now (cannot extend the idle window)',
  clamped?.toISOString());

const monoS = await mkSession({ lastSeen: '1 hour' });
const monoBefore = await lastSeenOf(monoS);
await withAssertion({ sid: monoS, last_seen: Date.now() - 10 * 24 * 3600 * 1000 }); // 10 days stale
const monoAfter = await lastSeenOf(monoS);
ok(monoAfter!.getTime() >= monoBefore!.getTime(), 'a stale last_seen never moves it backwards');

console.log('\n--- liveness windows -> 410 ---');
// Defaults: idle 72h, absolute 168h (persistent). Both must be judged gone.
const idleDead = await mkSession({ lastSeen: '100 hours', createdAt: '100 hours' });
r = await withAssertion({ sid: idleDead, last_seen: Date.now() });
ok(r.status === 410, 'idle-expired session -> 410', `got ${r.status}`);
ok((await lastSeenOf(idleDead))!.getTime() < Date.now() - 3600_000, 'a 410 did NOT resurrect last_seen');

const absDead = await mkSession({ lastSeen: '1 hour', createdAt: '200 hours' });
r = await withAssertion({ sid: absDead, last_seen: Date.now() });
ok(r.status === 410, 'absolute-expired session -> 410', `got ${r.status}`);

console.log('\n--- client scoping ---');
const foreign = await mkSession({ lastSeen: '1 hour', clients: ['some-other-app'] });
r = await withAssertion({ sid: foreign, last_seen: Date.now() });
ok(r.status === 410, "session we never participated in -> 410 (can't keep another RP's session alive)", `got ${r.status}`);
ok((await lastSeenOf(foreign))!.getTime() < Date.now() - 3000, "foreign session's last_seen untouched");

// --- cleanup ---
await pool.query('DELETE FROM sessions WHERE sid = ANY($1::uuid[])', [made]);
const { rows: left } = await pool.query('SELECT sid FROM sessions WHERE sid = ANY($1::uuid[])', [made]);
ok(left.length === 0, 'cleanup: all test sessions removed');

console.log(fail ? `\n${fail} FAILED\n` : '\nall passed\n');
await pool.end();
process.exit(fail ? 1 : 0);
