import assert from 'node:assert/strict';
import test from 'node:test';
import { randomBytes, randomUUID, createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { createServer, type Server } from 'node:http';
import express from 'express';
import cookieParser from 'cookie-parser';
import pg from 'pg';

// All persistence, session loading, cookie parsing and routing below are real.
// Only generated local stores and a loopback HTTP listener are allowed. The
// browser's Secure cookie is carried explicitly; redirects are never followed.
test('welcome replay is bound to the real browser cookie and live PostgreSQL session', async t => {
  const source = process.env.DREAMSSO_ROLE_SYNC_TEST_DATABASE_URL;
  const redisSource = process.env.DREAMSSO_AUTH_TEST_REDIS_URL;
  if (!source || !redisSource) throw new Error('Generated PostgreSQL and Redis fixtures are required.');
  const address = new URL(source), redisAddress = new URL(redisSource);
  if (address.hostname !== '127.0.0.1' || address.pathname !== '/dreamsso_role_sync_test' ||
      redisAddress.hostname !== '127.0.0.1' || redisAddress.pathname !== '/15') {
    throw new Error('Only generated loopback PostgreSQL/Redis fixtures are allowed.');
  }
  const schema = 'welcome_cookie_' + randomUUID().replaceAll('-', '');
  const admin = new pg.Pool({ connectionString: source, max: 2 });
  address.searchParams.set('options', `-c search_path=${schema},public`);
  process.env.DATABASE_URL = address.href;
  process.env.REDIS_URL = redisSource;
  process.env.DOTENV_CONFIG_PATH = '/dev/null';
  process.env.KEY_ENCRYPTION_KEY = randomBytes(32).toString('hex');
  process.env.ISSUER = 'https://welcome.example.invalid';
  process.env.ACCOUNT_PORTAL_URL = 'https://account.example.invalid';
  const { pool } = await import('../src/db.js');
  const { redis } = await import('../src/redis.js');
  const { mintLoginTicket } = await import('../src/passwordReset.js');
  const { registerRouter } = await import('../src/routes/register.js');
  const { setSetting } = await import('../src/settings.js');
  const ownedKeys = new Set<string>();
  const routeErrors: string[] = [];
  const app = express();
  app.disable('x-powered-by');
  app.use(cookieParser());
  app.use(registerRouter);
  app.use((error: any, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    routeErrors.push(typeof error?.code === 'string' ? error.code : 'route_failure');
    res.status(500).json({ error: 'route_failure' });
  });
  let server: Server | undefined, base = '', created = false;
  const ticketHash = (ticket: string) => createHash('sha256').update(ticket).digest('hex');
  const recipient = async () => {
    const sub = randomUUID();
    await pool.query("INSERT INTO identities(sub,username,display_name,status) VALUES($1,$2,'Synthetic recipient','active')", [sub, 'welcome_' + sub.slice(0, 12)]);
    return sub;
  };
  const issue = async (sub: string) => {
    const ticket = await mintLoginTicket({ sub, amr: ['email'], acr: 'urn:dreamsso:1fa', userLabel: 'Synthetic recipient' });
    const hash = ticketHash(ticket);
    ownedKeys.add('pwreset:ticket:' + hash);
    ownedKeys.add('reg:handoff:' + hash);
    return ticket;
  };
  const request = async (ticket: string, cookie?: string, method = 'GET') => {
    let response: Response;
    try {
      response = await fetch(base + '/welcome?ticket=' + encodeURIComponent(ticket), {
        method, redirect: 'manual', signal: AbortSignal.timeout(5000),
        headers: { 'user-agent': 'Synthetic welcome integration', ...(cookie ? { cookie } : {}) },
      });
    } catch { throw new Error('Loopback welcome request failed.'); }
    const body = await response.text();
    const location = response.headers.get('location');
    if (location?.startsWith('/login?txn=')) {
      const txn = new URL(location, base).searchParams.get('txn');
      assert.ok(txn && /^[A-Za-z0-9_-]+$/.test(txn), 'Expected a bounded synthetic login transaction');
      ownedKeys.add('txn:' + txn);
    }
    return { response, body, location };
  };
  const sessionRows = async (sub: string) => (await pool.query(
    'SELECT sid,auth_time,stepup_at,persistent FROM sessions WHERE user_sub=$1 ORDER BY created_at,sid', [sub],
  )).rows;
  const begin = async (sub: string) => {
    const ticket = await issue(sub);
    const first = await request(ticket);
    assert.equal(first.response.status, 302);
    assert.ok(first.location?.startsWith('/login?txn='), 'Fresh redemption must continue to its KMSI transaction');
    const header = first.response.headers.get('set-cookie') || '';
    assert.ok(/HttpOnly/i.test(header) && /Secure/i.test(header) && /SameSite=Lax/i.test(header), 'Session cookie security flags are required');
    const cookie = header.split(';', 1)[0];
    assert.ok(/^sso_session=[A-Za-z0-9_-]+$/.test(cookie), 'Expected one synthetic SSO cookie');
    assert.equal(first.response.headers.get('cache-control'), 'no-store');
    assert.equal(await redis.exists('pwreset:ticket:' + ticketHash(ticket)), 0, 'Authentication ticket must be consumed');
    return { ticket, cookie, receiptKey: 'reg:handoff:' + ticketHash(ticket) };
  };
  const rejected = async (ticket: string, cookie?: string) => {
    const result = await request(ticket, cookie);
    assert.equal(result.response.status, 400);
    assert.ok(result.body.includes('Link expired'), 'Invalid recovery must retain its terminal error');
    assert.ok(!result.response.headers.has('location'));
    assert.ok(!result.response.headers.has('set-cookie'), 'Denied replay must not create a session cookie');
  };
  try {
    await admin.query('CREATE EXTENSION IF NOT EXISTS citext WITH SCHEMA public');
    await admin.query('CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public');
    await admin.query(`CREATE SCHEMA ${schema}`); created = true;
    const sql = (await readFile(new URL('../db/schema.sql', import.meta.url), 'utf8')).replace(/^CREATE EXTENSION[^\n]*$/gm, '');
    await pool.query(sql);
    await setSetting('site_name', 'Synthetic welcome');
    await setSetting('account_portal_url', 'https://account.example.invalid');
    server = createServer(app);
    await new Promise<void>((resolve, reject) => {
      server!.once('error', reject);
      server!.listen(0, '127.0.0.1', resolve);
    });
    const listener = server.address();
    assert.ok(listener && typeof listener !== 'string');
    base = `http://127.0.0.1:${listener.port}`;

    await t.test('same cookie and consumed ticket resume without a second session or renewed receipt', async () => {
      const sub = await recipient(), flow = await begin(sub);
      const before = await sessionRows(sub); assert.equal(before.length, 1);
      const receipt = JSON.parse((await redis.get(flow.receiptKey))!);
      assert.ok(receipt.sid === before[0].sid && receipt.sub === sub, 'Receipt must bind the issued session and subject');
      const ttl = await redis.pttl(flow.receiptKey); assert.ok(ttl > 0 && ttl <= 60000);
      const result = await request(flow.ticket, flow.cookie);
      assert.equal(result.response.status, 302);
      assert.equal(result.location, 'https://account.example.invalid/auth/login');
      assert.equal(result.response.headers.get('cache-control'), 'no-store');
      assert.ok(!result.response.headers.has('set-cookie'), 'Recovery must not issue a new cookie');
      const after = await sessionRows(sub); assert.equal(after.length, 1);
      assert.ok(after[0].sid === before[0].sid, 'Session ID must remain unchanged');
      assert.ok(after[0].auth_time.getTime() === before[0].auth_time.getTime(), 'Recovery must not refresh authentication time');
      assert.ok(after[0].stepup_at.getTime() === before[0].stepup_at.getTime(), 'Recovery must not refresh step-up authority');
      assert.equal(after[0].persistent, false);
      assert.ok(await redis.pttl(flow.receiptKey) <= ttl, 'Reading the receipt must not extend it');
      await rejected(flow.ticket);
      assert.equal((await sessionRows(sub)).length, 1, 'Missing-cookie replay must not create a session');
    });

    await t.test('another valid SID for the same recipient cannot reuse the first session receipt', async () => {
      const sub = await recipient(), first = await begin(sub), second = await begin(sub);
      await rejected(first.ticket, second.cookie);
      assert.equal((await sessionRows(sub)).length, 2, 'Denied replay must not mint a third session');
    });

    await t.test('a different valid identity cookie cannot reuse the receipt', async () => {
      const a = await recipient(), b = await recipient(), first = await begin(a), other = await begin(b);
      await rejected(first.ticket, other.cookie);
      assert.equal((await sessionRows(a)).length, 1); assert.equal((await sessionRows(b)).length, 1);
    });

    await t.test('deleting the issued SQL session makes its receipt unusable', async () => {
      const sub = await recipient(), flow = await begin(sub);
      await pool.query('DELETE FROM sessions WHERE user_sub=$1', [sub]);
      await rejected(flow.ticket, flow.cookie);
      assert.equal((await sessionRows(sub)).length, 0);
    });

    for (const state of ['disabled', 'locked', 'deleted']) await t.test('an inactive recipient cannot resume: ' + state, async () => {
      const sub = await recipient(), flow = await begin(sub);
      if (state === 'deleted') await pool.query('UPDATE identities SET deleted_at=now() WHERE sub=$1', [sub]);
      else await pool.query('UPDATE identities SET status=$2 WHERE sub=$1', [sub, state]);
      // Deliberately keep the row to prove live identity validation, not just
      // absence of a session after the administrator's usual revocation path.
      await rejected(flow.ticket, flow.cookie);
      assert.equal((await sessionRows(sub)).length, 1);
    });

    await t.test('an expired receipt cannot fall back to an otherwise valid browser session', async () => {
      const sub = await recipient(), flow = await begin(sub);
      await redis.pexpire(flow.receiptKey, 0);
      await rejected(flow.ticket, flow.cookie);
      assert.equal((await sessionRows(sub)).length, 1);
    });

    await t.test('actual Express HEAD dispatch leaves the ticket available for the first GET', async () => {
      const sub = await recipient(), ticket = await issue(sub);
      const head = await request(ticket, undefined, 'HEAD');
      assert.equal(head.response.status, 204); assert.equal(head.body, '');
      assert.ok(!head.response.headers.has('set-cookie'));
      assert.equal((await sessionRows(sub)).length, 0);
      assert.equal(await redis.exists('pwreset:ticket:' + ticketHash(ticket)), 1);
      const first = await request(ticket); assert.equal(first.response.status, 302);
      assert.equal((await sessionRows(sub)).length, 1);
    });
    assert.equal(routeErrors.length, 0, 'Actual welcome route must not reach its server-error handler');
  } finally {
    if (server?.listening) await new Promise<void>((resolve, reject) => {
      server!.close(error => error ? reject(error) : resolve());
      server!.closeAllConnections();
    });
    if (ownedKeys.size) await redis.del(...ownedKeys).catch(() => {});
    await redis.quit().catch(() => redis.disconnect());
    await pool.end();
    if (created) await admin.query(`DROP SCHEMA ${schema} CASCADE`);
    await admin.end();
  }
});
