import assert from 'node:assert/strict';
import test from 'node:test';
import crypto from 'node:crypto';

test('registration handoff receipts expire in isolated Redis and cannot be rebound or extended', async () => {
  const source = process.env.DREAMSSO_AUTH_TEST_REDIS_URL;
  if (!source) throw new Error('An isolated Redis fixture is required.');
  const address = new URL(source);
  if (address.hostname !== '127.0.0.1' || address.pathname !== '/15') throw new Error('Only the generated local Redis fixture is allowed.');
  process.env.REDIS_URL = source;
  process.env.DOTENV_CONFIG_PATH = '/dev/null';
  const { rememberRegistrationHandoff, readRegistrationHandoff } = await import('../src/registrationHandoff.js');
  const { redis } = await import('../src/redis.js');
  const ticket = crypto.randomBytes(32).toString('base64url');
  const key = 'reg:handoff:' + crypto.createHash('sha256').update(ticket).digest('hex');
  const sid = crypto.randomUUID(), sub = crypto.randomUUID();
  try {
    await rememberRegistrationHandoff(ticket, { sid, sub });
    const first = await readRegistrationHandoff(ticket);
    assert.equal(first?.sid, sid); assert.equal(first?.sub, sub);
    const ttl = await redis.pttl(key); assert.ok(ttl > 0 && ttl <= 60000);
    const raw = (await redis.get(key))!; assert.ok(!raw.includes(ticket));
    // A second writer must neither replace the original binding nor reset TTL.
    await redis.pexpire(key, 30000);
    await rememberRegistrationHandoff(ticket, { sid: crypto.randomUUID(), sub: crypto.randomUUID() });
    assert.equal(await redis.get(key), raw);
    assert.ok(await redis.pttl(key) <= 30000);
    assert.deepEqual(await readRegistrationHandoff(ticket), first);
    // Expiry is checked by Redis even if the receipt's embedded deadline is later.
    await redis.pexpire(key, 0);
    assert.equal(await readRegistrationHandoff(ticket), null);
    assert.equal(await redis.exists(key), 0);
  } finally {
    await redis.del(key).catch(() => {});
    await redis.quit().catch(() => redis.disconnect());
  }
});
