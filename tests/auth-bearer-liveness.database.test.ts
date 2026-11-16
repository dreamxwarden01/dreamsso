import assert from 'node:assert/strict';
import test from 'node:test';
import { randomUUID, randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import type { Request, Response } from 'express';
import pg from 'pg';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import { createAccountResourceAuth, type AuthedRequest } from '../src/accountResourceAuth.js';
import { readAccessTokenState } from '../src/oidc/accessTokenState.js';
import { readSessionWindows } from '../src/oidc/sessionWindows.js';
import { createUserinfoHandler } from '../src/oidc/userinfo.js';

const connectionString = process.env.DREAMSSO_ROLE_SYNC_TEST_DATABASE_URL;
test('Account and ordinary userinfo immediately honor current PostgreSQL bearer state', { skip: !connectionString }, async t => {
  const url = new URL(connectionString!);
  if (url.hostname !== '127.0.0.1' || url.pathname !== '/dreamsso_role_sync_test') throw Error('Only the generated local auth database fixture is allowed.');
  const schema = 'bearer_state_' + randomUUID().replaceAll('-', '');
  const admin = new pg.Pool({ connectionString, max: 1 });
  const database = new pg.Pool({ connectionString, max: 1, connectionTimeoutMillis: 1000,
    options: `-c search_path=${schema},public`, application_name: schema });
  const sub = randomUUID(), otherSub = randomUUID(), sid = randomUUID(), otherSid = randomUUID(), issuer = 'https://issuer.example.invalid';
  const keys = await generateKeyPair('EdDSA'), jwk = await exportJWK(keys.publicKey);jwk.kid = 'generated-bearer-state-key';
  const auth = createAccountResourceAuth({ issuer: () => issuer, accountClientId: () => 'account', jwks: async () => ({ keys: [jwk] }),
    readState: async (identity, connection) => { const db = connection ?? database;return readAccessTokenState(db, identity, await readSessionWindows(db)); } });
  const userinfo = createUserinfoHandler({ verifyAccessToken: auth.verifyAccessToken, profile: async subject => {
    const { rows } = await database.query('SELECT sub,username,display_name,email,email_verified,avatar FROM identities WHERE sub=$1', [subject]);return rows[0];
  } });
  const signed = async (client = 'account', session: string | null = sid) => {
    const now = Math.floor(Date.now() / 1000);
    return new SignJWT({ client_id: client, scope: 'openid profile email', ...(session ? { sid: session } : {}) })
      .setProtectedHeader({ alg: 'EdDSA', typ: 'at+jwt', kid: jwk.kid }).setIssuer(issuer).setAudience(issuer).setSubject(sub)
      .setIssuedAt(now).setExpirationTime(now + 900).sign(keys.privateKey);
  };
  const response = () => ({ statusCode: 200, body: undefined as unknown, status(value: number) { this.statusCode = value;return this; },
    set() { return this; }, setHeader() {}, json(value: unknown) { this.body = value;return this; } });
  const account = async (token: string) => { const res = response();let next = false;
    await auth.requireScope('profile')({ headers: { authorization: 'Bearer ' + token } } as AuthedRequest, res as unknown as Response, () => { next = true; });
    return { status: res.statusCode, next }; };
  const profile = async (token: string) => { const res = response();await userinfo({ headers: { authorization: 'Bearer ' + token } } as Request, res as unknown as Response);return res.statusCode; };
  async function reset() {
    await database.query("UPDATE identities SET status='active',deleted_at=NULL WHERE sub=$1", [sub]);
    await database.query("UPDATE oauth_clients SET disabled_at=NULL WHERE client_id IN('account','ordinary-rp')");
    await database.query('DELETE FROM sessions WHERE sid=$1', [sid]);
    await database.query("INSERT INTO sessions(sid,user_sub,token_hash,expires_at,persistent) VALUES($1,$2,$3,now()+interval '1 day',true)", [sid, sub, randomBytes(32)]);
    await database.query("UPDATE settings SET value=CASE key WHEN 'session_idle_hours' THEN '2' WHEN 'session_max_hours' THEN '4' ELSE '1' END WHERE key IN('session_idle_hours','session_max_hours','session_transient_max_hours')");
  }
  try {
    await admin.query('CREATE EXTENSION IF NOT EXISTS citext WITH SCHEMA public');await admin.query('CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public');
    await admin.query(`CREATE SCHEMA ${schema}`);
    await database.query((await readFile(new URL('../db/schema.sql', import.meta.url), 'utf8')).replace(/^CREATE EXTENSION[^\n]*$/gm, ''));
    await database.query("INSERT INTO identities(sub,username,display_name) VALUES($1,'bearer-one','Bearer one'),($2,'bearer-two','Bearer two')", [sub, otherSub]);
    await database.query("INSERT INTO oauth_clients(client_id,name,redirect_uris) VALUES('account','Account','{}'),('ordinary-rp','RP','{}')");
    await database.query("INSERT INTO settings(key,value) VALUES('session_idle_hours','2'),('session_max_hours','4'),('session_transient_max_hours','1')");
    await database.query("INSERT INTO sessions(sid,user_sub,token_hash,expires_at) VALUES($1,$2,$3,now()+interval '1 day')", [otherSid, otherSub, randomBytes(32)]);

    await t.test('normal capabilities persist, while ordinary RP still cannot enter Account resources', async () => {
      await reset();assert.deepEqual(await account(await signed()), { status: 200, next: true });
      const rp = await signed('ordinary-rp');assert.equal((await account(rp)).status, 403);assert.equal(await profile(rp), 200);
    });
    await t.test('SID deletion and foreign or missing original SID return401 on both paths', async () => {
      for (const variant of ['deleted', 'foreign', 'legacy'] as const) {
        await reset();const token = await signed('account', variant === 'foreign' ? otherSid : variant === 'legacy' ? null : sid);
        if (variant === 'deleted') await database.query('DELETE FROM sessions WHERE sid=$1', [sid]);
        assert.equal((await account(token)).status, 401);assert.equal(await profile(token), 401);
      }
    });
    await t.test('account disable/deletion and RP disable return403 immediately despite unexpired JWT', async () => {
      for (const mutation of ["UPDATE identities SET status='disabled' WHERE sub=$1", "UPDATE identities SET deleted_at=now() WHERE sub=$1",
        "UPDATE oauth_clients SET disabled_at=now() WHERE client_id='ordinary-rp'"]) {
        await reset();const token = await signed('ordinary-rp');await database.query(mutation, mutation.includes('$1') ? [sub] : []);
        assert.equal(await profile(token), 403);
      }
      await reset();await database.query("UPDATE oauth_clients SET disabled_at=now() WHERE client_id='account'");assert.equal((await account(await signed())).status, 403);
    });
    await t.test('idle and per-persistence absolute windows use current settings without stale cache', async () => {
      for (const mutation of ["last_seen=now()-interval '3 hours'", "persistent=true,created_at=now()-interval '5 hours'", "persistent=false,created_at=now()-interval '90 minutes'"]) {
        await reset();await database.query('UPDATE sessions SET ' + mutation + ' WHERE sid=$1', [sid]);
        const token = await signed();assert.equal((await account(token)).status, 401);assert.equal(await profile(token), 401);
      }
      await reset();await database.query("UPDATE sessions SET last_seen=now()-interval '90 minutes' WHERE sid=$1", [sid]);
      const token = await signed();assert.equal((await account(token)).status, 200);
      await database.query("UPDATE settings SET value='1' WHERE key='session_idle_hours'");assert.equal((await account(token)).status, 401);
    });
    await t.test('transaction-owned state and policy reads need no second pool slot', async () => {
      await reset();const token = await signed(), db = await database.connect();
      try {
        await db.query('BEGIN');
        const req = { headers: { authorization: 'Bearer ' + token } } as Request;
        assert.equal((await auth.verifyAccessToken(req, db))?.sid, sid);
        await db.query("UPDATE identities SET status='disabled' WHERE sub=$1", [sub]);
        assert.equal((await auth.verifyAccessToken(req, db))?.denied, 'access_denied');
        assert.equal(database.waitingCount, 0);await db.query('ROLLBACK');
      } finally { db.release(); }
    });
  } finally {
    await database.end();await admin.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);await admin.end();
  }
});
