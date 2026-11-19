import assert from 'node:assert/strict';
import test from 'node:test';
import { randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import pg from 'pg';
import { createInvitation, revokeInvitation, requestInvitationResend, readInvitation, listInvitations,
  validateLockedInvitation, lockInvitation, invalidateIneligibleInvitations, invitationState,
  serializeInvitation, InvitationError } from '../src/invitations.js';

const connectionString=process.env.DREAMSSO_ROLE_SYNC_TEST_DATABASE_URL;
test('single-use invitation management keeps binding, hierarchy, history and request receipts atomic', {skip:!connectionString},async t=>{
  const url=new URL(connectionString!);assert.equal(url.hostname,'127.0.0.1');assert.equal(url.pathname,'/dreamsso_role_sync_test');
  const schema='invitations_'+randomUUID().replaceAll('-','');
  const admin=new pg.Pool({connectionString,max:2});
  const db=new pg.Pool({connectionString,max:6,options:`-c search_path=${schema},public`,application_name:schema});
  const owner=randomUUID(),peer=randomUUID(),higher=randomUUID(),lower=randomUUID(),consumer=randomUUID();
  const tx=async<T>(work:(c:pg.PoolClient)=>Promise<T>)=>{
    const c=await db.connect();try{await c.query('BEGIN');await c.query("SET LOCAL lock_timeout='3s'");
      await c.query('SELECT pg_advisory_xact_lock(1145624915)');
      const result=await work(c);await invalidateIneligibleInvitations(c);await c.query('COMMIT');return result;
    }catch(e){await c.query('ROLLBACK');throw e;}finally{c.release();}
  };
  const body=(extra:Record<string,unknown>={})=>({request_id:randomUUID(),role_slug:'member',delivery:'link',...extra});
  const create=(extra:Record<string,unknown>={},actor=owner)=>tx(c=>createInvitation(c,actor,body(extra))).then(r=>r.invitation);
  const failure=(code:string,status?:number)=>(error:unknown)=>error instanceof InvitationError&&error.code===code&&(status===undefined||error.status===status);
  const locked=async(c:pg.PoolClient,id:string)=>{const row=await lockInvitation(c,id);assert.ok(row);return row;};
  try{
    await admin.query('CREATE EXTENSION IF NOT EXISTS citext WITH SCHEMA public');await admin.query('CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public');
    await admin.query(`CREATE SCHEMA ${schema}`);
    await db.query((await readFile(new URL('../db/schema.sql',import.meta.url),'utf8')).replace(/^CREATE EXTENSION[^\n]*$/gm,''));
    const migration=await readFile(new URL('../db/migrations/005-invitations.sql',import.meta.url),'utf8');await db.query(migration);await db.query(migration);
    await db.query("INSERT INTO org_roles(slug,label,level) VALUES('higher','Higher',0),('manager','Manager',10),('member','Member',100),('lowest','Lowest',200)");
    for(const [id,name,role]of [[owner,'owner','manager'],[peer,'peer','manager'],[higher,'higher','higher'],[lower,'lower','member'],[consumer,'consumer','member']]){
      await db.query('INSERT INTO identities(sub,username,display_name) VALUES($1,$2::text,$2::text)',[id,name]);
      await db.query('INSERT INTO user_org_roles(user_sub,org_role_slug) VALUES($1,$2)',[id,role]);
    }
    await db.query(`INSERT INTO role_permissions(role_slug,perm_key,effect)
      SELECT r,p,'grant' FROM unnest(ARRAY['higher','manager']) r CROSS JOIN unnest(ARRAY['org.invites.view','org.invites.create']) p`);
    await db.query("INSERT INTO role_permissions VALUES('higher','org.invites.void','grant')");

    await t.test('migration upgrades legacy pending/expired/used rows once without dropping history',async()=>{
      const legacySchema=schema+'_legacy';const legacy=new pg.Pool({connectionString,max:2,options:`-c search_path=${legacySchema},public`});
      await admin.query(`CREATE SCHEMA ${legacySchema}`);
      try{
        const source=await readFile(new URL('../db/schema.sql',import.meta.url),'utf8');
        await legacy.query(source.slice(0,source.indexOf('-- Single-use invitations:')).replace(/^CREATE EXTENSION[^\n]*$/gm,''));
        await legacy.query("INSERT INTO org_roles(slug,label,level) VALUES('member','Legacy member',100)");
        await legacy.query(`INSERT INTO invitation_codes(code,created_by_label,invited_role_slug,expires_at,pending_email,pending_at,clear_at)
          VALUES('LEGACY000001','Old creator','member',now()+interval '1 day','legacy@example.invalid',now(),now()+interval '2 days')`);
        await legacy.query(`INSERT INTO invitation_codes(code,created_by_label,expires_at,used_at)
          VALUES('LEGACY000002','Old creator',now()-interval '1 day',now()-interval '2 days')`);
        await legacy.query(migration);const before=(await legacy.query('SELECT * FROM invitation_codes ORDER BY code')).rows;
        await legacy.query(migration);const after=(await legacy.query('SELECT * FROM invitation_codes ORDER BY code')).rows;
        assert.deepEqual(after,before);assert.equal(after.length,2);
        assert.equal(after[0].bound_email,'legacy@example.invalid');assert.equal(after[0].binding_source,'first_request');
        assert.equal(after[0].invited_role_label,'Legacy member');assert.equal(after[0].clear_at,null);
        assert.equal(invitationState(after[1]),'used');assert.equal(after[1].invalidated_at,null);
      }finally{await legacy.end();await admin.query(`DROP SCHEMA IF EXISTS ${legacySchema} CASCADE`);}
    });

    await t.test('defaults, explicit delivery, immutable deadline and safe independent mail metadata',async()=>{
      const row=await create({email:' Person@Example.Invalid ',delivery:'email',note:'  Group A  '});
      assert.match(row.id,/^[0-9a-f-]{36}$/);assert.match(row.code,/^[A-Z0-9]{12}$/);
      assert.equal(row.bound_email,'person@example.invalid');assert.equal(row.binding_source,'creation');assert.equal(row.note,'Group A');
      const duration=+new Date(row.expires_at)-+new Date(row.created_at);assert.ok(duration>=72*3600000-1000&&duration<=72*3600000+1000);
      const dto=serializeInvitation(row);assert.equal(dto.status,'active');assert.equal(dto.mail.state,'none');assert.equal(dto.can_resend,true);
      await db.query("UPDATE invitation_codes SET mail_state='failed',mail_error_code='private arbitrary provider response' WHERE id=$1",[row.id]);
      const after=await tx(c=>readInvitation(c,owner,row.id));assert.equal(invitationState(after),'active');
      assert.equal(serializeInvitation(after).mail.error_code,'send_failed');assert.equal(+new Date(after.expires_at),+new Date(row.expires_at));
      for(const invalid of [{request_id:'bad'},{validity_hours:0},{validity_hours:8761},{note:'x'.repeat(61)},{email:'broken',delivery:'email'},{role_slug:'manager'}])
        await assert.rejects(create(invalid),e=>e instanceof InvitationError&&e.status===422);
    });

    await t.test('same actor/request UUID is one durable operation, including concurrent retries',async()=>{
      const request=body({email:'retry@example.invalid'});
      const [first,second]=await Promise.all([tx(c=>createInvitation(c,owner,request)),tx(c=>createInvitation(c,owner,request))]);
      assert.equal(first.invitation.id,second.invitation.id);assert.deepEqual([first.replayed,second.replayed].sort(),[false,true]);
      assert.equal((await db.query('SELECT count(*)::int AS n FROM invitation_requests WHERE actor_sub=$1 AND request_id=$2',[owner,request.request_id])).rows[0].n,1);
      await assert.rejects(tx(c=>createInvitation(c,owner,{...request,note:'different'})),failure('request_mismatch',409));
      const other=await tx(c=>createInvitation(c,peer,request));assert.notEqual(other.invitation.id,first.invitation.id);
      const resendId=randomUUID();const r1=await tx(c=>requestInvitationResend(c,owner,first.invitation.id,resendId));
      const r2=await tx(c=>requestInvitationResend(c,owner,first.invitation.id,resendId));assert.equal(r1.replayed,false);assert.equal(r2.replayed,true);
      await assert.rejects(tx(c=>revokeInvitation(c,owner,first.invitation.id,resendId)),failure('request_mismatch',409));
    });

    await t.test('unbound first mail request locks one normalized mailbox even across concurrent requests',async()=>{
      const row=await create();let release!:()=>void,ready!:()=>void;
      const gate=new Promise<void>(r=>release=r),entered=new Promise<void>(r=>ready=r);
      const first=tx(async c=>{const bound=await validateLockedInvitation(c,await locked(c,row.id),'First@Example.Invalid',true);ready();await gate;return bound;});
      await entered;
      const second=tx(async c=>validateLockedInvitation(c,await locked(c,row.id),'other@example.invalid',true));
      // Attach rejection before releasing the holder so the runner sees no unhandled promise.
      const denied=assert.rejects(second,failure('email_mismatch',403));release();
      const bound=await first;await denied;
      assert.equal(bound.bound_email,'first@example.invalid');assert.equal(bound.binding_source,'first_request');
      const same=await tx(async c=>validateLockedInvitation(c,await locked(c,row.id),'FIRST@example.invalid',true));
      assert.equal(+new Date(same.bound_at!),+new Date(bound.bound_at!));
      assert.equal(+new Date(same.expires_at),+new Date(row.expires_at));
    });

    await t.test('strict expiry and terminal states reject resend/revoke/claim without extending validity',async()=>{
      const row=await create({email:'expired@example.invalid'});
      await db.query('UPDATE invitation_codes SET expires_at=clock_timestamp() WHERE id=$1',[row.id]);
      await assert.rejects(tx(c=>requestInvitationResend(c,owner,row.id,randomUUID())),failure('invitation_expired',409));
      await assert.rejects(tx(c=>revokeInvitation(c,owner,row.id,randomUUID())),failure('invitation_expired',409));
      await assert.rejects(tx(async c=>validateLockedInvitation(c,await locked(c,row.id),'expired@example.invalid',true)),failure('invitation_expired',409));
      const live=await create();const rid=randomUUID();const revoked=await tx(c=>revokeInvitation(c,owner,live.id,rid));
      assert.equal(invitationState(revoked.invitation),'revoked');assert.equal((await tx(c=>revokeInvitation(c,owner,live.id,rid))).replayed,true);
      await assert.rejects(tx(c=>revokeInvitation(c,owner,live.id,randomUUID())),failure('invitation_revoked',409));
      assert.equal((await db.query('SELECT clear_at FROM invitation_codes WHERE id=$1',[live.id])).rows[0].clear_at,null);
    });

    await t.test('loss then restoration of creator permission never revives an unused invitation; completed stays used',async()=>{
      const row=await create(),used=await create();
      await db.query('UPDATE invitation_codes SET used_at=clock_timestamp(),used_by=$2,used_username_snapshot=$3 WHERE id=$1',[used.id,consumer,'Consumer snapshot']);
      await tx(async c=>{await c.query("INSERT INTO user_permission_overrides VALUES($1,'org.invites.create','deny')",[owner]);});
      assert.equal(invitationState((await db.query('SELECT * FROM invitation_codes WHERE id=$1',[row.id])).rows[0]),'invalid');
      await tx(c=>c.query("DELETE FROM user_permission_overrides WHERE user_sub=$1 AND perm_key='org.invites.create'",[owner]));
      await assert.rejects(tx(async c=>validateLockedInvitation(c,await locked(c,row.id))),failure('invitation_unavailable',409));
      await db.query('UPDATE invitation_codes SET used_by=NULL WHERE id=$1',[used.id]);
      const complete=(await db.query('SELECT * FROM invitation_codes WHERE id=$1',[used.id])).rows[0];
      assert.equal(invitationState(complete),'used');assert.equal(serializeInvitation(complete).used_by?.username,'Consumer snapshot');
      await assert.rejects(tx(async c=>validateLockedInvitation(c,await locked(c,used.id))),failure('invitation_used',409));
    });

    await t.test('role deletion remains invalid after same slug recreation, and original role snapshot survives',async()=>{
      await db.query("INSERT INTO org_roles(slug,label,level) VALUES('temporary','Original role',150)");
      const row=await create({role_slug:'temporary'});
      await tx(c=>c.query("DELETE FROM org_roles WHERE slug='temporary'"));
      await db.query("INSERT INTO org_roles(slug,label,level) VALUES('temporary','Replacement role',150)");
      const dead=(await db.query('SELECT * FROM invitation_codes WHERE id=$1',[row.id])).rows[0];
      assert.equal(dead.invited_role_slug,null);assert.equal(dead.invalid_reason,'role_deleted');
      assert.deepEqual(serializeInvitation(dead).invited_role,{slug:'temporary',label:'Original role'});
      await assert.rejects(tx(async c=>validateLockedInvitation(c,await locked(c,row.id))),failure('invitation_unavailable',409));
    });

    await t.test('hierarchy hides higher creators, peers cannot revoke, own revoke needs no void grant',async()=>{
      const secret=await create({},higher),own=await create();
      await assert.rejects(tx(c=>readInvitation(c,owner,secret.id)),failure('not_found',404));
      await assert.rejects(tx(c=>revokeInvitation(c,peer,own.id,randomUUID())),failure('permission_denied',403));
      assert.equal(invitationState((await tx(c=>revokeInvitation(c,owner,own.id,randomUUID()))).invitation),'revoked');
      const delegated=await create();assert.equal(invitationState((await tx(c=>revokeInvitation(c,higher,delegated.id,randomUUID()))).invitation),'revoked');
      await assert.rejects(tx(c=>listInvitations(c,lower,{})),failure('permission_denied',403));
    });

    await t.test('on-demand pagination clamps and searches metadata with literal wildcard characters and stable ordering',async()=>{
      const ids=[];for(let n=0;n<13;n++)ids.push((await create({note:`paged group ${String(n).padStart(2,'0')}`,email:`paged${n}@example.invalid`})).id);
      const first=await tx(c=>listInvitations(c,owner,{query:'paged group',page_size:'10',sort:'code',order:'asc'}));
      const last=await tx(c=>listInvitations(c,owner,{query:'paged group',page_size:'10',page:'999',sort:'code',order:'asc'}));
      assert.equal(first.items.length,10);assert.equal(first.total,13);assert.equal(last.items.length,3);assert.equal(last.page,2);
      assert.equal(new Set([...first.items,...last.items].map(x=>x.id)).size,13);
      assert.deepEqual([...first.items,...last.items].map(x=>x.code),[...first.items,...last.items].map(x=>x.code).sort());
      const exact=await tx(c=>listInvitations(c,owner,{query:ids[0],page_size:'25'}));assert.equal(exact.items.length,1);
      const literal=await tx(c=>listInvitations(c,owner,{query:'%',page_size:'100'}));assert.equal(literal.total,0);
      for(const query of [{page_size:'200'},{page:'0'},{query:'x'.repeat(101)},{sort:'id'},{order:'sql'}])
        await assert.rejects(tx(c=>listInvitations(c,owner,query)),failure('invalid_query',400));
      const all=await tx(c=>listInvitations(c,owner,{page_size:'100'}));assert.equal(all.counts.all,all.counts.current+all.counts.history);
      assert.equal(all.items.some(x=>x.created_by_label==='higher'),false);
      const history=await tx(c=>listInvitations(c,owner,{status:'history',page_size:'100'}));assert.ok(history.items.every(x=>x.status!=='active'));
    });
  }finally{await db.end();await admin.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);await admin.end();}
});
