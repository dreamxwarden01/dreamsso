import { randomInt, randomUUID } from 'node:crypto';
import type pg from 'pg';

const UUID = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i;
const CODE = /^[A-Z0-9]{12}$/;
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const INF = 2147483647;
export class InvitationError extends Error {
  readonly body: Record<string, unknown>;
  constructor(readonly status: number, readonly code: string, extra: Record<string, unknown> = {}) {
    super(code); this.body = { error: code, ...extra };
  }
}
const fail = (status: number, code: string, extra?: Record<string, unknown>): never => { throw new InvitationError(status, code, extra); };
/** Invitation bindings are not reservations; only an existing identity occupies an address. */
export async function assertInvitationEmailAvailable(db: Pick<pg.PoolClient,'query'>, email: string | null): Promise<void> {
  if(email && (await db.query('SELECT 1 FROM identities WHERE email=$1 AND deleted_at IS NULL',[email])).rowCount)
    fail(422,'email_taken',{errors:{email:'email_taken'}});
}
export interface InviteRow {
  id: string; code: string; created_by: string | null; created_by_label: string;
  created_at: Date | string; expires_at: Date | string; invited_role_slug: string | null;
  invited_role_slug_snapshot: string | null; invited_role_label: string | null;
  bound_email: string | null; bound_at: Date | string | null; binding_source: 'creation' | 'first_request' | null;
  delivery: 'link' | 'email'; note: string; used_by: string | null; used_at: Date | string | null;
  voided_at: Date | string | null; invalidated_at: Date | string | null; invalid_reason: string | null;
  revoked_by_label: string | null; used_username_snapshot: string | null; used_display_name_snapshot: string | null;
  mail_state: 'none' | 'queued' | 'sending' | 'sent' | 'failed' | 'unknown';
  mail_attempts: number; mail_last_at: Date | string | null; mail_error_code: string | null;
  creator_level?: number; offered_role_level?: number | null; can_revoke?: boolean; can_resend?: boolean;
}
interface Actor { sub: string; label: string; level: number; create: boolean; view: boolean; void: boolean }
interface CreateInput { request_id: string; role_slug: string; validity_hours: number; email: string | null; delivery: 'link' | 'email'; note: string }
const inputObject = (value: unknown): Record<string, unknown> => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return fail(422, 'invalid_request');
  return value as Record<string, unknown>;
};
function requestId(value: unknown): string {
  if (typeof value !== 'string' || !UUID.test(value)) return fail(422, 'invalid_request_id');
  return value.toLowerCase();
}
export function normalizeInvitationEmail(value: unknown, optional = false): string | null {
  if ((value === undefined || value === null || value === '') && optional) return null;
  if (typeof value !== 'string') return fail(422, 'invalid_email');
  const email = value.trim().toLowerCase();
  if (email.length > 254 || !EMAIL.test(email)) return fail(422, 'invalid_email');
  return email;
}
function createInput(value: unknown): CreateInput {
  const body = inputObject(value), rid = requestId(body.request_id);
  const hours = body.validity_hours === undefined ? 72 : body.validity_hours;
  if (typeof hours !== 'number' || !Number.isInteger(hours) || hours < 1 || hours > 8760) return fail(422, 'invalid_validity');
  if (typeof body.role_slug !== 'string' || !body.role_slug) return fail(422, 'invalid_role');
  const delivery = body.delivery === undefined ? 'link' : body.delivery;
  if (delivery !== 'link' && delivery !== 'email') return fail(422, 'invalid_delivery');
  if (body.note !== undefined && typeof body.note !== 'string') return fail(422, 'invalid_note');
  const note = (body.note as string | undefined ?? '').trim();
  if ([...note].length > 60) return fail(422, 'invalid_note');
  return { request_id: rid, role_slug: body.role_slug, validity_hours: hours,
    email: normalizeInvitationEmail(body.email, delivery === 'link'), delivery, note };
}
async function actor(db: pg.PoolClient, sub: string): Promise<Actor> {
  if (!UUID.test(sub)) return fail(401, 'invalid_token');
  const { rows: [row] } = await db.query(`SELECT i.sub,i.display_name,i.username,i.status,i.deleted_at,r.level,
    COALESCE(uc.effect,rc.effect,'deny')='grant' AS can_create,
    COALESCE(uv.effect,rv.effect,'deny')='grant' AS can_view,
    COALESCE(ud.effect,rd.effect,'deny')='grant' AS can_void
    FROM identities i LEFT JOIN user_org_roles ur ON ur.user_sub=i.sub LEFT JOIN org_roles r ON r.slug=ur.org_role_slug
    LEFT JOIN role_permissions rc ON rc.role_slug=r.slug AND rc.perm_key='org.invites.create'
    LEFT JOIN role_permissions rv ON rv.role_slug=r.slug AND rv.perm_key='org.invites.view'
    LEFT JOIN role_permissions rd ON rd.role_slug=r.slug AND rd.perm_key='org.invites.void'
    LEFT JOIN user_permission_overrides uc ON uc.user_sub=i.sub AND uc.perm_key='org.invites.create'
    LEFT JOIN user_permission_overrides uv ON uv.user_sub=i.sub AND uv.perm_key='org.invites.view'
    LEFT JOIN user_permission_overrides ud ON ud.user_sub=i.sub AND ud.perm_key='org.invites.void'
    WHERE i.sub=$1 FOR SHARE OF i`, [sub]);
  if (!row || row.deleted_at || row.status !== 'active') return fail(403, 'permission_denied');
  return { sub, label: row.display_name || row.username || sub, level: row.level ?? INF,
    create: row.can_create, view: row.can_view, void: row.can_void };
}
const permit = (allowed: boolean, permission: string) => { if (!allowed) fail(403, 'permission_denied', { permission }); };
async function creatorLevel(db: pg.PoolClient, row: InviteRow): Promise<number> {
  const { rows: [r] } = await db.query(`SELECT r.level FROM identities i
    LEFT JOIN user_org_roles ur ON ur.user_sub=i.sub LEFT JOIN org_roles r ON r.slug=ur.org_role_slug
    WHERE i.sub=$1 AND i.deleted_at IS NULL`, [row.created_by]);
  return r?.level ?? INF;
}
function see(a: Actor, row: InviteRow, level: number) { if (row.created_by !== a.sub && level < a.level) fail(404, 'not_found'); }
/** Caller holds the common role-writer lock BEFORE acquiring any invitation row. */
export async function lockInvitation(db: pg.PoolClient, idOrCode: string): Promise<InviteRow | null> {
  let clause: string;
  if (UUID.test(idOrCode)) clause = 'id=$1::uuid';
  else if (CODE.test(idOrCode.toUpperCase())) { clause = 'code=$1'; idOrCode = idOrCode.toUpperCase(); }
  else return null;
  return (await db.query<InviteRow>(`SELECT * FROM invitation_codes WHERE ${clause} FOR UPDATE`, [idOrCode])).rows[0] ?? null;
}
/** Public preview is a single read snapshot, never a global authority writer. */
export async function readInvitationPreview(db: pg.Pool | pg.PoolClient, code: string): Promise<InviteRow | null> {
  if(!CODE.test(code))return null;
  const row=(await db.query(`SELECT ic.*, (ir.slug IS NOT NULL AND i.sub IS NOT NULL AND i.status='active' AND i.deleted_at IS NULL
    AND cr.level IS NOT NULL AND ir.level>cr.level AND COALESCE(up.effect,rp.effect,'deny')='grant') AS eligible
    FROM invitation_codes ic LEFT JOIN org_roles ir ON ir.slug=ic.invited_role_slug
    LEFT JOIN identities i ON i.sub=ic.created_by LEFT JOIN user_org_roles ur ON ur.user_sub=i.sub
    LEFT JOIN org_roles cr ON cr.slug=ur.org_role_slug
    LEFT JOIN role_permissions rp ON rp.role_slug=cr.slug AND rp.perm_key='org.invites.create'
    LEFT JOIN user_permission_overrides up ON up.user_sub=i.sub AND up.perm_key='org.invites.create'
    WHERE ic.code=$1`,[code])).rows[0];
  if(!row)return null;
  if(!row.eligible && !row.used_at && !row.voided_at && !row.invalidated_at && new Date(row.expires_at).getTime()>Date.now())
    row.invalidated_at=new Date();
  return row;
}
export function invitationState(row: InviteRow, now = Date.now()): 'active' | 'used' | 'expired' | 'revoked' | 'invalid' {
  if (row.used_at) return 'used';
  if (row.voided_at) return 'revoked';
  if (row.invalidated_at) return 'invalid';
  return new Date(row.expires_at).getTime() <= now ? 'expired' : 'active';
}
const stateError = (state: ReturnType<typeof invitationState>) => ({used:'invitation_used',revoked:'invitation_revoked',invalid:'invitation_unavailable',expired:'invitation_expired',active:''})[state];
/** Revalidation AND permanent invalidation run in the authority-changing transaction. */
export async function invalidateIneligibleInvitations(db: pg.PoolClient): Promise<void> {
  await db.query(`UPDATE invitation_codes ic SET invalidated_at=clock_timestamp(),
    invalid_reason=CASE WHEN ir.slug IS NULL THEN 'role_deleted' ELSE 'creator_unauthorized' END
    FROM (SELECT x.id FROM invitation_codes x
      LEFT JOIN org_roles r ON r.slug=x.invited_role_slug
      LEFT JOIN identities i ON i.sub=x.created_by
      LEFT JOIN user_org_roles ur ON ur.user_sub=i.sub
      LEFT JOIN org_roles cr ON cr.slug=ur.org_role_slug
      LEFT JOIN role_permissions rp ON rp.role_slug=cr.slug AND rp.perm_key='org.invites.create'
      LEFT JOIN user_permission_overrides up ON up.user_sub=i.sub AND up.perm_key='org.invites.create'
      WHERE x.used_at IS NULL AND x.voided_at IS NULL AND x.invalidated_at IS NULL
        AND x.expires_at>clock_timestamp()
        AND (r.slug IS NULL OR i.sub IS NULL OR i.deleted_at IS NOT NULL OR i.status<>'active'
          OR COALESCE(up.effect,rp.effect,'deny')<>'grant' OR cr.level IS NULL OR r.level<=cr.level)) bad
    LEFT JOIN invitation_codes x2 ON x2.id=bad.id
    LEFT JOIN org_roles ir ON ir.slug=x2.invited_role_slug
    WHERE ic.id=bad.id`);
}
/** Must run inside the transaction that binds/sends/consumes, after the shared role lock. */
export async function validateLockedInvitation(db: pg.PoolClient, row: InviteRow, email?: string, bind = false): Promise<InviteRow> {
  const { rows: [live] } = await db.query<{ valid: boolean; eligible: boolean }>(`SELECT expires_at>clock_timestamp() AS valid,
    (ir.slug IS NOT NULL AND i.sub IS NOT NULL AND i.status='active' AND i.deleted_at IS NULL
      AND cr.level IS NOT NULL AND ir.level>cr.level AND COALESCE(up.effect,rp.effect,'deny')='grant') AS eligible
    FROM invitation_codes ic LEFT JOIN org_roles ir ON ir.slug=ic.invited_role_slug
    LEFT JOIN identities i ON i.sub=ic.created_by LEFT JOIN user_org_roles ur ON ur.user_sub=i.sub
    LEFT JOIN org_roles cr ON cr.slug=ur.org_role_slug
    LEFT JOIN role_permissions rp ON rp.role_slug=cr.slug AND rp.perm_key='org.invites.create'
    LEFT JOIN user_permission_overrides up ON up.user_sub=i.sub AND up.perm_key='org.invites.create'
    WHERE ic.id=$1`, [row.id]);
  const state = row.used_at ? 'used' : row.voided_at ? 'revoked' : row.invalidated_at || !live?.eligible ? 'invalid' : !live.valid ? 'expired' : 'active';
  if (state !== 'active') return fail(409, stateError(state));
  if (email !== undefined) {
    const normalized = normalizeInvitationEmail(email)!;
    if (row.bound_email && row.bound_email.toLowerCase() !== normalized) return fail(403, 'email_mismatch');
    if (!row.bound_email && bind) {
      const { rows: [bound] } = await db.query<InviteRow>(`UPDATE invitation_codes SET bound_email=$2,bound_at=clock_timestamp(),
        binding_source='first_request',pending_email=$2,pending_at=clock_timestamp()
        WHERE id=$1 AND bound_email IS NULL RETURNING *`, [row.id, normalized]);
      if (!bound) return fail(409, 'invitation_unavailable');
      return bound;
    }
  }
  return row;
}
const safeMailErrors = new Set(['rate_limited','email_not_configured','not_configured','send_failed','unreachable','rejected','bounced','delivery_unknown','invitation_expired','invitation_unavailable','email_taken']);
export function serializeInvitation(row: InviteRow) {
  const status = invitationState(row);
  return { id: row.id, code: row.code, status, note: row.note, email: row.bound_email,
    bound_at: row.bound_at, binding_source: row.binding_source, delivery: row.delivery,
    created_at: row.created_at, expires_at: row.expires_at,
    ended_at: row.used_at || row.voided_at || row.invalidated_at || (status === 'expired' ? row.expires_at : null),
    created_by_label: row.created_by_label,
    invited_role: { slug: row.invited_role_slug_snapshot ?? row.invited_role_slug, label: row.invited_role_label },
    mail: { state: row.mail_state, at: row.mail_last_at, attempts: row.mail_attempts,
      ...(row.mail_error_code ? { error_code: safeMailErrors.has(row.mail_error_code) ? row.mail_error_code : 'send_failed' } : {}) },
    ...(row.used_at ? { used_by: { username: row.used_username_snapshot, display_name: row.used_display_name_snapshot } } : {}),
    ...(row.revoked_by_label ? { revoked_by_label: row.revoked_by_label } : {}),
    ...(row.invalid_reason ? { invalid_reason: row.invalid_reason === 'role_deleted' ? 'role_deleted' : 'creator_unauthorized' } : {}),
    can_revoke: !!row.can_revoke && status === 'active', can_resend: !!row.can_resend && !!row.bound_email && status === 'active' };
}
async function decorate(db: pg.PoolClient, a: Actor, row: InviteRow): Promise<InviteRow> {
  const level = await creatorLevel(db, row); see(a,row,level);
  row.can_revoke = row.created_by === a.sub || a.void && level > a.level;
  const role = row.invited_role_slug ? (await db.query('SELECT level FROM org_roles WHERE slug=$1',[row.invited_role_slug])).rows[0] : null;
  row.can_resend = a.create && !!role && role.level > a.level;
  return row;
}
async function receipt(db: pg.PoolClient, a: Actor, rid: string, operation: string, input: unknown): Promise<InviteRow | null> {
  const { rows: [old] } = await db.query(`SELECT invitation_id,operation,input=$3::jsonb AS matches
    FROM invitation_requests WHERE actor_sub=$1 AND request_id=$2 FOR UPDATE`, [a.sub,rid,JSON.stringify(input)]);
  if (!old) return null;
  if (old.operation !== operation || !old.matches) return fail(409, 'request_mismatch');
  const row = await lockInvitation(db,old.invitation_id);
  if (!row) return fail(404,'not_found');
  return decorate(db,a,row);
}
async function record(db: pg.PoolClient, a: Actor, rid: string, op: string, input: unknown, row: InviteRow) {
  await db.query('INSERT INTO invitation_requests(actor_sub,request_id,operation,input,invitation_id) VALUES($1,$2,$3,$4,$5)',[a.sub,rid,op,JSON.stringify(input),row.id]);
}
async function audit(db: pg.PoolClient, a: Actor, action: string, row: InviteRow) {
  await db.query(`INSERT INTO org_audit_log(actor_sub,actor_label,action,detail) VALUES($1,$2,$3,$4)`,
    [a.sub,a.label,action,JSON.stringify({invitation_id:row.id,code:row.code,role:row.invited_role_slug_snapshot})]);
}
export async function createInvitation(db: pg.PoolClient, actorSub: string, raw: unknown): Promise<{invitation:InviteRow;replayed:boolean}> {
  const input = createInput(raw), a = await actor(db,actorSub); permit(a.create,'org.invites.create');
  const previous = await receipt(db,a,input.request_id,'create',input);
  if (previous) return {invitation:previous,replayed:true};
  const role = (await db.query('SELECT slug,label,level FROM org_roles WHERE slug=$1',[input.role_slug])).rows[0];
  if (!role || role.level <= a.level) return fail(422,'invalid_role');
  await assertInvitationEmailAvailable(db,input.email);
  const chars='ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  for (let attempt=0;attempt<5;attempt++) {
    const code=Array.from({length:12},()=>chars[randomInt(chars.length)]).join('');
    const {rows:[row]}=await db.query<InviteRow>(`INSERT INTO invitation_codes(id,code,created_by,created_by_label,
      invited_role_slug,invited_role_slug_snapshot,invited_role_label,expires_at,bound_email,bound_at,binding_source,delivery,note)
      VALUES($1,$2,$3,$4,$5,$5,$6,clock_timestamp()+make_interval(hours=>$7),$8,
        CASE WHEN $8::citext IS NOT NULL THEN clock_timestamp() END,CASE WHEN $8::citext IS NOT NULL THEN 'creation' END,$9,$10)
      ON CONFLICT(code) DO NOTHING RETURNING *`,[randomUUID(),code,a.sub,a.label,role.slug,role.label,input.validity_hours,input.email,input.delivery,input.note]);
    if (!row) continue;
    await record(db,a,input.request_id,'create',input,row); await audit(db,a,'invite.create',row);
    return {invitation:await decorate(db,a,row),replayed:false};
  }
  return fail(503,'code_generation_failed');
}
export async function requestInvitationResend(db: pg.PoolClient, actorSub: string, id: string, rawRequestId: unknown): Promise<{invitation:InviteRow;replayed:boolean}> {
  const rid=requestId(rawRequestId),a=await actor(db,actorSub); permit(a.create,'org.invites.create');
  const input={id}; const previous=await receipt(db,a,rid,'resend',input);
  if(previous)return{invitation:previous,replayed:true};
  const row=await lockInvitation(db,id);if(!row)return fail(404,'not_found');
  const level=await creatorLevel(db,row);see(a,row,level);
  await validateLockedInvitation(db,row);
  if(!row.bound_email)return fail(422,'email_required');
  const role=(await db.query('SELECT level FROM org_roles WHERE slug=$1',[row.invited_role_slug])).rows[0];
  if(!role || role.level<=a.level)return fail(403,'permission_denied',{permission:'org.invites.create'});
  await assertInvitationEmailAvailable(db,row.bound_email);
  await record(db,a,rid,'resend',input,row);await audit(db,a,'invite.resend',row);
  return{invitation:await decorate(db,a,row),replayed:false};
}
export async function revokeInvitation(db: pg.PoolClient, actorSub: string, id: string, rawRequestId: unknown): Promise<{invitation:InviteRow;replayed:boolean}> {
  const rid=requestId(rawRequestId),a=await actor(db,actorSub),input={id};
  const previous=await receipt(db,a,rid,'revoke',input);if(previous)return{invitation:previous,replayed:true};
  const row=await lockInvitation(db,id);if(!row)return fail(404,'not_found');
  const level=await creatorLevel(db,row);
  if(row.created_by!==a.sub){permit(a.void,'org.invites.void');if(level<=a.level)return fail(403,'creator_not_below');}
  await validateLockedInvitation(db,row);
  const {rows:[revoked]}=await db.query<InviteRow>(`UPDATE invitation_codes SET voided_at=clock_timestamp(),revoked_by=$2,
    revoked_by_label=$3,clear_at=NULL WHERE id=$1 RETURNING *`,[row.id,a.sub,a.label]);
  await record(db,a,rid,'revoke',input,revoked);await audit(db,a,'invite.void',revoked);
  return{invitation:await decorate(db,a,revoked),replayed:false};
}
export async function readInvitation(db: pg.PoolClient, actorSub: string, id: string): Promise<InviteRow> {
  const a=await actor(db,actorSub);permit(a.view,'org.invites.view');
  const row=await lockInvitation(db,id);if(!row)return fail(404,'not_found');
  return decorate(db,a,row);
}
export async function listInvitations(db: pg.PoolClient, actorSub: string, query: Record<string,unknown>) {
  const a=await actor(db,actorSub);permit(a.view,'org.invites.view');
  const str=(key:string,fallback:string)=>query[key]===undefined?fallback:typeof query[key]==='string'?query[key] as string:fail(400,'invalid_query');
  const pageText=str('page','1'),sizeText=str('page_size','10');
  if(!/^[1-9][0-9]*$/.test(pageText)||!['10','25','100'].includes(sizeText))return fail(400,'invalid_query');
  const requested=Number(pageText),size=Number(sizeText),q=str('query',str('q','')).trim(),status=str('status','all'),sort=str('sort','created_at'),order=str('order','desc');
  if(!Number.isSafeInteger(requested)||[...q].length>100||!['all','current','history'].includes(status)||!['created_at','code'].includes(sort)||!['asc','desc'].includes(order))return fail(400,'invalid_query');
  const escape=(value:string)=>'%'+value.replace(/[\\%_]/g,'\\$&')+'%';
  const needle=escape(q),codeNeedle=escape(q.replace(/[\s-]/g,''));
  const base=`FROM invitation_codes ic LEFT JOIN identities ci ON ci.sub=ic.created_by AND ci.deleted_at IS NULL
    LEFT JOIN user_org_roles ur ON ur.user_sub=ci.sub LEFT JOIN org_roles cr ON cr.slug=ur.org_role_slug
    LEFT JOIN org_roles offered ON offered.slug=ic.invited_role_slug
    WHERE (ic.created_by=$1 OR COALESCE(cr.level,${INF}) >= $2)
      AND ($3='' OR ($5<>'%%' AND ic.code ILIKE $5) OR ic.bound_email::text ILIKE $4 OR ic.note ILIKE $4 OR ic.id::text ILIKE $4)`;
  const active='ic.used_at IS NULL AND ic.voided_at IS NULL AND ic.invalidated_at IS NULL AND ic.expires_at>clock_timestamp()';
  const args=[a.sub,a.level,q,needle,codeNeedle];
  const {rows:[counts]}=await db.query(`SELECT count(*)::int AS all,count(*) FILTER(WHERE ${active})::int AS current,
    count(*) FILTER(WHERE NOT(${active}))::int AS history ${base}`,args);
  const total=status==='all'?counts.all:counts[status],pages=Math.max(1,Math.ceil(total/size)),page=Math.min(requested,pages);
  const filter=status==='all'?'':` AND ${status==='current'?'':'NOT'}(${active})`;
  const {rows}=await db.query<InviteRow>(`SELECT ic.*,COALESCE(cr.level,${INF}) AS creator_level,offered.level AS offered_role_level ${base}${filter}
    ORDER BY ic.${sort} ${order},ic.id ${order} LIMIT $6 OFFSET $7`,[...args,size,(page-1)*size]);
  // A bounded page and its action flags are resolved without per-row queries.
  const items=rows.map(row=>serializeInvitation({...row,
    can_revoke:row.created_by===a.sub || a.void && Number(row.creator_level)>a.level,
    can_resend:a.create && row.offered_role_level!=null && row.offered_role_level>a.level}));
  return{items,page,page_size:size,total,pages,counts};
}
