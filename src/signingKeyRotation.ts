import {randomUUID} from 'node:crypto';
import type pg from 'pg';

export const SIGNING_KEY_PREPUBLICATION_SECONDS = 300;
const LOCK = 8_246_115;
export interface SigningKeyMaterial {
  kid:string; alg:string; publicJwk:Record<string,unknown>; privateKeyEnc:Buffer;
}
export interface SigningKeyRow {
  kid:string; alg:string; public_jwk:Record<string,unknown>; private_key_enc:Buffer;
  status:'current'|'next'; created_at:Date; activated_at:Date|null; retired_at:Date|null;
  rotation_id:string|null; published_at:Date|null; activate_after:Date|null; observed_at:Date;
}
export interface SigningKeyStatus {
  kid:string; rotated_at:string|null; state:'active'|'pending';
  rotation:null|{id:string;kid:string;published_at:string|null;activate_after:string|null};
}
export class SigningKeyStateError extends Error {
  readonly code='signing_key_state_unavailable';
  constructor(){super('Signing-key state is unavailable.');}
}
const need=(value:unknown):void=>{if(!value)throw new SigningKeyStateError();};
const iso=(value:Date|null):string|null=>value?value.toISOString():null;
const SELECT=`SELECT kid,alg,public_jwk,private_key_enc,status,created_at,activated_at,retired_at,
  rotation_id,published_at,activate_after,clock_timestamp() AS observed_at
  FROM signing_keys WHERE status IN ('current','next') ORDER BY created_at DESC`;

/** Database authority is read on each selection; only parsed private keys cache by kid. */
export class SigningKeyRotation {
  constructor(private readonly database:pg.Pool,private readonly generate:()=>Promise<SigningKeyMaterial>,
    private readonly changed:()=>void=()=>{}){}

  private async rows(db:Pick<pg.PoolClient,'query'>=this.database):Promise<SigningKeyRow[]> {
    const {rows}=await db.query<SigningKeyRow>(SELECT);
    need(rows.length<=2&&rows.filter(r=>r.status==='current').length<=1&&rows.filter(r=>r.status==='next').length<=1);
    for(const row of rows){
      need(typeof row.kid==='string'&&row.kid.length>0&&row.observed_at instanceof Date&&Number.isFinite(row.observed_at.getTime()));
      need((row.published_at===null)===(row.activate_after===null));
      if(row.activate_after)need(row.published_at instanceof Date&&row.activate_after instanceof Date&&row.activate_after.getTime()-row.published_at.getTime()>=SIGNING_KEY_PREPUBLICATION_SECONDS*1000);
      if(row.status==='next')need(row.rotation_id&&row.activated_at===null&&row.retired_at===null);
    }
    return rows;
  }
  private async transaction<T>(work:(db:pg.PoolClient)=>Promise<T>):Promise<T>{
    const db=await this.database.connect();
    try{await db.query('BEGIN');await db.query("SET LOCAL lock_timeout='2s'; SET LOCAL statement_timeout='5s'");
      await db.query('SELECT pg_advisory_xact_lock($1)',[LOCK]);const result=await work(db);await db.query('COMMIT');return result;
    }catch(error){await db.query('ROLLBACK').catch(()=>{});throw error;}finally{db.release();}
  }
  private async bootstrap(db:pg.PoolClient,rows:SigningKeyRow[]):Promise<SigningKeyRow>{
    const current=rows.find(r=>r.status==='current');if(current)return current;
    // Missing current with historical/pending material is not a fresh install.
    need(rows.length===0&&(await db.query('SELECT count(*)::text AS n FROM signing_keys')).rows[0].n==='0');
    const key=await this.generate();
    await db.query(`INSERT INTO signing_keys(kid,alg,public_jwk,private_key_enc,status,activated_at)
      VALUES($1,$2,$3,$4,'current',clock_timestamp())`,[key.kid,key.alg,key.publicJwk,key.privateKeyEnc]);
    return (await this.rows(db)).find(r=>r.status==='current')!;
  }
  private async reconcile(kid:string):Promise<void>{
    let modified=false;
    await this.transaction(async db=>{
      const rows=await this.rows(db),current=rows.find(r=>r.status==='current'),next=rows.find(r=>r.status==='next');
      need(current);
      if(!next||next.kid!==kid)return;
      if(!next.published_at){
        // This transaction reads a key published by an EARLIER commit. Even if
        // this marker commit stalls, all of its waiting time is already public.
        await db.query(`WITH marker AS (SELECT clock_timestamp() AS at)
          UPDATE signing_keys SET published_at=marker.at,activate_after=marker.at+interval '300 seconds'
          FROM marker WHERE kid=$1 AND status='next' AND published_at IS NULL`,[kid]);modified=true;return;
      }
      if(next.observed_at.getTime()<next.activate_after!.getTime())return;
      await db.query("UPDATE signing_keys SET status='retired',retired_at=clock_timestamp() WHERE kid=$1 AND status='current'",[current!.kid]);
      const result=await db.query("UPDATE signing_keys SET status='current',activated_at=clock_timestamp() WHERE kid=$1 AND status='next'",[kid]);
      need(result.rowCount===1);modified=true;
    });
    if(modified)this.changed();
  }
  async current(strictReconcile=false):Promise<SigningKeyRow>{
    let rows=await this.rows();
    if(!rows.some(r=>r.status==='current')){
      await this.transaction(async db=>this.bootstrap(db,await this.rows(db)));this.changed();rows=await this.rows();
    }
    const next=rows.find(r=>r.status==='next');
    if(next&&(!next.published_at||next.observed_at.getTime()>=next.activate_after!.getTime())){
      try{await this.reconcile(next.kid);}catch(error){if(strictReconcile)throw error;}
      // Even after an ambiguous/failed maintenance attempt, only freshly read
      // durable authority can select a signer. Status callers still report errors.
      rows=await this.rows();
    }
    const current=rows.find(r=>r.status==='current');need(current);return current!;
  }
  async status():Promise<SigningKeyStatus>{
    await this.current(true);const rows=await this.rows(),current=rows.find(r=>r.status==='current'),next=rows.find(r=>r.status==='next');need(current);
    return{kid:current!.kid,rotated_at:iso(current!.activated_at),state:next?'pending':'active',
      rotation:next?{id:next.rotation_id!,kid:next.kid,published_at:iso(next.published_at),activate_after:iso(next.activate_after)}:null};
  }
  async schedule():Promise<SigningKeyStatus>{
    const pendingKid=await this.transaction(async db=>{
      const rows=await this.rows(db);await this.bootstrap(db,rows);
      const next=rows.find(r=>r.status==='next');if(next)return next.kid;
      const key=await this.generate();
      await db.query(`INSERT INTO signing_keys(kid,alg,public_jwk,private_key_enc,status,rotation_id)
        VALUES($1,$2,$3,$4,'next',$5)`,[key.kid,key.alg,key.publicJwk,key.privateKeyEnc,randomUUID()]);
      return key.kid;
    });
    this.changed();
    await this.reconcile(pendingKid);
    return this.status();
  }
}
