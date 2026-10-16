import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {generateKeyPair,exportJWK,exportPKCS8,SignJWT,jwtVerify} from 'jose';
process.env.DOTENV_CONFIG_PATH='/dev/null';process.env.DATABASE_URL='postgres://fixture:fixture@127.0.0.1:1/never_connect';
process.env.KEY_ENCRYPTION_KEY=crypto.randomBytes(32).toString('hex');
const {pool}=await import('../src/db.js');
const {getJwks,invalidateJwksCache,getSigningKey}=await import('../src/keys.js');

test('public-key cache ages from read start, bounds delayed reads and never revives stale data after DB failure',async()=>{
  const originalQuery=pool.query,originalPerformance=globalThis.performance;
  let clock=0,calls=0,delay=4000,fail=false;
  const pair=await generateKeyPair('EdDSA'),public_jwk={...await exportJWK(pair.publicKey),kid:'fixture-public'};
  Object.defineProperty(globalThis,'performance',{configurable:true,writable:true,value:{now:()=>clock}});
  pool.query=(async(query:{query_timeout:number})=>{
    calls++;assert.equal(query.query_timeout,5000);clock+=delay;if(fail)throw Error('synthetic_db_unavailable');return{rows:[{public_jwk}]};
  }) as typeof pool.query;
  try{
    invalidateJwksCache();assert.equal((await getJwks()).keys.length,1);clock=59999;await getJwks();assert.equal(calls,1);
    clock=60001;delay=0;await getJwks();assert.equal(calls,2,'time spent reading counts toward cache freshness');
    clock=120002;fail=true;await assert.rejects(getJwks(),/synthetic_db_unavailable/);assert.equal(calls,3);
    fail=false;delay=5001;await assert.rejects(getJwks(),/Signing-key state is unavailable/);assert.equal(calls,4);
    delay=0;await getJwks();assert.equal(calls,5,'a refused stale snapshot was not cached');
  }finally{pool.query=originalQuery;invalidateJwksCache();Object.defineProperty(globalThis,'performance',{configurable:true,writable:true,value:originalPerformance});}
});

test('signer reads current authority on each request and keeps concurrent kid/private-key pairs consistent',async()=>{
  const originalQuery=pool.query;
  const rows=await Promise.all([1,2].map(async n=>{
    const pair=await generateKeyPair('EdDSA',{extractable:true}),public_jwk={...await exportJWK(pair.publicKey),kid:'fixture-signer-'+n,alg:'EdDSA'};
    const iv=crypto.randomBytes(12),cipher=crypto.createCipheriv('aes-256-gcm',Buffer.from(process.env.KEY_ENCRYPTION_KEY!,'hex'),iv);
    const bytes=Buffer.concat([cipher.update(await exportPKCS8(pair.privateKey),'utf8'),cipher.final()]);
    return{kid:public_jwk.kid,public_jwk,private_key_enc:Buffer.concat([iv,cipher.getAuthTag(),bytes]),alg:'EdDSA',status:'current',
      created_at:new Date(),activated_at:new Date(),retired_at:null,rotation_id:null,published_at:null,activate_after:null,observed_at:new Date(),pair};
  }));
  let selected=0;
  pool.query=(async()=>({rows:[rows[selected++%2]]})) as typeof pool.query;
  try{
    const keys=await Promise.all([getSigningKey(),getSigningKey()]);assert.equal(selected,2);
    for(const key of keys){const token=await new SignJWT({}).setProtectedHeader({alg:'EdDSA',kid:key.kid}).sign(key.privateKey);
      const expected=rows.find(row=>row.kid===key.kid)!;await jwtVerify(token,expected.pair.publicKey);}
    assert.equal((await getSigningKey()).kid,rows[0].kid);assert.equal(selected,3);
    const broken={...rows[0],kid:'broken-key',public_jwk:{...rows[1].public_jwk,kid:'broken-key'}};
    pool.query=(async()=>({rows:[broken]})) as typeof pool.query;
    await assert.rejects(getSigningKey(),/Signing-key state is unavailable/);
  }finally{pool.query=originalQuery;await pool.end();}
});
