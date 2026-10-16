import {Router} from 'express';
import {jwtVerify,type JWTVerifyGetKey} from 'jose';
import type {ClientKeyStatus} from '../client-key-state.js';

export function createClientKeyRouter(deps:{
  issuer:()=>string;audience:()=>string;verificationKey:JWTVerifyGetKey;
  claimNonce:(key:string)=>Promise<boolean>;
  schedule:()=>Promise<ClientKeyStatus>;status:()=>Promise<ClientKeyStatus>;
}){
  const router=Router(),path='/internal/rotate-client-key';
  router.all(path,async(req,res)=>{
    res.set('Cache-Control','no-store');
    if(req.method!=='GET'&&req.method!=='POST')return res.set('Allow','GET, POST').status(405).json({error:'method_not_allowed'});
    const reading=req.method==='GET',header=req.get('authorization')??'';
    const token=reading?(header.startsWith('Bearer ')?header.slice(7):''):req.body?.token;
    let jti:string;
    try{
      if(typeof token!=='string'||token.length===0||token.length>16384)throw Error('bad_token');
      const {payload,protectedHeader}=await jwtVerify(token,deps.verificationKey,{
        issuer:deps.issuer(),audience:deps.audience(),algorithms:['EdDSA'],maxTokenAge:90,
        requiredClaims:['iat','exp','jti'],
      });
      if(typeof payload.jti!=='string'||payload.jti.length===0||payload.jti.length>256)throw Error('bad_token');
      if(reading){
        if(protectedHeader.typ!=='client-key-status+jwt'||payload.method!=='GET'||payload.path!==path)throw Error('bad_token');
      }else if(protectedHeader.typ!=='rotate+jwt')throw Error('bad_token');
      jti=payload.jti;
    }catch{return res.status(401).json({error:'invalid_token'});}
    let fresh:boolean;
    try{fresh=await deps.claimNonce((reading?'acct:key-status:jti:':'acct:rotate:jti:')+jti);}
    catch{return res.status(503).json({error:'replay_guard_unavailable'});}
    if(!fresh)return res.status(401).json({error:'invalid_token'});
    try{
      const value=await(reading?deps.status():deps.schedule());
      return res.status(!reading&&value.state==='pending'?202:200).json(value);
    }catch{return res.status(503).json({error:'client_key_unavailable'});}
  });
  return router;
}
