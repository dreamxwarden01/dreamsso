import {Router} from 'express';
import type {JSONWebKeySet} from 'jose';

/** Mount after the setup gate and before body parsers; HEAD must not fall through to GET. */
export function createJwksRouter(readKeys:()=>Promise<JSONWebKeySet>):Router {
  const router=Router();
  router.all('/jwks',async(req,res)=>{
    res.set('Cache-Control','no-store');
    if(req.method!=='GET'){
      res.set('Allow','GET').status(405).json({error:'method_not_allowed'});return;
    }
    try{
      const keys=await readKeys();
      res.set('Cache-Control','public, max-age=120, must-revalidate').status(200).json(keys);
    }catch{
      res.set('Cache-Control','no-store').status(500).json({error:'keys_unavailable'});
    }
  });
  return router;
}
