import {Router,type RequestHandler} from 'express';

/** Keep the setup gate ahead of key reads while handling methods before body parsing. */
export function createAccountJwksRouter(readKeyFile:()=>string|Promise<string>,setupGate:RequestHandler):Router {
  const router=Router();
  router.all('/.well-known/jwks.json',setupGate,async(req,res)=>{
    res.set('Cache-Control','no-store');
    if(req.method!=='GET'){
      res.set('Allow','GET').status(405).json({error:'method_not_allowed'});return;
    }
    try{
      const raw=JSON.parse(await readKeyFile()) as {keys?:Record<string,unknown>[]} & Record<string,unknown>;
      const keys=(Array.isArray(raw.keys)?raw.keys:[raw]) as Record<string,unknown>[];
      // Preserve the existing single-key/rotation-overlap projection; private members never leave this route.
      const value={keys:keys.map(({d,p,q,dp,dq,qi,k,...pub})=>({use:'sig',...pub}))};
      res.set('Cache-Control','public, max-age=120, must-revalidate').status(200).json(value);
    }catch{
      res.set('Cache-Control','no-store').status(500).json({error:'keys_unavailable'});
    }
  });
  return router;
}
