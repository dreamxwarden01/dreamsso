import { Agent, fetch as undiciFetch, getGlobalDispatcher } from 'undici';
import { outboundIdentity } from './mtls.js';

// Outbound S2S fetch: when mTLS enforcement is on (admin Settings), calls to
// apps present the Cloudflare-issued client certificate; otherwise this is
// plain fetch. Trust is the edge's job — we only present, never verify peers
// beyond normal TLS. The agent is rebuilt when the cert changes (renew) and
// torn down when enforcement goes off.
let cached: { agent: Agent; sig: string } | null = null;
let stopping=false;
const agents=new Set<Agent>();
function retire(agent:Agent):void {void agent.close().catch(()=>{}).finally(()=>agents.delete(agent));}
function own(agent:Agent):Agent {agents.add(agent);return agent;}

export async function s2sFetch(url: string, init: RequestInit): Promise<Response> {
  if(stopping)throw Error('Service is shutting down.');
  const id = await outboundIdentity();
  if(stopping)throw Error('Service is shutting down.');
  if (!id) {
    if (cached) {
      retire(cached.agent);
      cached = null;
    }
    return fetch(url, init);
  }
  if (!cached || cached.sig !== id.cert) {
    if (cached) retire(cached.agent);
    cached = { agent: own(new Agent({ connect: { cert: id.cert, key: id.key } })), sig: id.cert };
  }
  // undici's fetch types differ cosmetically from the DOM lib's; the runtime
  // objects are compatible for our use (ok/status/json/text).
  return undiciFetch(url, {
    ...(init as Parameters<typeof undiciFetch>[1]),
    dispatcher: cached.agent,
  } as Parameters<typeof undiciFetch>[1]) as unknown as Promise<Response>;
}

/** Called only after accepted HTTP requests and background jobs have settled. */
export async function closeS2SFetch():Promise<void>{
 stopping=true;cached=null;
 const results=await Promise.allSettled([...agents].map(agent=>agent.close()).concat(getGlobalDispatcher().close()));
 if(results.some(result=>result.status==='rejected'))throw Error('Outbound cleanup failed.');
 agents.clear();
}
export function destroyS2SFetch():void {
 stopping=true;cached=null;
 for(const agent of agents)void agent.destroy().catch(()=>{});
 void getGlobalDispatcher().destroy().catch(()=>{});
}
