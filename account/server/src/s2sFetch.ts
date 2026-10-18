import { Agent, fetch as undiciFetch, getGlobalDispatcher } from 'undici';
import { outboundIdentity } from './mtls.js';

// Outbound S2S fetch to the SSO: when mTLS enforcement is on, calls present the
// Cloudflare-issued client certificate at the edge; otherwise this is plain fetch.
// Trust is the edge's job — we only PRESENT, never verify peers beyond normal TLS.
// The agent is rebuilt when the cert changes (renew) and torn down when enforcement
// goes off. Mirrors videosite/services/s2sFetch.js.
let cached: { agent: Agent; sig: string } | null = null;
let stopping=false;
const agents=new Set<Agent>();
function retire(agent:Agent):void {void agent.close().catch(()=>{}).finally(()=>agents.delete(agent));}
function own(agent:Agent):Agent {agents.add(agent);return agent;}

function drop(): void {
  if (cached) {
    retire(cached.agent);
    cached = null;
  }
}

export async function s2sFetch(url: string, init?: RequestInit): Promise<Response> {
  if(stopping)throw Error('Service is shutting down.');
  const id = outboundIdentity();
  if (!id) {
    drop();
    return fetch(url, init);
  }
  if (!cached || cached.sig !== id.cert) {
    drop();
    cached = { agent: own(new Agent({ connect: { cert: id.cert, key: id.key } })), sig: id.cert };
  }
  // undici's fetch types diverge slightly from the global lib.dom ones; the shapes
  // we use (method/headers/body/status/json/text) are identical at runtime.
  return undiciFetch(url, {
    ...(init as Record<string, unknown>),
    dispatcher: cached.agent,
  } as never) as unknown as Response;
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
