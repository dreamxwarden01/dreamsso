import { Agent, fetch as undiciFetch } from 'undici';
import { outboundIdentity } from './mtls.js';

// Outbound S2S fetch to the SSO: when mTLS enforcement is on, calls present the
// Cloudflare-issued client certificate at the edge; otherwise this is plain fetch.
// Trust is the edge's job — we only PRESENT, never verify peers beyond normal TLS.
// The agent is rebuilt when the cert changes (renew) and torn down when enforcement
// goes off. Mirrors videosite/services/s2sFetch.js.
let cached: { agent: Agent; sig: string } | null = null;

function drop(): void {
  if (cached) {
    void cached.agent.close().catch(() => {});
    cached = null;
  }
}

export async function s2sFetch(url: string, init?: RequestInit): Promise<Response> {
  const id = outboundIdentity();
  if (!id) {
    drop();
    return fetch(url, init);
  }
  if (!cached || cached.sig !== id.cert) {
    drop();
    cached = { agent: new Agent({ connect: { cert: id.cert, key: id.key } }), sig: id.cert };
  }
  // undici's fetch types diverge slightly from the global lib.dom ones; the shapes
  // we use (method/headers/body/status/json/text) are identical at runtime.
  return undiciFetch(url, {
    ...(init as Record<string, unknown>),
    dispatcher: cached.agent,
  } as never) as unknown as Response;
}
