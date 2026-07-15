import { Agent, fetch as undiciFetch } from 'undici';
import { outboundIdentity } from './mtls.js';

// Outbound S2S fetch: when mTLS enforcement is on (admin Settings), calls to
// apps present the Cloudflare-issued client certificate; otherwise this is
// plain fetch. Trust is the edge's job — we only present, never verify peers
// beyond normal TLS. The agent is rebuilt when the cert changes (renew) and
// torn down when enforcement goes off.
let cached: { agent: Agent; sig: string } | null = null;

export async function s2sFetch(url: string, init: RequestInit): Promise<Response> {
  const id = await outboundIdentity();
  if (!id) {
    if (cached) {
      void cached.agent.close().catch(() => {});
      cached = null;
    }
    return fetch(url, init);
  }
  if (!cached || cached.sig !== id.cert) {
    if (cached) void cached.agent.close().catch(() => {});
    cached = { agent: new Agent({ connect: { cert: id.cert, key: id.key } }), sig: id.cert };
  }
  // undici's fetch types differ cosmetically from the DOM lib's; the runtime
  // objects are compatible for our use (ok/status/json/text).
  return undiciFetch(url, {
    ...(init as Parameters<typeof undiciFetch>[1]),
    dispatcher: cached.agent,
  } as Parameters<typeof undiciFetch>[1]) as unknown as Promise<Response>;
}
