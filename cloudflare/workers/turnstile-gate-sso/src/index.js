// turnstile-gate-sso — edge Turnstile verification for the account portal's
// public flows (videosite's turnstile-gate lineage, minus its coordination
// toggle). On every routed POST:
//   1. Strip any inbound x-gate-* headers — clients can never smuggle a
//      signature through (same trust model as cf-connecting-ip). This is the
//      primary replay defense: a captured signed request re-sent through the
//      edge loses its signature here.
//   2. Parse the JSON body, verify `turnstile_token` with siteverify
//      (including CF-Connecting-IP), 403 `{error:"turnstile_failed"}` on any
//      failure — the same shape the origin uses.
//   3. Strip the token from the body and SIGN what is actually forwarded:
//      an Ed25519 JWT (back-channel style) in x-gate-assertion with
//      {iss, aud, iat, exp=iat+90s, jti, path, body_sha256}. The random jti
//      guarantees no two assertions are ever identical (Ed25519 is
//      deterministic — same body in the same second would otherwise repeat).
//      The origin verifies against the stored PUBLIC JWK, binds the path, and
//      hashes the exact received bytes.
//
// The origin accepts token OR assertion, so this worker is optional per
// deployment — no origin toggle to coordinate. Misconfigured env fails loud
// (503) instead of silently 403-ing every reset.

const SITEVERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';

const FAILURE_HEADERS = {
  'Content-Type': 'application/json; charset=utf-8',
  'Cache-Control': 'no-store',
};

function failure() {
  return new Response(JSON.stringify({ error: 'turnstile_failed' }), {
    status: 403,
    headers: FAILURE_HEADERS,
  });
}

const enc = new TextEncoder();

function b64u(buf) {
  let bin = '';
  const bytes = new Uint8Array(buf);
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function verifyToken(token, ip, secret) {
  if (!token || typeof token !== 'string') return false;
  const form = new FormData();
  form.append('secret', secret);
  form.append('response', token);
  if (ip) form.append('remoteip', ip);
  let result;
  try {
    const res = await fetch(SITEVERIFY_URL, { method: 'POST', body: form });
    if (!res.ok) return false;
    result = await res.json();
  } catch {
    // siteverify unreachable -> fail closed; a rare flap surfaces as a 403,
    // better than letting a bot through.
    return false;
  }
  return result?.success === true;
}

async function signAssertion(privJwk, claims) {
  const key = await crypto.subtle.importKey('jwk', privJwk, { name: 'Ed25519' }, false, ['sign']);
  const header = b64u(enc.encode(JSON.stringify({ alg: 'EdDSA', typ: 'JWT', kid: privJwk.kid })));
  const payload = b64u(enc.encode(JSON.stringify(claims)));
  const sig = await crypto.subtle.sign('Ed25519', key, enc.encode(`${header}.${payload}`));
  return `${header}.${payload}.${b64u(sig)}`;
}

// Forwarded headers: originals minus content-length (recomputed from the new
// body) minus every inbound x-gate-* (client-supplied signatures never pass).
function forwardHeaders(request) {
  const headers = new Headers(request.headers);
  headers.delete('content-length');
  for (const name of [...headers.keys()]) {
    if (name.toLowerCase().startsWith('x-gate-')) headers.delete(name);
  }
  return headers;
}

export default {
  async fetch(request, env) {
    if (!env.TURNSTILE_SECRET_KEY || !env.GATE_SIGNING_KEY) {
      return new Response(JSON.stringify({ error: 'turnstile_gate_misconfigured' }), {
        status: 503,
        headers: FAILURE_HEADERS,
      });
    }

    // These three routes are POST-only (the only method that does anything).
    // Reject everything else at the edge with 405 — no origin round-trip for junk
    // methods, and no non-POST can slip an x-gate-* header past the worker.
    if (request.method !== 'POST') {
      return new Response(JSON.stringify({ error: 'method_not_allowed' }), {
        status: 405,
        headers: { ...FAILURE_HEADERS, Allow: 'POST' },
      });
    }

    let body;
    try {
      body = await request.json();
    } catch {
      // The gated endpoints only take JSON; anything else is suspicious.
      return failure();
    }

    const ip = request.headers.get('CF-Connecting-IP') || '';
    if (!(await verifyToken(body?.turnstile_token, ip, env.TURNSTILE_SECRET_KEY))) {
      return failure();
    }

    delete body.turnstile_token;
    const bodyStr = JSON.stringify(body);
    const now = Math.floor(Date.now() / 1000);
    const url = new URL(request.url);
    const assertion = await signAssertion(JSON.parse(env.GATE_SIGNING_KEY), {
      iss: 'turnstile-gate',
      aud: 'account-bff',
      iat: now,
      exp: now + 90,
      jti: crypto.randomUUID(),
      path: url.pathname,
      body_sha256: b64u(await crypto.subtle.digest('SHA-256', enc.encode(bodyStr))),
    });

    const headers = forwardHeaders(request);
    headers.set('content-type', 'application/json');
    headers.set('x-gate-assertion', assertion);

    return fetch(new Request(request.url, {
      method: 'POST',
      headers,
      body: bodyStr,
      redirect: 'manual',
    }));
  },
};
