// Dev relying party — the local stand-in for videosite-as-OIDC-client.
// Serves https://stream-dev.dreamxwarden.ca (via Caddy) and drives the full
// authorization-code + PKCE + private_key_jwt flow against the SSO.
import express from 'express';
import cookieParser from 'cookie-parser';
import crypto from 'node:crypto';
import fs from 'node:fs';
import { SignJWT, jwtVerify, createRemoteJWKSet, importJWK } from 'jose';

const ISSUER = process.env.SSO_ISSUER || 'https://sso-dev.dreamxwarden.ca';
const CLIENT_ID = 'videosite';
const REDIRECT = 'https://stream-dev.dreamxwarden.ca/callback';
const PORT = 4000;
// Back-channel S2S (token / jwks / userinfo). Defaults to the public/edge URL so dev
// mirrors prod, where S2S goes through the edge (mTLS) and the two services may live on
// different hosts. Overridable via SSO_INTERNAL — the seed of a future dedicated S2S
// hostname config — for when the services are co-located.
const INTERNAL = process.env.SSO_INTERNAL || ISSUER;

const privJwk = JSON.parse(fs.readFileSync(new URL('../.videosite-client-key.json', import.meta.url)));
const clientKey = await importJWK(privJwk, 'EdDSA');
const jwks = createRemoteJWKSet(new URL(INTERNAL + '/jwks'));

const esc = (s) => String(s).replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' })[c]);
const page = (body) => `<!DOCTYPE html><meta charset="utf-8"><title>Dev RP</title>
<body style="font-family:system-ui;background:#0e1117;color:#e6edf3;max-width:680px;margin:40px auto;padding:0 16px">${body}</body>`;

const app = express();
app.use(cookieParser());

app.get('/', (_req, res) => res.send(page(
  `<h1>Dev RP — videosite</h1><p><a style="color:#2f81f7" href="/login">Log in with DreamSSO →</a></p>`,
)));

app.get('/login', (_req, res) => {
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  const state = crypto.randomBytes(16).toString('base64url');
  const nonce = crypto.randomBytes(16).toString('base64url');
  res.cookie('rp_flow', JSON.stringify({ verifier, state, nonce }), {
    httpOnly: true, secure: true, sameSite: 'lax', maxAge: 600_000,
  });
  const u = new URL(ISSUER + '/authorize');
  u.search = new URLSearchParams({
    response_type: 'code', client_id: CLIENT_ID, redirect_uri: REDIRECT,
    scope: 'openid profile email', state, nonce,
    code_challenge: challenge, code_challenge_method: 'S256',
  }).toString();
  res.redirect(u.toString());
});

app.get('/callback', async (req, res) => {
  const flow = JSON.parse(req.cookies.rp_flow ?? '{}');
  if (req.query.error) return res.status(400).send(page(`<h1>Error</h1><pre>${esc(JSON.stringify(req.query, null, 2))}</pre>`));
  if (!req.query.code || req.query.state !== flow.state) return res.status(400).send(page('<h1>bad state</h1>'));

  const now = Math.floor(Date.now() / 1000);
  const assertion = await new SignJWT({})
    .setProtectedHeader({ alg: 'EdDSA', kid: privJwk.kid })
    .setIssuer(CLIENT_ID).setSubject(CLIENT_ID).setAudience(ISSUER)
    .setIssuedAt(now).setExpirationTime(now + 60).setJti(crypto.randomUUID())
    .sign(clientKey);

  const tr = await fetch(INTERNAL + '/token', {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code', code: String(req.query.code), redirect_uri: REDIRECT, code_verifier: flow.verifier,
      client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', client_assertion: assertion,
    }),
  });
  const tok = await tr.json();
  if (!tr.ok) return res.status(500).send(page(`<h1>token error</h1><pre>${esc(JSON.stringify(tok, null, 2))}</pre>`));

  const { payload } = await jwtVerify(tok.id_token, jwks, { issuer: ISSUER, audience: CLIENT_ID });
  if (payload.nonce !== flow.nonce) return res.status(400).send(page('<h1>nonce mismatch</h1>'));
  const ui = await (await fetch(INTERNAL + '/userinfo', { headers: { authorization: 'Bearer ' + tok.access_token } })).json();

  res.clearCookie('rp_flow');
  res.send(page(
    `<h1>Logged in ✓</h1>
     <h3>ID token claims</h3><pre>${esc(JSON.stringify(payload, null, 2))}</pre>
     <h3>/userinfo</h3><pre>${esc(JSON.stringify(ui, null, 2))}</pre>
     <p><a style="color:#2f81f7" href="/login">log in again</a></p>`,
  ));
});

app.listen(PORT, () => console.log(`dev RP listening on :${PORT} -> ${ISSUER}`));
