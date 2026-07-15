// Generates the `videosite` client's keypair for private_key_jwt:
//   - writes the private JWK to ../.videosite-client-key.json (gitignored; the dev RP reads it)
//   - registers the public JWK in oauth_clients.jwks
// Run with PG* env set.
import { generateKeyPair, exportJWK, calculateJwkThumbprint } from 'jose';
import pg from 'pg';
import fs from 'node:fs';

const OUT = new URL('../.videosite-client-key.json', import.meta.url);

const { publicKey, privateKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });
const pub = await exportJWK(publicKey);
const priv = await exportJWK(privateKey);
const kid = await calculateJwkThumbprint(pub);
pub.kid = kid; pub.alg = 'EdDSA'; pub.use = 'sig';
priv.kid = kid; priv.alg = 'EdDSA';

fs.writeFileSync(OUT, JSON.stringify(priv, null, 2));

const pool = new pg.Pool();
await pool.query("UPDATE oauth_clients SET jwks = $1 WHERE client_id = 'videosite'", [{ keys: [pub] }]);
await pool.end();
console.log(`videosite client key ready (kid ${kid}); public JWK registered, private -> ${OUT.pathname}`);
