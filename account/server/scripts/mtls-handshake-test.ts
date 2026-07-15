// Proves the portal actually PRESENTS its client certificate in a real TLS
// handshake — the one thing the unit test can't show (it only checks that
// outboundIdentity() hands the agent the right material).
//
// A local https server asks for a client cert (requestCert) and reports back what
// it saw. We call it through the portal's own s2sFetch and assert:
//   enforcement ON  -> the server sees our leaf, by CN, and the chain we sent
//   enforcement OFF -> the server sees no client cert at all (plain-fetch path)
//
// NODE_EXTRA_CA_CERTS has to be set before Node boots, so this runs in two phases:
// the parent mints the server's CA + cert, then re-execs itself as the child that
// does the actual handshake.
//
// Run: npx tsx scripts/mtls-handshake-test.ts        (from account/server)
import 'reflect-metadata';
import * as x509 from '@peculiar/x509';
import { spawn } from 'node:child_process';
import { webcrypto } from 'node:crypto';
import fs from 'node:fs';
import https from 'node:https';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

x509.cryptoProvider.set(webcrypto as unknown as Crypto);
const EC = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' };
const PORT = 3995;

async function pkcs8(key: CryptoKey): Promise<string> {
  const der = Buffer.from(await webcrypto.subtle.exportKey('pkcs8', key));
  return '-----BEGIN PRIVATE KEY-----\n' + der.toString('base64').match(/.{1,64}/g)!.join('\n') + '\n-----END PRIVATE KEY-----\n';
}

// ---------------------------------------------------------------- phase 1 (parent)
if (!process.env.MTLS_HS_CHILD) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dxw-hs-'));
  const caKeys = (await webcrypto.subtle.generateKey(EC, true, ['sign', 'verify'])) as CryptoKeyPair;
  const ca = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: '01',
    name: 'CN=Local Test CA',
    notBefore: new Date(Date.now() - 3600e3),
    notAfter: new Date(Date.now() + 864e5),
    signingAlgorithm: EC,
    keys: caKeys,
    extensions: [new x509.BasicConstraintsExtension(true, 1, true)],
  });
  const srvKeys = (await webcrypto.subtle.generateKey(EC, true, ['sign', 'verify'])) as CryptoKeyPair;
  const srv = await x509.X509CertificateGenerator.create({
    serialNumber: '02',
    subject: 'CN=localhost',
    issuer: ca.subject,
    notBefore: new Date(Date.now() - 3600e3),
    notAfter: new Date(Date.now() + 864e5),
    signingAlgorithm: EC,
    publicKey: srvKeys.publicKey,
    signingKey: caKeys.privateKey,
    extensions: [
      new x509.BasicConstraintsExtension(false, undefined, true),
      new x509.SubjectAlternativeNameExtension([{ type: 'dns', value: 'localhost' }]),
    ],
  });
  fs.writeFileSync(path.join(dir, 'ca.pem'), ca.toString('pem'));
  fs.writeFileSync(path.join(dir, 'srv.pem'), srv.toString('pem'));
  fs.writeFileSync(path.join(dir, 'srv.key'), await pkcs8(srvKeys.privateKey));

  // Re-exec through tsx (not process.execPath — plain node has no TS loader).
  const self = fileURLToPath(import.meta.url);
  const tsx = path.resolve(path.dirname(self), '../node_modules/.bin/tsx');
  const child = spawn(tsx, [self], {
    env: {
      ...process.env,
      MTLS_HS_CHILD: '1',
      MTLS_HS_DIR: dir,
      MTLS_STATE_FILE: path.join(dir, 'mtls.json'),
      NODE_EXTRA_CA_CERTS: path.join(dir, 'ca.pem'), // so undici trusts our test server
    },
    stdio: 'inherit',
  });
  child.on('exit', (code) => {
    fs.rmSync(dir, { recursive: true, force: true });
    process.exit(code ?? 1);
  });
} else {
  // ------------------------------------------------------------- phase 2 (child)
  const dir = process.env.MTLS_HS_DIR!;
  const mtls = await import('../src/mtls.js');
  const { s2sFetch } = await import('../src/s2sFetch.js');

  let pass = 0;
  let fail = 0;
  const check = (n: string, ok: boolean, detail?: unknown) => {
    if (ok) { pass++; console.log('  ✓ ' + n); }
    else { fail++; console.error('  ✗ ' + n, detail !== undefined ? JSON.stringify(detail) : ''); }
  };

  // The "SSO behind Cloudflare": asks for a client cert, doesn't verify it (the edge
  // would), and echoes back what the handshake actually carried.
  const server = https.createServer(
    {
      cert: fs.readFileSync(path.join(dir, 'srv.pem')),
      key: fs.readFileSync(path.join(dir, 'srv.key')),
      requestCert: true,
      rejectUnauthorized: false,
    },
    (req, res) => {
      const peer = (req.socket as import('tls').TLSSocket).getPeerCertificate(true);
      const present = !!peer && Object.keys(peer).length > 0;
      const chain: string[] = [];
      for (let c: typeof peer | undefined = present ? peer : undefined; c; c = c.issuerCertificate === c ? undefined : c.issuerCertificate) {
        chain.push(c.subject?.CN ?? '?');
      }
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ present, cn: present ? peer.subject?.CN : null, chain }));
    },
  );
  await new Promise<void>((r) => server.listen(PORT, '127.0.0.1', r));
  const URL_ = 'https://localhost:' + PORT + '/token';

  // A CA standing in for Cloudflare, issuing our client cert.
  const caKeys = (await webcrypto.subtle.generateKey(EC, true, ['sign', 'verify'])) as CryptoKeyPair;
  const clientCa = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: '01', name: 'CN=Client CA',
    notBefore: new Date(Date.now() - 3600e3), notAfter: new Date(Date.now() + 864e5),
    signingAlgorithm: EC, keys: caKeys,
    extensions: [new x509.BasicConstraintsExtension(true, 1, true)],
  });

  try {
    // --- no cert yet: s2sFetch must fall back to a plain, anonymous connection ---
    const anon = await (await s2sFetch(URL_)).json() as { present: boolean };
    check('no cert installed -> handshake carries NO client cert', anon.present === false, anon);

    // --- install a cert the way the wizard does ---
    const { csr } = await mtls.startSetup('portal-handshake');
    const parsed = new x509.Pkcs10CertificateRequest(csr);
    const leaf = await x509.X509CertificateGenerator.create({
      serialNumber: '02', subject: parsed.subject, issuer: clientCa.subject,
      notBefore: new Date(Date.now() - 3600e3), notAfter: new Date(Date.now() + 864e5),
      signingAlgorithm: EC, publicKey: parsed.publicKey, signingKey: caKeys.privateKey,
      extensions: [
        new x509.BasicConstraintsExtension(false, undefined, true),
        new x509.ExtendedKeyUsageExtension(['1.3.6.1.5.5.7.3.2'], true), // clientAuth
      ],
    });
    // Chain pasted CA-first, as a CA portal would hand it over.
    const res = mtls.installCert(clientCa.toString('pem') + '\n' + leaf.toString('pem'));
    check('cert installs + auto-enables', res.ok === true && mtls.getStatus().enforce === true);

    // --- THE point of this test: the cert is actually presented on the wire ---
    const withCert = await (await s2sFetch(URL_)).json() as { present: boolean; cn: string; chain: string[] };
    check('handshake NOW carries our client cert', withCert.present === true, withCert);
    check('  the peer cert is OUR leaf (by CN)', withCert.cn === 'portal-handshake', withCert.cn);
    check('  the leaf was sent FIRST (server sees it as the peer cert)', withCert.chain[0] === 'portal-handshake', withCert.chain);
    check('  the intermediate went with it', withCert.chain.includes('Client CA'), withCert.chain);

    // --- turning enforcement off must tear the agent down, not keep using it ---
    mtls.setEnforce(false);
    const off = await (await s2sFetch(URL_)).json() as { present: boolean };
    check('enforcement off -> back to an anonymous handshake', off.present === false, off);

    mtls.setEnforce(true);
    const back = await (await s2sFetch(URL_)).json() as { present: boolean; cn: string };
    check('enforcement back on -> presenting again', back.present === true && back.cn === 'portal-handshake', back);
  } catch (e) {
    fail++;
    console.error('EXCEPTION:', e);
  } finally {
    server.close();
  }

  console.log(`\nportal mtls handshake: ${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
}
