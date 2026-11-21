import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import type { AddressInfo } from 'node:net';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { brandRouter, BRAND_DIR } from '../src/branding.js';

test('public branding has font MIME/cache and cannot bypass the following setup gate', async () => {
  const app = express();
  app.use(brandRouter);
  app.use((_req,res)=>{res.status(503).send('setup gate');});
  const server = app.listen(0, '127.0.0.1');
  await new Promise<void>(resolve=>server.once('listening',resolve));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  try {
    for (const [url, mime] of [['fonts.css','text/css'],['geist-sans.woff2','font/woff2'],['favicon.svg','image/svg+xml'],['apple-touch-icon.png','image/png']]) {
      const res = await fetch(`${base}/brand/v1/${url}`);
      assert.equal(res.status,200);
      assert.ok(res.headers.get('content-type')?.startsWith(mime));
      assert.match(res.headers.get('cache-control')!,/max-age=31536000.*immutable/);
      assert.ok((await res.arrayBuffer()).byteLength > 0);
    }
    for (const url of ['missing.woff2','.env','%2e%2e%2f.env','%2e%2e%2fpackage.json','']) {
      const res=await fetch(`${base}/brand/v1/${url}`);
      assert.equal(res.status,404);
      assert.equal(await res.text(),'');
    }
    assert.equal((await fetch(`${base}/brand/v1/fonts.css`,{method:'POST'})).status,404);
    assert.equal((await fetch(`${base}/admin`)).status,503);
    assert.equal((await fetch(`${base}/brand/v1/../../.env`)).status,503);
  } finally { server.closeAllConnections(); await new Promise<void>(resolve=>server.close(()=>resolve())); }
});

test('all CSS font URLs resolve to shipped WOFF2 files without external origins',()=>{
  const css=readFileSync(path.join(BRAND_DIR,'fonts.css'),'utf8');
  const urls=[...css.matchAll(/url\(['"]?([^)'"\s]+)['"]?\)/g)].map(match=>match[1]);
  assert.ok(urls.length > 200);
  for(const url of urls){
    assert.ok(url.startsWith('./'));
    assert.equal(readFileSync(path.resolve(BRAND_DIR,url)).subarray(0,4).toString(),'wOF2');
  }
  assert.doesNotMatch(css,/@import|https?:\/\//);
});
