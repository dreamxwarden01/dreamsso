import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import type { AddressInfo } from 'node:net';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { brandRouter, BRAND_DIR, FONT_DIR } from '../src/branding.js';

test('public branding has font MIME/cache and cannot bypass the following setup gate', async () => {
  const app = express();
  app.use(brandRouter);
  app.use((_req,res)=>{res.status(503).send('setup gate');});
  const server = app.listen(0, '127.0.0.1');
  await new Promise<void>(resolve=>server.once('listening',resolve));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  try {
    for (const [url, mime] of [['v1/fonts.css','text/css'],['v1/geist-sans.woff2','font/woff2'],['v1/favicon.svg','image/svg+xml'],['v1/apple-touch-icon.png','image/png'],['v2/fonts.css','text/css'],['v2/inter-variable.woff2','font/woff2']]) {
      const res = await fetch(`${base}/brand/${url}`);
      assert.equal(res.status,200);
      assert.ok(res.headers.get('content-type')?.startsWith(mime));
      assert.match(res.headers.get('cache-control')!,/max-age=31536000.*immutable/);
      assert.ok((await res.arrayBuffer()).byteLength > 0);
    }
    for (const version of ['v1','v2']) for (const url of ['missing.woff2','.env','%2e%2e%2f.env','%2e%2e%2fpackage.json','']) {
      const res=await fetch(`${base}/brand/${version}/${url}`);
      assert.equal(res.status,404);
      assert.equal(await res.text(),'');
    }
    for (const version of ['v1','v2']) assert.equal((await fetch(`${base}/brand/${version}/fonts.css`,{method:'POST'})).status,404);
    assert.equal((await fetch(`${base}/admin`)).status,503);
    assert.equal((await fetch(`${base}/brand/v1/../../.env`)).status,503);
  } finally { server.closeAllConnections(); await new Promise<void>(resolve=>server.close(()=>resolve())); }
});

test('both font-kit generations resolve locally and v2 reuses immutable CJK/mono files',()=>{
  const brandRoot=path.resolve(BRAND_DIR,'..');
  const referenced = new Map<string, string[]>();
  for (const directory of [BRAND_DIR,FONT_DIR]) {
    const css=readFileSync(path.join(directory,'fonts.css'),'utf8');
    const urls=[...css.matchAll(/url\(['"]?([^)'"\s]+)['"]?\)/g)].map(match=>match[1]);
    referenced.set(directory,urls);
    assert.equal(urls.length,211);
    assert.doesNotMatch(css,/@import|https?:\/\//);
    for(const url of urls){
      const absolute=path.resolve(directory,url),relative=path.relative(brandRoot,absolute);
      assert.ok(!relative.startsWith('..')&&!path.isAbsolute(relative));
      assert.equal(readFileSync(absolute).subarray(0,4).toString(),'wOF2');
      if(directory===FONT_DIR) {
        assert.ok(url==='./inter-variable.woff2'||url.startsWith('../v1/'));
      } else assert.ok(url.startsWith('./'));
    }
  }
  assert.deepEqual(
    new Set(referenced.get(FONT_DIR)!.filter(url=>url!=='./inter-variable.woff2').map(url=>'./'+url.slice('../v1/'.length))),
    new Set(referenced.get(BRAND_DIR)!.filter(url=>url!=='./geist-sans.woff2')),
  );
});
