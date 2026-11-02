/* Real Chromium acceptance for the built viewer and its same-origin bridge.
 * Run scripts/attack-flow-smoke-fixture first. No production data is used.
 */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const { chromium } = require('../runtime/browser-check/node_modules/playwright');
const root = path.resolve(__dirname, '..');
const artifacts = path.join(root, 'runtime/attack-flow-smoke/artifacts');
const viewer = path.join(root, 'runtime/attack-flow-viewer');
const packageId = fs.readdirSync(artifacts).find(id => {
  const file = path.join(artifacts, id, 'attack-flow.json');
  if (!fs.existsSync(file)) return false;
  return JSON.parse(fs.readFileSync(file)).objects.filter(o => o.type === 'attack-action').length === 3;
});
assert.ok(packageId, 'authored three-action fixture missing');
const original = fs.readFileSync(path.join(artifacts, packageId, 'attack-flow.json'));
const artifactPath = `/api/artifacts/${packageId}/attack-flow.json`;
const types = {'.js':'text/javascript','.css':'text/css','.html':'text/html','.json':'application/json','.woff2':'font/woff2','.svg':'image/svg+xml'};
let origin;
const server = http.createServer((req, res) => {
  const url = new URL(req.url, origin);
  if (url.pathname === '/') {
    const query = new URLSearchParams({src: `${origin}${artifactPath}?customer_id=fictional-bank&environment_id=windows-ad`, iti_frame:'smoke', iti_package:packageId});
    if (!url.searchParams.has('editor')) query.set('readonly','true');
    res.setHeader('Content-Type','text/html');
    res.end(`<html><body><script>window.messages=[];addEventListener('message',e=>{if(e.origin===location.origin && e.source===document.querySelector('iframe').contentWindow)messages.push(e.data)});</script><iframe style="width:1200px;height:800px" src="/attack-flow-builder/?${query.toString()}"></iframe></body></html>`);
  } else if (url.pathname === artifactPath) {
    res.setHeader('Content-Type','application/json');res.end(original);
  } else if (url.pathname.startsWith('/attack-flow-builder/')) {
    const name = decodeURIComponent(url.pathname.slice('/attack-flow-builder/'.length)) || 'index.html';
    const file = path.resolve(viewer,name);
    if (!file.startsWith(viewer+path.sep) || !fs.existsSync(file) || !fs.statSync(file).isFile()) {res.writeHead(404);res.end();return;}
    res.setHeader('Content-Type',types[path.extname(file)] || 'application/octet-stream');res.end(fs.readFileSync(file));
  } else {res.writeHead(404);res.end();}
});
(async () => {
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  origin = `http://127.0.0.1:${server.address().port}`;
  let browser;
  try {
    browser = await chromium.launch({headless:true});
    const page = await browser.newPage({viewport:{width:1280,height:900}});
    const errors=[], outbound=[];
    page.on('pageerror',e=>errors.push(e.message));
    await page.route('**/*',route=>{
      if (new URL(route.request().url()).origin !== origin) {outbound.push(route.request().url());return route.abort();}
      return route.continue();
    });
    for (const mode of ['viewer','editor']) {
      await page.goto(origin+(mode==='editor'?'/?editor':''));
      await page.waitForFunction(()=>window.messages.some(m=>m.status==='ready'),{},{timeout:30000});
      const ready = await page.evaluate(()=>window.messages.find(m=>m.status==='ready'));
      assert.equal(ready.nodes,3);assert.equal(ready.edges,1);
      assert.equal(ready.packageId,packageId);assert.equal(ready.frame,'smoke');
      const frame = page.frameLocator('iframe');
      if (mode==='editor') await frame.getByText('Properties',{exact:true}).first().waitFor();
      assert.equal(await frame.getByText('Chat',{exact:true}).count(),0);
      await page.evaluate(()=>{window.messages=[];document.querySelector('iframe').contentWindow.postMessage({type:'iti-attack-flow-fit',frame:'smoke',packageId:new URL(document.querySelector('iframe').src).searchParams.get('iti_package')},location.origin);});
      await page.waitForFunction(()=>window.messages.some(m=>m.status==='ready'));
      assert.equal(await page.evaluate(()=>window.messages.some(m=>m.status==='error')),false);
    }
    assert.deepEqual(errors,[]);assert.deepEqual(outbound,[]);
    assert.deepEqual(fs.readFileSync(path.join(artifacts,packageId,'attack-flow.json')),original);
    console.log('Browser smoke passed: viewer/editor, 3 nodes / 1 edge, Fit bridge, no Chat/outbound/page errors, immutable artifact preserved.');
  } finally {if(browser)await browser.close();await new Promise(resolve=>server.close(resolve));}
})().catch(e=>{console.error(e);process.exitCode=1;});
