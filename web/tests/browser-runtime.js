async (page) => {
  const rows=[];
  const check=(name,ok)=>{rows.push({name,ok:!!ok});if(!ok)throw new Error(name);};
  const runtime=await page.evaluate(async()=>(await window.__command({action:'runtime'})).result);
  check('loaded cryptography is patched',runtime.cryptography==='50.0.2');
  check('loaded OpenSSL is patched',runtime.openssl.split(' ')[1]==='3.6.5');
  const address=page.url();
  const manifest=await (await page.request.get(new URL('assets.json',address).href)).json();
  const originalLock=await (await page.request.get(new URL('assets/pyodide-lock.json',address).href)).json();
  const name=originalLock.packages.cryptography.file_name;
  // Development-only public download for a downgrade regression. Never used by the app.
  const old=await (await page.request.get('https://cdn.jsdelivr.net/pyodide/v314.0.7/full/cryptography-47.0.0-cp314-abi3-pyemscripten_2026_0_wasm32.whl')).body();
  const digest=buffer=>page.evaluate(async encoded=>{
    const bytes=Uint8Array.from(atob(encoded),c=>c.charCodeAt(0));
    return [...new Uint8Array(await crypto.subtle.digest('SHA-256',bytes))].map(x=>x.toString(16).padStart(2,'0')).join('');
  },buffer.toString('base64'));
  const oldHash=await digest(old);
  if(oldHash!=='0b41491ced2cf85046559cac2502e875492cbef6d332addafa680e41be27f0ad')throw new Error('Public downgrade fixture digest mismatch');
  for(const scenario of ['old-binary','wrong-openssl-policy']) {
    const assets=structuredClone(manifest),lock=structuredClone(originalLock);
    if(scenario==='old-binary') {
      lock.packages.cryptography.sha256=oldHash;
      assets.files[name]={sha256:oldHash,bytes:old.length};
    } else lock.packages.cryptography.tool.openssl_version='3.6.2';
    const lockBytes=Buffer.from(JSON.stringify(lock));
    assets.files['pyodide-lock.json']={sha256:await digest(lockBytes),bytes:lockBytes.length};
    const test=await page.context().newPage();
    try {
      await test.route('**/assets.json',route=>route.fulfill({json:assets}));
      await test.route('**/assets/pyodide-lock.json',route=>route.fulfill({body:lockBytes,contentType:'application/json'}));
      if(scenario==='old-binary') await test.route('**/assets/'+name,route=>route.fulfill({body:old,contentType:'application/octet-stream'}));
      await test.goto(address);
      await test.getByText('引擎未就绪',{exact:true}).waitFor({timeout:90000});
      check(scenario+' fails before key input',await test.locator('#generate').isDisabled()&&await test.locator('#compare').isDisabled());
    } finally {await test.close();}
  }
  await page.evaluate(rows=>window.__runtimeChecks=rows,rows);
  console.log(JSON.stringify(rows));
}
