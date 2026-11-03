async (page) => {
  const rows=[];
  const check=(name,ok)=>{rows.push({name,ok:!!ok});if(!ok)throw new Error(name);};
  const address=page.url();
  const context=await page.context().browser().newContext();
  const test=await context.newPage();
  try {
    const host=new URL('../tests/isolation/host.html',address).href;
    // Real iframe, with the unmodified application delivered to the child.
    await test.goto(host);
    await test.setContent('<iframe title="synthetic frame"></iframe>');
    await test.locator('iframe').evaluate((frame,url)=>{frame.src=url;},address);
    const child=test.frameLocator('iframe');
    await child.getByText('加载失败',{exact:true}).waitFor({timeout:90000});
    check('framed application refuses key input',await child.locator('#generate').isDisabled()&&await child.locator('#compare').isDisabled());
    // Actual Service Worker, scoped to disposable test pages only.
    await test.goto(host);
    await test.evaluate(async()=>{
      await navigator.serviceWorker.register('./worker.js');
      await navigator.serviceWorker.ready;
      if(!navigator.serviceWorker.controller) await new Promise(resolve=>navigator.serviceWorker.addEventListener('controllerchange',resolve,{once:true}));
    });
    const controlled=new URL('./controlled/',host).href;
    await test.route('**/tests/isolation/controlled/**',async route=>{
      const suffix=route.request().url().slice(controlled.length);
      const response=await route.fetch({url:new URL(suffix||'index.html',address).href});
      await route.fulfill({response});
    });
    await test.goto(controlled);
    await test.getByText('加载失败',{exact:true}).waitFor({timeout:90000});
    check('existing service worker prevents engine startup',await test.evaluate(()=>!!navigator.serviceWorker.controller)&&await test.locator('#generate').isDisabled());
    // Clear cannot bypass a failed bootstrap.
    await test.locator('#clear-all').click();
    check('clear does not bypass controlled-origin rejection',await test.locator('#generate').isDisabled());
    await test.evaluate(async()=>{for(const registration of await navigator.serviceWorker.getRegistrations())await registration.unregister();});
  } finally {await context.close();}
  await page.evaluate(rows=>window.__isolation=rows,rows);
  console.log(JSON.stringify(rows));
}
