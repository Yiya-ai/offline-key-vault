async (page) => {
  const rows=[];
  const check=(name,ok)=>{rows.push({name,ok:!!ok});if(!ok)throw new Error(name);};
  await page.clock.install();
  await page.reload();
  await page.getByText('仅本地计算 · 网络已关闭',{exact:true}).waitFor({timeout:90000});
  await page.locator('[data-view="generate"]').click();
  await page.locator('#generate').click();
  await page.waitForFunction(()=>document.querySelector('#preview').value.includes('BEGIN PUBLIC KEY'));
  await page.clock.fastForward(305000);
  await page.clock.runFor(5000);
  await page.waitForFunction(()=>document.querySelector('#preview').value==='');
  await page.getByText('仅本地计算 · 网络已关闭',{exact:true}).waitFor({timeout:90000});
  check('idle clears current key',await page.evaluate(()=>document.querySelector('#preview').value===''));
  check('idle drops worker material',await page.evaluate(async()=>!(await window.__command({action:'preview',id:0})).ok));
  await page.clock.resume();
  await page.locator('#generate').click();
  await page.waitForFunction(()=>document.querySelector('#preview').value.includes('BEGIN PUBLIC KEY'));
  await page.reload();
  await page.getByText('仅本地计算 · 网络已关闭',{exact:true}).waitFor({timeout:90000});
  check('reload does not restore keys',await page.evaluate(()=>document.querySelector('#preview').value===''));
  const broken=await page.context().newPage();
  try {
    await broken.route('**/assets/kernel.py',async route=>{
      const response=await route.fetch();
      await route.fulfill({response,body:(await response.text())+'\n# synthetic tamper test\n'});
    });
    await broken.goto(page.url());
    await broken.getByText('加载失败',{exact:true}).waitFor({timeout:90000});
    check('tampered runtime fails closed',await broken.locator('#generate').isDisabled()&&await broken.locator('#compare').isDisabled());
    check('tampered runtime creates no worker',await broken.evaluate(()=>!window.__worker));
  } finally {await broken.close();}
  await page.evaluate(rows=>window.__lifecycle=rows,rows);
  console.log(JSON.stringify(rows));
}
