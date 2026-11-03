async (page) => {
  const rows=[];
  for(const width of [1440,1024,768,390,320]) {
    await page.setViewportSize({width,height:960});
    for(const view of ['generate','convert','compare','certificates','help']) {
      await page.locator(`[data-view="${view}"]`).click();
      rows.push(await page.evaluate(({width,view})=>({width,view,ok:document.documentElement.scrollWidth<=innerWidth}),{width,view}));
      if((width===1440||width===390)&&['generate','convert','compare'].includes(view))
        await page.screenshot({path:`output/playwright/web-${view}-${width}.png`,fullPage:true});
    }
  }
  await page.setViewportSize({width:1280,height:900});
  await page.locator('[data-view="generate"]').click();
  await page.evaluate(rows=>window.__layout=rows,rows);
  console.log(JSON.stringify(rows));
  if(rows.some(row=>!row.ok)) throw new Error('Responsive layout overflow');
}
