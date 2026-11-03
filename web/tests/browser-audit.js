async (page) => {
  // Test-only observation of our own worker and synthetic file reads. Never ship.
  await page.addInitScript(() => {
    const Original = window.Worker;
    window.Worker = class extends Original {
      constructor(...args) { super(...args); window.__auditWorker = this; }
      postMessage(data, ...args) {
        if (window.__holdPreview && data.type === 'command' && data.message.action === 'preview' && data.message.private) {
          window.__releasePreview = () => super.postMessage(data, ...args); return;
        }
        return super.postMessage(data, ...args);
      }
    };
    const originalRead = File.prototype.arrayBuffer;
    File.prototype.arrayBuffer = function () {
      const result = originalRead.call(this);
      return this.name === 'held-public.pem' ? result.then(bytes => new Promise(resolve => {
        window.__fileHeld = true; window.__releaseFile = () => resolve(bytes);
      })) : result;
    };
    let serial = 800000;
    window.__auditCommand = message => new Promise((resolve, reject) => {
      const worker = window.__auditWorker, id = ++serial;
      const timer = setTimeout(() => reject(new Error('Audit command timeout')), 30000);
      const receive = ({data}) => {
        if (data.type === 'result' && data.id === id) {
          clearTimeout(timer); worker.removeEventListener('message', receive); resolve(data);
        }
      };
      worker.addEventListener('message', receive); worker.postMessage({type:'command', id, message});
    });
  });
  await page.reload();
  const ready = () => page.getByText('仅本地计算 · 网络已关闭', {exact:true}).waitFor({timeout:90000});
  await ready();
  const rows = [];
  const check = (name, ok) => { rows.push({name,ok:!!ok}); if (!ok) throw new Error(name); };
  check('revealed passwords opt out of browser spellcheck and correction',await page.evaluate(()=>
    [...document.querySelectorAll('[data-password]')].every(button=>{
      const field=document.getElementById(button.dataset.password);
      return field.spellcheck===false && field.getAttribute('autocapitalize')==='off' && field.getAttribute('autocorrect')==='off';
    })));
  let probeRequests = 0;
  await page.route('**/audit-probe-*', route => { probeRequests++; return route.fulfill({body:'',contentType:'text/css'}); });
  const csp = await page.evaluate(async () => {
    const before = getComputedStyle(document.body).fontFamily;
    const style = document.createElement('link'); style.rel = 'stylesheet'; style.href = './audit-probe-style.css';
    const loaded = new Promise(resolve => {style.onload=()=>resolve(true);style.onerror=()=>resolve(false);});
    document.head.append(style);
    const rejected = !(await loaded); style.remove();
    return {rejected,styled:before.includes('Microsoft YaHei') && before === getComputedStyle(document.body).fontFamily,
      fetchBlocked:await fetch('./audit-probe-fetch').then(()=>false,()=>true)};
  });
  check('post-bootstrap stylesheet requests blocked', csp.rejected && probeRequests === 0);
  check('existing stylesheet remains applied', csp.styled);
  check('post-bootstrap fetch blocked', csp.fetchBlocked);
  await page.locator('#algorithm').selectOption('Ed25519');
  await page.locator('#generate').click();
  await page.waitForFunction(()=>document.querySelector('#preview').value.includes('BEGIN PUBLIC KEY'));
  const publicText = await page.locator('#preview').inputValue();
  await page.locator('#toggle-private').click();
  await page.waitForFunction(()=>document.querySelector('#preview').value.includes('BEGIN PRIVATE KEY'));
  await page.evaluate(()=>window.dispatchEvent(new Event('blur')));
  check('blur removes visible private content',await page.locator('#preview').inputValue()==='');
  await page.locator('#export-password').fill('Synthetic audit password');
  await page.locator('[data-password="export-password"]').click();
  check('password eye explicitly reveals',await page.locator('#export-password').getAttribute('type')==='text');
  await page.evaluate(()=>window.dispatchEvent(new Event('blur')));
  check('blur conceals visible password',await page.locator('#export-password').getAttribute('type')==='password');
  await page.evaluate(()=>{window.__holdPreview=true;});
  await page.locator('#toggle-private').click();
  await page.waitForFunction(()=>!!window.__releasePreview);
  await page.evaluate(()=>{window.dispatchEvent(new Event('blur'));window.__holdPreview=false;window.__releasePreview();});
  await page.waitForFunction(()=>!document.body.classList.contains('busy'));
  check('late private preview cannot undo automatic hiding',await page.locator('#preview').inputValue()==='');
  await page.locator('#toggle-private').click();
  await page.waitForFunction(()=>document.querySelector('#preview').value.includes('BEGIN PRIVATE KEY'));
  await page.locator('[data-view="convert"]').click();
  check('navigation hides visible private key',!(await page.locator('#preview').inputValue()).includes('PRIVATE'));
  await page.locator('#input-file').setInputFiles({name:'held-public.pem',mimeType:'application/octet-stream',buffer:Buffer.from(publicText)});
  await page.locator('#inspect').click();
  await page.waitForFunction(()=>window.__fileHeld);
  check('whole operation locks editable fields and actions',await page.evaluate(()=>
    ['inspect','input-password','output-name','export-public','export-private'].every(id=>document.getElementById(id).matches(':disabled'))
    && [...document.querySelectorAll('[data-view]')].every(x=>x.disabled)));
  check('old key discarded before asynchronous file read',await page.evaluate(async()=>!(await window.__auditCommand({action:'preview',id:0})).ok));
  await page.locator('#clear-all').click();
  await ready();
  await page.evaluate(()=>window.__releaseFile());
  await page.waitForFunction(()=>!document.body.classList.contains('busy'));
  check('clear cancels delayed file result',await page.locator('#key-result').isHidden());
  check('cancelled file does not restore worker key',await page.evaluate(async()=>!(await window.__auditCommand({action:'preview',id:0})).ok));
  await page.locator('[data-view="generate"]').click();
  await page.locator('#algorithm').selectOption('Ed25519');
  await page.locator('#key-name').fill('<img src=x onerror=alert(1)>');
  await page.locator('#generate').click();
  await page.waitForFunction(()=>document.querySelector('#preview').value.includes('BEGIN PUBLIC KEY'));
  check('key name cannot inject markup',await page.locator('#output-name').inputValue()==='<img src=x onerror=alert(1)>' && await page.locator('img[src="x"]').count()===0);
  await page.locator('[data-view="convert"]').click();
  await page.locator('#input-text').fill('synthetic-invalid-key-private-marker');
  await page.locator('#input-password').fill('synthetic-secret-marker');
  await page.locator('#inspect').click();
  await page.waitForFunction(()=>!document.body.classList.contains('busy'));
  check('invalid input hides previous result',await page.locator('#key-result').isHidden());
  check('invalid input drops previous worker key',await page.evaluate(async()=>!(await window.__auditCommand({action:'preview',id:0})).ok));
  const error = await page.locator('#message').textContent();
  check('parser errors do not echo sensitive input',!error.includes('private-marker')&&!error.includes('secret-marker'));
  check('failed import clears password',await page.locator('#input-password').inputValue()==='');
  await page.locator('[data-view="compare"]').click();
  await page.locator('#private-password').fill('synthetic-secret-marker');
  await page.locator('#compare').click();
  await page.waitForFunction(()=>!document.body.classList.contains('busy'));
  check('failed comparison input clears password',await page.locator('#private-password').inputValue()==='');
  await page.locator('[data-view="generate"]').click();
  await page.locator('#generate').click();
  await page.waitForFunction(()=>document.querySelector('#preview').value.includes('BEGIN PUBLIC KEY'));
  // Advance wall time without running interval callbacks, simulating suspended timers.
  const browserNow=await page.evaluate(()=>Date.now());
  await page.clock.install({time:new Date(browserNow)});
  await page.clock.setSystemTime(new Date(browserNow+301000));
  await page.evaluate(()=>document.dispatchEvent(new Event('pointerdown',{bubbles:true})));
  await ready();
  check('first activity after suspended timeout clears old session',await page.locator('#key-result').isHidden());
  check('expiry removes secrets from worker',await page.evaluate(async()=>!(await window.__auditCommand({action:'preview',id:0})).ok));
  check('no browser persistence',await page.evaluate(async()=>localStorage.length===0 && sessionStorage.length===0 && document.cookie==='' && (await indexedDB.databases()).length===0));
  await page.evaluate(rows=>window.__auditResults=rows,rows);
  console.log(JSON.stringify(rows));
}
