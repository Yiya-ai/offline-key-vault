async (page) => {
  await page.addInitScript(() => {
    const Original = window.Worker;
    window.Worker = class extends Original {
      constructor(...args) { super(...args); window.__worker = this; }
    };
    let seq = 900000;
    window.__command = (message) => new Promise((resolve, reject) => {
      const worker = window.__worker, id = ++seq;
      const timer = setTimeout(() => { worker.removeEventListener('message', receive); reject(new Error('Test operation timed out')); }, 110000);
      function receive({data}) { if(data.type === 'result' && data.id === id) { clearTimeout(timer);worker.removeEventListener('message',receive);resolve(data); } }
      worker.addEventListener('message',receive);worker.postMessage({type:'command',id,message});
    });
  });
  await page.reload();
  await page.getByText('仅本地计算 · 网络已关闭',{exact:true}).waitFor({timeout:90000});
  const results = await page.evaluate(async () => {
    const rows=[]; const password='Synthetic browser phrase 7314';
    for (const algorithm of ['Ed25519','RSA-2048','RSA-3072','RSA-4096','ECDSA-P256','ECDSA-P384','ECDSA-P521','ECDSA-secp256k1','Ed448','X25519','X448','SM2','OpenPGP-RSA3072']) {
      const command=async message=>{const r=await window.__command(message);if(!r.ok)throw new Error(message.action+': '+r.error);return r.result;};
      try {
        const info=await command({action:'generate',algorithm,identity:'Synthetic browser key'});
        const format=algorithm.startsWith('OpenPGP')?'OpenPGP':'PEM';
        const pub=await command({action:'export',id:0,private:false,format});
        const priv=await command({action:'export',id:0,private:true,format,password});
        const imported=await command({action:'inspect',data:priv.data,password});
        if(imported.items[0].fingerprint!==info.items[0].fingerprint)throw new Error('Fingerprint changed');
        const match=await command({action:'compare',publicData:pub.data,privateData:priv.data,privatePassword:password});
        if(!match.matched)throw new Error('Pair mismatch');
        rows.push({algorithm,ok:true});
      }catch(error){rows.push({algorithm,ok:false,error:error.message});}
    }
    window.__matrix=rows;return rows;
  });
  console.log(JSON.stringify(results));
  if(results.some(row=>!row.ok)) throw new Error('Algorithm matrix failed');
}
