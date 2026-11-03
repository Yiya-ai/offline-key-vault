async (page) => {
  await page.reload();
  await page.getByText('仅本地计算 · 网络已关闭',{exact:true}).waitFor({timeout:90000});
  const results = await page.evaluate(async () => {
    const rows=[]; const password='Synthetic browser phrase 7314';
    const command=async message=>{const r=await window.__command(message);if(!r.ok)throw new Error(message.action+': '+r.error);return r.result;};
    for (const algorithm of ['SM2','Ed25519','RSA-2048','ECDSA-P256','ECDSA-secp256k1','Ed448','X25519','X448','OpenPGP-RSA3072']) {
      try {
        const info=(await command({action:'generate',algorithm,identity:'Synthetic key'})).items[0];
        const exports=[];
        for(const privateKey of [false,true]) for(const format of (privateKey?info.privateFormats:info.publicFormats)) {
          const row={algorithm,format,private:privateKey};
          try {
            const plain=['JWK','Raw-base64','Raw-base64url','PKCS1-DER','SEC1-DER','PKCS1-PEM','SEC1-PEM'].includes(format);
            const output=await command({action:'export',id:0,private:privateKey,format,password:plain?'':password,plaintext:plain});
            exports.push({row,output,password:plain?'':password});
          }catch(e){rows.push({...row,ok:false,error:e.message});}
        }
        for(const item of exports){
          try {
            const rawKind=item.row.format.startsWith('Raw')?`X25519-${item.row.private?'private':'public'}`:'';
            const imported=(await command({action:'inspect',data:item.output.data,password:item.password,rawKind})).items[0];
            if(imported.fingerprint!==info.fingerprint || imported.private!==item.row.private)throw new Error('Identity/type changed');
            rows.push({...item.row,ok:true});
          }catch(e){rows.push({...item.row,ok:false,error:e.message});}
        }
      }catch(e){rows.push({algorithm,ok:false,error:e.message});}
    }
    window.__formats=rows;return {total:rows.length,passed:rows.filter(x=>x.ok).length,failures:rows.filter(x=>!x.ok)};
  });
  console.log(JSON.stringify(results));
  if(results.failures.length) throw new Error('Format matrix failed');
}
