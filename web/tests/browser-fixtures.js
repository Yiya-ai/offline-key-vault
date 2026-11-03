async (page) => {
  // Only the synthetic data created by make_fixtures.py is read.
  const fixtures = await (await page.request.get(new URL('../.vendor/test-fixtures.json', page.url()).href)).json();
  const result = await page.evaluate(async fixtures => {
    const rows=[];
    for(const item of fixtures){
      const result=await window.__command({action:'inspect',data:item.data,password:item.password});
      let ok=result.ok===item.expected;
      if(ok&&result.ok)ok=result.result.items[0].fingerprint===item.fingerprint;
      rows.push({name:item.name,ok});
      if(!ok || !result.ok) continue;
      const record=result.result.items[0];
      for(const format of record.publicFormats.filter(x=>['Certificate-PEM','Certificate-Chain','PKCS7','SSH-Certificate'].includes(x))){
        const output=await window.__command({action:'export',id:0,private:false,format});
        rows.push({name:item.name+' export '+format,ok:output.ok});
      }
      if(item.name==='jks') {
        for(const format of ['JKS','PKCS12']){
          const output=await window.__command({action:'export',id:0,private:true,format,password:item.password});
          const imported=output.ok?await window.__command({action:'inspect',data:output.result.data,password:item.password}):output;
          rows.push({name:'certificate roundtrip '+format,ok:imported.ok&&imported.result.items[0].fingerprint===item.fingerprint&&imported.result.items[0].publicFormats.includes('Certificate-Chain')});
        }
      }
    }
    window.__fixtures=rows;return rows;
  },fixtures);
  console.log(JSON.stringify(result));
  if(result.some(row=>!row.ok)) throw new Error('Native fixture compatibility failed');
}
