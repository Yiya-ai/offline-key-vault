const $ = (id) => document.getElementById(id);
const encoder = new TextEncoder();
const titles = {
  generate: ['生成密钥对', '选择算法，在当前浏览器生成。公钥与私钥来自同一密钥对。'],
  convert: ['文本 / 文件转换', '读取已有密钥，转换需要的格式。私钥也可以独立处理，无需密钥库。'],
  certificates: ['证书与容器', '读取证书、证书集合、PFX 或 JKS，选择条目后导出密钥及随附证书。'],
  compare: ['公私钥校对', '比较私钥推导出的公钥参数。解密失败会单独提示，不会被当作不匹配。'],
  help: ['格式与隐私说明', '了解哪些内容会被处理、什么时候被清空，以及浏览器的能力边界。'],
};
const formatNames = {PEM:'PEM（PKCS#8 / SPKI）', DER:'DER（二进制）', PKCS12:'PKCS#12 / PFX',
  'Raw-base64':'原始 Base64', 'Raw-base64url':'原始 Base64url', 'Certificate-PEM':'证书 PEM',
  'Certificate-Chain':'证书集合 PEM', 'SSH-Certificate':'SSH 证书', PKCS7:'P7B 证书集合',
  'OpenPGP-Binary':'OpenPGP 二进制', 'PPK-v2':'PPK v2（旧式兼容）', 'PPK-v3':'PPK v3'};
let assets, worker, workerURL, ready = false, serial = 0, epoch = 0, pending, entries = [], currentView = 'generate';
let showingPrivate = false, lastActivity = Date.now(), lastMonotonic = performance.now();
let activeTask = null, presentationEpoch = 0;
const downloadURLs = new Set();

function message(text = '', error = false) {
  $('message').textContent = text; $('message').hidden = !text;
  $('message').classList.toggle('error', error);
}
function controls() {
  const busy = !!pending || activeTask !== null;
  const blocked = !ready || busy;
  $('tool-fields').disabled = blocked; $('compare-fields').disabled = blocked;
  for (const id of ['entry-select','export-public','export-private','export-original','toggle-private']) $(id).disabled = blocked;
  for (const id of ['output-name','public-format','private-format','export-password','allow-plain']) $(id).disabled = blocked;
  for (const nav of document.querySelectorAll('[data-view]')) nav.disabled = busy;
  for (const eye of document.querySelectorAll('[data-password]')) eye.disabled = blocked;
  document.body.classList.toggle('busy', busy);
}
function touchActivity() { lastActivity = Date.now(); lastMonotonic = performance.now(); }
function expireIfNeeded() {
  const wall = Date.now() - lastActivity, elapsed = performance.now() - lastMonotonic;
  if (ready && (wall >= 300000 || elapsed >= 300000 || wall < 0)) {
    clearAll('会话已超时，本次输入和密钥已自动清空。'); return true;
  }
  return false;
}
function redactVisibleSecrets() {
  presentationEpoch++;
  for (const eye of document.querySelectorAll('[data-password]')) {
    $(eye.dataset.password).type = 'password'; eye.setAttribute('aria-pressed', 'false');
    eye.setAttribute('aria-label', eye.getAttribute('aria-label').replace(/^隐藏/, '显示'));
  }
  if (showingPrivate) {
    showingPrivate = false; $('preview').value = ''; $('preview').classList.remove('private');
    $('preview-title').textContent = '公钥内容';
    $('toggle-private').querySelector('span').textContent = '显示私钥';
    $('preview-note').textContent = '已自动隐藏私钥；如需查看，请再次主动显示。';
  }
}
function resetResult() {
  entries = []; showingPrivate = false;
  $('key-result').hidden = true; $('empty-result').hidden = false; $('result-kind').hidden = true;
  $('preview').value = ''; $('fingerprint').textContent = '';
  $('entry-select').replaceChildren(); $('public-format').replaceChildren(); $('private-format').replaceChildren();
}
function clearAll(text = '已清空本次输入、密钥和结果。', restart = true) {
  epoch++; ready = false; activeTask = null; redactVisibleSecrets();
  if (pending) { const reject = pending.reject; clearTimeout(pending.timer); pending = null; reject(new Error('操作已取消，内容已清空。')); }
  worker?.terminate(); worker = undefined;
  if (workerURL) URL.revokeObjectURL(workerURL); workerURL = undefined;
  for (const url of downloadURLs) URL.revokeObjectURL(url); downloadURLs.clear();
  for (const field of document.querySelectorAll('textarea, input')) {
    if (field.type === 'checkbox') field.checked = false;
    else field.value = '';
  }
  $('key-name').value = 'my-key'; $('output-name').value = 'my-key';
  for (const eye of document.querySelectorAll('[data-password]')) {
    $(eye.dataset.password).type = 'password'; eye.setAttribute('aria-pressed', 'false');
    eye.setAttribute('aria-label', eye.getAttribute('aria-label').replace(/^隐藏/, '显示'));
  }
  $('input-file-name').textContent = '未选择文件'; $('compare-public-name').textContent = ''; $('compare-private-name').textContent = '';
  $('compare-result').textContent = ''; $('compare-result').hidden = true;
  resetResult(); controls(); message(text); touchActivity();
  $('engine-status').textContent = '正在重置计算环境'; $('engine-status').classList.remove('ready');
  if (restart && assets) startWorker();
}
function startWorker() {
  const mine = epoch;
  $('loading').hidden = false; $('loading-text').textContent = '资源已在本页内存中，正在初始化隔离计算环境…';
  workerURL = URL.createObjectURL(new Blob([assets.get('worker.js')], {type:'text/javascript'}));
  worker = new Worker(workerURL);
  const timer = setTimeout(() => {
    if (mine !== epoch || ready) return;
    worker?.terminate(); message('引擎启动超时，请刷新页面，或使用桌面版。', true);
    $('loading').hidden = true; $('engine-status').textContent = '引擎未就绪';
  }, 90000);
  worker.onmessage = ({data}) => {
    if (mine !== epoch) return;
    if (data.type === 'ready') {
      clearTimeout(timer); ready = true; $('loading').hidden = true;
      $('engine-status').textContent = '仅本地计算 · 网络已关闭'; $('engine-status').classList.add('ready'); controls();
    } else if (data.type === 'fatal') {
      clearTimeout(timer); ready = false; worker?.terminate(); $('loading').hidden = true;
      $('engine-status').textContent = '引擎未就绪'; message(data.error, true); controls();
    } else if (data.type === 'result' && pending?.id === data.id) {
      const saved = pending; clearTimeout(saved.timer); pending = null; controls();
      data.ok ? saved.resolve(data.result) : saved.reject(new Error(data.error));
    }
  };
  worker.onerror = () => { if (mine === epoch) { clearTimeout(timer); clearAll('计算环境异常，已清空。请刷新页面后重试。', false); } };
  const copies = [...assets].filter(([name]) => name !== 'worker.js').map(([name, data]) => [name, data.slice(0)]);
  worker.postMessage({type:'init', assets:copies}, copies.map(([, data]) => data));
}
function run(command) {
  if (!ready || pending) return Promise.reject(new Error('请等待当前操作完成。'));
  const mine = epoch;
  return new Promise((resolve, reject) => {
    const id = ++serial;
    const timer = setTimeout(() => clearAll('操作超过两分钟，已终止并清空，避免异常文件持续占用资源。'), 120000);
    pending = {id, resolve, reject, timer}; controls(); worker.postMessage({type:'command', id, message:command});
  }).then(result => { if (mine !== epoch) throw new Error('操作已取消。'); return result; });
}
async function task(operation) {
  if (expireIfNeeded() || !ready || activeTask !== null) return;
  const token = {}; activeTask = token; touchActivity(); controls();
  const mine = epoch; message();
  try { await operation(); } catch (error) { if (mine === epoch) message(error.message || '操作未完成。', true); }
  finally { if (activeTask === token) { activeTask = null; controls(); } }
}
function b64(bytes) {
  let raw = ''; for (let i = 0; i < bytes.length; i += 8192) raw += String.fromCharCode(...bytes.subarray(i, i + 8192));
  return btoa(raw);
}
async function input(textId, fileId) {
  const mine = epoch;
  const text = $(textId).value;
  if (text.trim()) {
    const bytes = encoder.encode(text);
    try { if (bytes.length > 131072) throw new Error('输入超过 128 KiB 限制。'); return b64(bytes); } finally { bytes.fill(0); }
  }
  const file = $(fileId).files[0];
  if (!file || !file.size) throw new Error('请粘贴完整内容或选择本地文件。');
  if (file.size > 131072) throw new Error('文件超过 128 KiB 限制。');
  const bytes = new Uint8Array(await file.arrayBuffer());
  try { if (mine !== epoch) throw new Error('操作已取消。'); return b64(bytes); } finally { bytes.fill(0); }
}
function options(id, values) {
  $(id).replaceChildren(...values.map(value => { const option = document.createElement('option'); option.value = value; option.textContent = formatNames[value] || value; return option; }));
}
function selected() { return entries[Number($('entry-select').value)]; }
async function preview(privateKey = false) {
  const item = selected(); if (!item) return;
  const presentation = presentationEpoch;
  const result = await run({action:'preview', id:item.id, private:privateKey, confirmed:privateKey});
  if (privateKey && (document.hidden || presentation !== presentationEpoch)) return;
  showingPrivate = privateKey; $('preview').value = result.text;
  $('preview').classList.toggle('private', privateKey); $('preview-title').textContent = privateKey ? '私钥内容（未加密）' : '公钥内容';
  $('toggle-private').querySelector('span').textContent = privateKey ? '隐藏私钥' : '显示私钥';
  $('preview-note').textContent = privateKey ? '当前展示的是未加密私钥，请留意旁观者。导出时可另设口令保护。' : '指纹用于识别密钥，不代表证书可信。';
}
async function selectEntry() {
  const item = selected(); if (!item) return;
  $('preview').value = ''; $('fingerprint').textContent = item.fingerprint;
  $('result-kind').textContent = `${item.algorithm} / ${item.private ? '含私钥' : '仅公钥'}`; $('result-kind').hidden = false;
  options('public-format', item.publicFormats); options('private-format', item.privateFormats);
  $('toggle-private').hidden = !item.private; $('private-export').hidden = !item.private && !item.publicFormats.includes('JKS');
  $('private-export').querySelector('.export-row').hidden = !item.private;
  $('allow-plain').parentElement.hidden = !item.private; $('allow-plain').checked = false;
  $('export-original').hidden = !item.original;
  if (item.alias) $('output-name').value = item.alias;
  await preview(false);
}
async function showResult(result) {
  entries = result.items;
  $('entry-select').replaceChildren(...entries.map(item => { const option = document.createElement('option'); option.value = item.id; option.textContent = `${item.alias || '当前密钥'} — ${item.algorithm}${entries.length > 1 ? ` (${item.id + 1}/${entries.length})` : ''}`; return option; }));
  $('empty-result').hidden = true; $('key-result').hidden = false;
  await selectEntry();
}
function safeName(value) {
  const name = value.normalize('NFC').replace(/[<>:"/\\|?*\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069]/g, '-').slice(0, 80).replace(/[. ]+$/g, '') || 'key';
  return /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(name) ? 'key-' + name : name;
}
async function download(privateKey, original = false) {
  const item = selected(); if (!item) throw new Error('请先生成或读取密钥。');
  const format = original ? 'Original' : $(privateKey ? 'private-format' : 'public-format').value;
  const filename = safeName($('output-name').value);
  const result = await run({action:'export', id:item.id, private:privateKey, format,
    password:$('export-password').value, plaintext:$('allow-plain').checked});
  const bytes = Uint8Array.from(atob(result.data), c => c.charCodeAt(0));
  const url = URL.createObjectURL(new Blob([bytes], {type:'application/octet-stream'})); bytes.fill(0); downloadURLs.add(url);
  const link = document.createElement('a'); link.href = url; link.download = filename + result.extension; link.rel = 'noreferrer';
  document.body.append(link); link.click(); link.remove();
  setTimeout(() => { URL.revokeObjectURL(url); downloadURLs.delete(url); }, 30000);
  $('export-password').value = '';
  message(`已交给浏览器下载（${result.bytes} 字节）。下载位置由浏览器设置决定。`);
}

for (const button of document.querySelectorAll('[data-view]')) button.addEventListener('click', () => {
  redactVisibleSecrets();
  currentView = button.dataset.view;
  for (const nav of document.querySelectorAll('[data-view]')) { const active = nav === button; nav.classList.toggle('active', active); active ? nav.setAttribute('aria-current','page') : nav.removeAttribute('aria-current'); }
  $('page-title').textContent = titles[currentView][0]; $('page-description').textContent = titles[currentView][1];
  $('workspace').hidden = ['compare','help'].includes(currentView); $('compare-panel').hidden = currentView !== 'compare'; $('help-panel').hidden = currentView !== 'help';
  $('generate-panel').hidden = currentView !== 'generate'; $('convert-panel').hidden = !['convert','certificates'].includes(currentView);
  $('input-title').textContent = currentView === 'certificates' ? '读取证书 / 容器' : '读取密钥'; message();
});
for (const button of document.querySelectorAll('[data-password]')) button.addEventListener('click', () => {
  const field = $(button.dataset.password), visible = field.type === 'password'; field.type = visible ? 'text' : 'password';
  button.setAttribute('aria-pressed', String(visible)); button.setAttribute('aria-label', button.getAttribute('aria-label').replace(/^(显示|隐藏)/, visible ? '隐藏' : '显示'));
});
for (const [fileId, captionId] of [['input-file','input-file-name'],['compare-public-file','compare-public-name'],['compare-private-file','compare-private-name']]) {
  $(fileId).addEventListener('change', () => { const file = $(fileId).files[0]; $(captionId).textContent = file?.name || '未选择文件'; if (file?.size > 131072) { $(fileId).value = ''; $(captionId).textContent = '文件过大，未读取'; message('文件最多 128 KiB。', true); } });
}
$('generate').addEventListener('click', () => task(async () => {
  resetResult(); $('output-name').value = $('key-name').value || 'my-key';
  message('正在生成，请稍候。较大 RSA 和 OpenPGP 密钥需要更多时间。');
  await showResult(await run({action:'generate', algorithm:$('algorithm').value, identity:$('key-name').value})); message('已生成匹配的公私钥。请下载需要的文件。');
}));
$('inspect').addEventListener('click', () => task(async () => {
  const filename = $('input-text').value.trim() ? '' : $('input-file').files[0]?.name;
  const password = $('input-password').value, entryPassword = $('input-entry-password').value, rawKind = $('raw-kind').value;
  resetResult();
  try {
    await run({action:'discard'});
    const data = await input('input-text', 'input-file');
    if (filename) $('output-name').value = filename.replace(/\.[^.]+$/, '');
    await showResult(await run({action:'inspect', data, password, entryPassword, rawKind}));
  }
  finally { $('input-password').value = ''; $('input-entry-password').value = ''; }
  message('已读取并校验。只显示当前输入，不创建历史记录。');
}));
$('entry-select').addEventListener('change', () => task(selectEntry));
$('toggle-private').addEventListener('click', () => task(() => preview(!showingPrivate)));
$('export-public').addEventListener('click', () => task(() => download(false)));
$('export-private').addEventListener('click', () => task(() => download(true)));
$('export-original').addEventListener('click', () => task(() => download(!!selected()?.private, true)));
$('export-password').addEventListener('input', () => { if ($('export-password').value) $('allow-plain').checked = false; });
$('allow-plain').addEventListener('change', () => { if ($('allow-plain').checked) $('export-password').value = ''; });
$('compare').addEventListener('click', () => task(async () => {
  $('compare-result').hidden = true; $('compare-result').textContent = '';
  const publicPassword = $('public-password').value, privatePassword = $('private-password').value;
  const entryPassword = $('compare-entry-password').value, raw = $('compare-raw').checked;
  let result;
  try {
    const publicData = await input('compare-public','compare-public-file'), privateData = await input('compare-private','compare-private-file');
    result = await run({action:'compare', publicData, privateData, publicPassword, privatePassword, entryPassword, raw});
  }
  finally { for (const id of ['public-password','private-password','compare-entry-password']) $(id).value = ''; }
  $('compare-result').textContent = `${result.matched ? '匹配：两者属于同一密钥对。' : '不匹配：公钥参数不同。'}\n校验范围：${result.scope}\n公钥指纹：${result.public_fingerprint}\n私钥推导指纹：${result.derived_fingerprint}`;
  $('compare-result').classList.toggle('mismatch', !result.matched); $('compare-result').hidden = false;
}));
$('algorithm').addEventListener('change', () => {
  const name = $('algorithm').value;
  $('algorithm-hint').textContent = name.startsWith('X') ? '用于密钥交换，不用于数字签名或普通 SSH 登录。' : name.startsWith('OpenPGP') ? '生成主密钥和加密子密钥，保留身份；仅导出 OpenPGP 格式。' : name === 'SM2' ? 'SM2 密钥支持 PKCS#8 / SPKI；目标系统也需要支持 SM2。' : name.startsWith('RSA') ? '通用兼容算法。更大的密钥会增加生成和计算时间。' : '适合数字签名；请按目标系统选择兼容算法。';
});
$('clear-all').addEventListener('click', () => clearAll());
for (const event of ['pointerdown','keydown','input']) document.addEventListener(event, () => { if (!expireIfNeeded()) touchActivity(); }, {passive:true,capture:true});
setInterval(expireIfNeeded, 5000);
document.addEventListener('visibilitychange', () => { if (document.hidden) redactVisibleSecrets(); else expireIfNeeded(); });
window.addEventListener('blur', redactVisibleSecrets);
window.addEventListener('focus', expireIfNeeded);
window.addEventListener('pagehide', () => clearAll('', false));
window.addEventListener('pageshow', event => { if (event.persisted) clearAll('页面已恢复，本次敏感内容已清空。'); });

async function bootstrap() {
  if (window.top !== window.self) throw new Error('请直接打开本站，不能在其他网站的框架中使用密钥工具。');
  if (!isSecureContext || !crypto.subtle || !crypto.getRandomValues || !window.Worker) throw new Error('请通过 HTTPS 或本机地址，在支持 WebAssembly 的现代浏览器中打开。');
  // An existing controller can substitute resources before our integrity checks.
  // Refuse accidental shared-origin deployments; never unregister another app's worker.
  if (navigator.serviceWorker?.controller) throw new Error('请使用不受 Service Worker 控制的独立站点。');
  navigator.serviceWorker?.addEventListener('controllerchange', () => {
    assets = undefined; clearAll('站点控制环境发生变化，已停止并清空。请使用独立站点。', false);
  });
  // Disable browser form restoration; no user content is read until boot ends.
  for (const field of document.querySelectorAll('textarea,input[type=password],input[type=file]')) field.value = '';
  const response = await fetch(new URL('assets.json', import.meta.url), {credentials:'omit',cache:'no-store',referrerPolicy:'no-referrer'});
  if (!response.ok) throw new Error('程序资源清单加载失败。');
  const manifest = await response.json(), files = Object.entries(manifest.files || {});
  if (!files.length || files.length > 40) throw new Error('程序资源清单无效。');
  let total = 0, done = 0;
  assets = new Map();
  for (const [name, item] of files) {
    if (!/^[a-zA-Z0-9_.-]+$/.test(name) || !/^[0-9a-f]{64}$/.test(item.sha256) || !Number.isSafeInteger(item.bytes) || item.bytes < 1 || item.bytes > 32*1024*1024) throw new Error('程序资源清单无效。');
    total += item.bytes;
  }
  if (total > 80*1024*1024) throw new Error('程序资源超出限制。');
  await Promise.all(files.map(async ([name, item]) => {
    const response = await fetch(new URL(`assets/${name}`, import.meta.url), {credentials:'omit',referrerPolicy:'no-referrer'});
    if (!response.ok) throw new Error('程序资源加载失败，请刷新重试。');
    const bytes = await response.arrayBuffer();
    const sha = [...new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))].map(n => n.toString(16).padStart(2,'0')).join('');
    if (bytes.byteLength !== item.bytes || sha !== item.sha256) throw new Error('程序资源校验失败，未开放密钥输入。');
    assets.set(name, bytes); done += item.bytes; $('load-progress').value = Math.round(done / total * 100);
  }));
  // Intersect with the initial CSP. All code/data is already in memory. Future
  // workers inherit a policy allowing only Blob scripts and in-memory WASM.
  const seal = document.createElement('meta'); seal.httpEquiv = 'Content-Security-Policy';
  seal.content = "default-src 'none'; connect-src 'none'; script-src blob: 'wasm-unsafe-eval'; worker-src blob:; style-src 'none'; img-src data: blob:; base-uri 'none'; form-action 'none'; object-src 'none'; frame-src 'none'";
  document.head.append(seal);
  startWorker();
}
bootstrap().catch(() => { ready = false; assets = undefined; $('loading').hidden = true; $('engine-status').textContent = '加载失败'; message('浏览器引擎加载或资源校验失败。请刷新重试，确保使用 HTTPS 或本机地址，并直接打开网页。密钥输入尚未开放。', true); controls(); });
