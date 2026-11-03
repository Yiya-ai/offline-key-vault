import { loadPyodide } from 'pyodide';
import createPyodideModule from 'pyodide/pyodide.asm.mjs';
import { sm2Public, sm2Validate, pkcs12Kdf } from './crypto-bridge.js';

let engine, invoke, started = false;
const deny = () => { throw new Error('Network access is disabled'); };
for (const name of ['XMLHttpRequest', 'WebSocket', 'EventSource', 'WebTransport', 'Worker', 'SharedWorker', 'importScripts']) {
  Object.defineProperty(globalThis, name, { value: deny, configurable: false, writable: false });
}

self.onmessage = async ({ data }) => {
  if (data.type === 'init' && !started) {
    started = true;
    try {
      const memory = new Map(data.assets);
      // No fallback to a real fetch, even during initialization. The Blob worker
      // also inherits connect-src 'none' before it is created.
      Object.defineProperty(globalThis, 'fetch', { value: async (input) => {
        const url = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url);
        if (url.origin !== 'https://runtime.invalid' || url.search || url.hash) return deny();
        const name = url.pathname.slice(1);
        if (!memory.has(name)) return deny();
        return new Response(memory.get(name), { headers: { 'Content-Type': name.endsWith('.wasm') ? 'application/wasm' : 'application/octet-stream' } });
      }, configurable: false, writable: false });
      const lock = JSON.parse(new TextDecoder().decode(memory.get('pyodide-lock.json')));
      engine = await loadPyodide({ indexURL: 'https://runtime.invalid/', packageBaseUrl: 'https://runtime.invalid/',
        lockFileContents: lock, createPyodideModule, stdout: () => {}, stderr: () => {},
        jsglobals: Object.freeze({}), enableRunUntilComplete: false });
      await engine.loadPackage(Object.keys(lock.packages), { messageCallback: () => {}, errorCallback: () => {} });
      engine.unpackArchive(new Uint8Array(memory.get('python-code.zip')), 'zip', { extractDir: '/app' });
      engine.registerJsModule('browser_crypto', { sm2Public, sm2Validate, pkcs12Kdf });
      engine.runPython("import sys\nsys.path.insert(0, '/app')");
      engine.runPython(new TextDecoder().decode(memory.get('kernel.py')));
      invoke = engine.globals.get('handle');
      // Verify the loaded binary, not just the wheel's filename or metadata.
      const runtime = JSON.parse(invoke(JSON.stringify({action:'runtime'})));
      const expected = lock.packages.cryptography;
      if (!runtime.ok || runtime.result.cryptography !== expected.version ||
          runtime.result.openssl.split(' ')[1] !== expected.tool.openssl_version ||
          expected.version !== '50.0.2' || expected.tool.openssl_version !== '3.6.5') {
        throw new Error('Unexpected cryptographic runtime');
      }
      // Only code/runtime assets have ever entered MEMFS. Do not mount IDBFS,
      // OPFS, a browser FileSystemHandle or any host directory.
      memory.clear();
      self.postMessage({ type: 'ready' });
    } catch { self.postMessage({ type: 'fatal', error: '浏览器计算引擎初始化失败，请使用新版 Chrome、Edge、Firefox 或 Safari 重试。' }); }
    return;
  }
  if (data.type !== 'command' || !invoke || !Number.isSafeInteger(data.id)) return;
  try {
    const serialized = JSON.stringify(data.message);
    if (serialized.length > 400000) throw new Error('Input too large');
    const result = JSON.parse(invoke(serialized));
    self.postMessage({ type: 'result', id: data.id, ...result });
  } catch { self.postMessage({ type: 'result', id: data.id, ok: false, error: '操作未完成，请清空后重试。' }); }
};
