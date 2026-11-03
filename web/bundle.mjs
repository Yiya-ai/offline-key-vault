import { build } from 'esbuild';
await build({entryPoints: ['src/worker.js'], bundle: true, format: 'iife', platform: 'browser',
  target: ['chrome120', 'firefox120', 'safari17'], outfile: 'dist/assets/worker.js',
  external: ['node:*'], sourcemap: false, minify: true, legalComments: 'eof'});
