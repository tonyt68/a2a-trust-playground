// Dev server. Bare imports (pkijs, asn1js) need resolving, so esbuild bundles
// app.js on the fly and the page is served over 127.0.0.1 — localhost is a
// secure context, which crypto.subtle requires.
import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import { build } from 'esbuild';

const root = new URL('..', import.meta.url).pathname;
const port = Number(process.argv[2] ?? 9100);

const bundle = async () => (await build({
  entryPoints: [root + 'src/app.js'], bundle: true, format: 'esm',
  write: false, target: 'es2022', logLevel: 'silent',
})).outputFiles[0].text;

createServer(async (req, res) => {
  try {
    if (req.url.startsWith('/src/app.js')) {
      res.writeHead(200, { 'Content-Type': 'text/javascript' });
      res.end(await bundle());
    } else {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(readFileSync(root + 'page.html', 'utf8'));
    }
  } catch (e) {
    res.writeHead(500, { 'Content-Type': 'text/plain' });
    res.end(String(e.message ?? e));
  }
}).listen(port, '127.0.0.1', () => console.log(`http://127.0.0.1:${port}/`));
