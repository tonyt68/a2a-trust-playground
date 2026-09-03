/**
 * Produce dist/a2a.html — ONE self-contained file.
 *
 * DESIGN.md's single-file constraint is not tidiness. It exists so that:
 *   - deploying is `cp`, not syncing a folder of assets between two repos, and
 *   - anyone can save the page, pull the network cable, and satisfy themselves
 *     that nothing leaves the browser. That check is what turns "nothing is
 *     transmitted" from a promise into something a stranger can verify.
 *
 * Naming: the SOURCE is page.html and the OUTPUT is dist/a2a.html, deployed as
 * portfolio/a2a/index.html. Three names for three roles, deliberately — an
 * index.html in this repo would be one `cp` away from being confused with the
 * website's own index.html.
 *
 * The bundle is minified because it is a runtime artifact; nobody learns
 * anything from reading 290KB of inlined PKI.js. The readable version is the
 * repository, and the built file says so at the top and in the footer.
 */
import { build } from 'esbuild';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { execSync } from 'node:child_process';

const root = new URL('..', import.meta.url).pathname;
const REPO = 'https://github.com/tonyt68/a2a-trust-playground';

const sha = (() => {
  try { return execSync('git rev-parse --short HEAD', { cwd: root }).toString().trim(); }
  catch { return 'nogit'; }
})();
const dirty = (() => {
  try { return execSync('git status --porcelain', { cwd: root }).toString().trim() ? '-dirty' : ''; }
  catch { return ''; }
})();
const version = `1.0.0+${sha}${dirty}`;
const built = new Date().toISOString();

// ── Bundle ────────────────────────────────────────────────────────────────
const out = await build({
  entryPoints: [root + 'src/app.js'],
  bundle: true, format: 'esm', minify: true, target: 'es2022', write: false,
});
let js = out.outputFiles[0].text.replace(/1\.0\.0\+dev/g, version);

// ── Inline ────────────────────────────────────────────────────────────────
let html = readFileSync(root + 'page.html', 'utf8');

/**
 * Images become data URIs. The deployed page must reference NOTHING outside
 * itself: no /a2a/assets/, no site-relative paths that break when the file is
 * saved and opened from a downloads folder, and no request that would
 * contradict the page's own "nothing leaves your browser" claim.
 */
for (const name of ['favicon-32.png', 'shield-64.png']) {
  const b64 = readFileSync(`${root}assets/${name}`).toString('base64');
  html = html.replaceAll(`./assets/${name}`, `data:image/png;base64,${b64}`);
}
// A function replacer, not a template-string replaceValue: `String.replace`
// treats a STRING replaceValue as a pattern language ($&, $`, $', $1, $$...),
// and minified JS can coincidentally contain those two-character sequences
// (a variable minified to `$` immediately before `&&` produces `$&`, which
// means "re-insert the whole match" — the placeholder tag came back INSIDE
// the bundle and silently corrupted it). A function's return value is used
// verbatim, with no pattern language at all.
html = html.replace('<script type="module" src="./src/app.js"></script>',
  () => `<script type="module">${js}</script>`);

/**
 * CSP by HASH, not nonce. A static file served from GitHub Pages cannot mint a
 * per-response nonce, so the only way to keep `unsafe-inline` out is to hash
 * the inline blocks at build time. Both the script and the style are covered.
 */
const hash = (s) => `'sha256-${createHash('sha256').update(s, 'utf8').digest('base64')}'`;
const styleBody = /<style>([\s\S]*?)<\/style>/.exec(html)[1];
const scriptBody = /<script type="module">([\s\S]*?)<\/script>/.exec(html)[1];

const csp = [
  "default-src 'none'",
  `script-src ${hash(scriptBody)}`,
  `style-src ${hash(styleBody)}`,
  // Only the two inlined data: URIs — no remote image can load.
  "img-src data:",
  // No connect-src at all: the page has nothing to talk to, and saying so is
  // stronger than a policy that permits an origin it never uses.
  "connect-src 'none'",
  "form-action 'none'",
  "base-uri 'none'",
  // frame-ancestors is IGNORED in a <meta> CSP and logs a console error on
  // every load. It belongs in a response header, which a static host sets.
].join('; ');

html = html.replace('<meta name="viewport"',
  `<meta http-equiv="Content-Security-Policy" content="${csp}">\n<meta name="viewport"`);

// ── Stamp ─────────────────────────────────────────────────────────────────
html = html.replace('<!DOCTYPE html>', `<!DOCTYPE html>
<!--
  A2A Trust Playground — ${version}
  built    ${built}
  draft    draft-tonyai-a2a-trust-03
  source   ${REPO}

  This file is minified because it is a runtime artifact. The readable
  implementation — commented, modular, tested — is in the repository
  above. If you are here to learn how to validate one of these chains, read that
  instead; there is nothing to learn from the bundle below.
-->`);

mkdirSync(root + 'dist', { recursive: true });
writeFileSync(root + 'dist/a2a.html', html);

/**
 * Publish the file's own digest so a visitor can verify the bytes they received
 * are the bytes that were built.
 *
 * The CSP already makes the page tamper-EVIDENT from the inside: the inline
 * script is pinned by hash, so altering one byte of it makes the browser refuse
 * to run the page at all (measured: 17 injected bytes → "Refused to execute",
 * app never loads). That defends against local file modification, a MITM proxy,
 * and an extension trying to inject into the page's own context.
 *
 * What it cannot do is prove to a visitor that the file they DOWNLOADED is the
 * one that was published — a sufficiently privileged local attacker could
 * replace the file and its CSP hash together, and the page would run happily.
 * Only an out-of-band check settles that, so the digest is written beside the
 * artifact and printed here:
 *
 *     shasum -a 256 a2a.html
 */
const digest = createHash('sha256').update(html, 'utf8').digest('hex');
writeFileSync(root + 'dist/a2a.html.sha256', `${digest}  a2a.html\n`);

const kb = (n) => `${(n / 1024).toFixed(0)} KB`;
console.log(`  dist/a2a.html   ${kb(Buffer.byteLength(html))}`);
console.log(`  version         ${version}`);
console.log(`  CSP             no unsafe-inline, no unsafe-eval, connect-src 'none'`);
console.log(`  script pinned   ${hash(scriptBody)}`);
console.log(`  sha256          ${digest}`);
