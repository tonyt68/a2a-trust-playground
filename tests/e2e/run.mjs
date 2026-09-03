/**
 * End-to-end regression suite — drives the BUILT single file in a real browser.
 *
 * Everything here was, at some point, a bug found by clicking around by hand.
 * Unit tests were green through all of it, because none of those are questions
 * a unit test asks.
 *
 * Runs against dist/a2a.html over file:// with the network DISCONNECTED, which
 * is the strictest environment the page ever sees and the one that proves the
 * "nothing leaves your browser" claim rather than asserting it.
 *
 *   pnpm test:e2e
 */
import { chromium } from 'playwright';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const CHROME = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
const BUILT = fileURLToPath(new URL('../../dist/a2a.html', import.meta.url));

if (!existsSync(BUILT)) { console.error('dist/a2a.html is missing — run `pnpm build` first.'); process.exit(1); }
if (!existsSync(CHROME)) { console.log('SKIP: Google Chrome not found at the expected path.'); process.exit(0); }

let lastStep = 'startup';
let passed = 0;
const failures = [];
const ok = (name, cond, detail = '') => {
  if (cond) { passed += 1; console.log(`  ok    ${name}`); }
  else { failures.push(`${name}${detail ? ` — ${detail}` : ''}`); console.log(`  FAIL  ${name}${detail ? ` — ${detail}` : ''}`); }
};
const section = (t) => { lastStep = t; console.log(`\n${t}`); };

const browser = await chromium.launch({ executablePath: CHROME });
const context = await browser.newContext({ viewport: { width: 1500, height: 1000 } });
await context.setOffline(true);
const page = await context.newPage();

const consoleErrors = [];
const requests = [];
page.on('console', (m) => { if (m.type() === 'error') consoleErrors.push(`[after: ${lastStep}] ${m.text()}`); });
page.on('pageerror', (e) => consoleErrors.push(`[after: ${lastStep}] PAGEERROR: ${e.message}`));
page.on('request', (r) => requests.push(r.url()));

const btn = (label) => page.evaluate((l) => {
  const b = [...document.querySelectorAll('.admin-btn')].find((x) => x.firstChild.textContent === l);
  if (!b) throw new Error(`no button: ${l}`);
  b.click();
}, label);
const settle = () => page.waitForFunction(
  () => ![...document.querySelectorAll('.admin-btn')].some((b) => b.disabled), { timeout: 40000 });
const click = async (label) => { await btn(label); await settle(); };
const verdict = () => page.evaluate(() => document.querySelector('.banner-main')?.textContent);
const code = () => page.evaluate(() => (document.querySelector('.banner-code')?.textContent || '').split(' · ')[0]);
const flow = () => page.evaluate(() => [...document.querySelectorAll('#pipeline .p-box')]
  .map((b) => `${b.querySelector('.p-name').textContent}=${b.querySelector('.p-sub').textContent}`));
const doc = () => page.evaluate(() => JSON.parse(document.getElementById('doc').value));

// ── Load ──────────────────────────────────────────────────────────────────
await page.goto(`file://${BUILT}`);
await page.waitForFunction(
  () => document.querySelector('.banner-main')?.textContent === 'NOT VALIDATED'
    && ![...document.querySelectorAll('.admin-btn')].some((b) => b.disabled),
  { timeout: 40000 });

section('load');
ok('seeds a chain without validating it', await verdict() === 'NOT VALIDATED', await verdict());
ok('flow starts with nothing claimed, seven steps', (await flow()).length === 7 && (await flow()).every((f) => f.endsWith('=—')));
ok('editor holds a parseable -03 document', await page.evaluate(() => {
  try { const d = JSON.parse(document.getElementById('doc').value);
    return Array.isArray(d.chain) && d.chain.length === 3 && d.policy?.body && !('policy_doc' in d); }
  catch { return false; }
}));
ok('the header names -03', await page.evaluate(() => document.getElementById('draft-link').textContent) === 'DRAFT-TONYAI-A2A-TRUST-03');
ok('the audit log carries the seeded entries before any validation',
  await page.evaluate(() => document.querySelectorAll('.audit-row:not(.head)').length) >= 3);

// ── Validate ──────────────────────────────────────────────────────────────
section('validate');
const auditBefore = (await doc()).audit.chain.length;
await click('Validate');
ok('a fresh chain validates', await verdict() === 'ALL STAGES PASSED', await code());
ok('all seven walk steps are VALID', (await flow()).every((f) => f.endsWith('=VALID')), (await flow()).join(' '));
ok('nine stages logged, none skipped',
  await page.evaluate(() => [...document.querySelectorAll('#log .log-row')].filter((r) => r.children[2].textContent === 'PASS').length) === 9);
ok('a validation run appends exactly one audit entry', (await doc()).audit.chain.length === auditBefore + 1);
ok('every clause link points into -03', await page.evaluate(() =>
  [...document.querySelectorAll('a.sec')].every((a) => a.href.includes('draft-tonyai-a2a-trust-03.html#section-'))));

// ── Modifications the draft ALLOWS ────────────────────────────────────────
section('modifications the draft allows — must stay valid');
const allowed = await page.evaluate(() => [...document.querySelectorAll('.phase-grid .admin-btn.ok')].map((b) => b.firstChild.textContent));
ok('there are green buttons', allowed.length >= 5, allowed.join(', '));
for (const label of allowed) {
  await click('Reset Certs'); await click('Validate'); await click(label); await click('Validate');
  ok(`allowed: ${label}`, await verdict() === 'ALL STAGES PASSED', await code());
}
ok('the cross-org grant step reports the grant once one is present', (await flow()).some((f) => f.startsWith('CROSS-ORG GRANT=VALID')));

// ── Advisory ──────────────────────────────────────────────────────────────
section('advisory — a SHOULD is reported, not refused');
await click('Reset Certs'); await click('Child outlives its parent'); await click('Validate');
ok('the chain stays valid', await verdict() === 'ALL STAGES PASSED', await code());
ok('DELEGATION reads ADVISORY', (await flow()).some((f) => f === 'DELEGATION=ADVISORY'), (await flow()).join(' '));
ok('the banner says so and cites §10.3', await page.evaluate(() => /ADVISORY.*10\.3/.test(document.querySelector('.banner-sub')?.textContent ?? '')));

// ── Modifications the draft REFUSES ───────────────────────────────────────
section('modifications the draft refuses — must name the clause');
const EXPECTED = {
  'Forge the issuer': 'ERR_FORGED_ISSUER',
  'Corrupt the certificate': 'ERR_CHAIN_INVALID',
  'Forge the parent link': 'ERR_PARENT_MISMATCH',
  'Expire the certificate': 'ERR_CERT_EXPIRED',
  'Agent cert claims keyCertSign': 'ERR_KEY_USAGE',
  'Outlive the template TTL': 'ERR_VALIDITY_EXCEEDS_TTL',
  'Drop the revocation pointer': 'ERR_NO_REVOCATION_SOURCE',
  'One identity, two certificates': 'ERR_DUPLICATE_SUBJECT',
  'Duplicate nonce in the chain': 'ERR_NONCE_REUSED',
  'Revoke the parent': 'ERR_AGENT_REVOKED',
  'Disable the template at the Registry': 'ERR_AGENT_DISABLED',
  'Cross-org spawn with no grant': 'ERR_GRANT_MISSING',
  'Expired grant': 'ERR_GRANT_EXPIRED',
  'Grant exceeds the template': 'ERR_GRANT_EXCEEDS_TEMPLATE',
  'Remove one grant signature': 'ERR_GRANT_INVALID',
  'Drop the grant’s issued_at': 'ERR_GRANT_INVALID',
  'Grant allows no spawns': 'ERR_MAX_SPAWNS',
  'Escalate the scope': 'ERR_SCOPE_ESCALATION',
  'Exceed max_children': 'ERR_MAX_CHILDREN',
  'Spawn a non-whitelisted child': 'ERR_CHILD_NOT_WHITELISTED',
  'Parent may not spawn at all': 'ERR_SPAWN_NOT_PERMITTED',
  'Widen policy past the ceiling': 'ERR_POLICY_EXCEEDS_TEMPLATE',
  'Sign with one key only': 'ERR_PA_SIG_MISSING',
  'One key, both roles': 'ERR_SINGLE_SIGNATURE',
  'Tamper with the policy body': 'ERR_OWNER_SIG_INVALID',
  'Replay an old policy, bump version': 'ERR_OWNER_SIG_INVALID',
  'Alter the stored hash only': 'ERR_CONTENT_HASH',
  'Edit can_spawn via policy': 'ERR_IMMUTABLE_FIELD',
  'Submit as the wrong owner': 'ERR_OWNER_MISMATCH',
  'Owner certificate does not match the template': 'ERR_OWNER_CERT_MISMATCH',
  'Alter an audit entry': 'ERR_AUDIT_CHAIN_BROKEN',
};
for (const [label, expected] of Object.entries(EXPECTED)) {
  await click('Reset Certs'); await click('Validate'); await click(label); await click('Validate');
  const got = await code();
  ok(`refused: ${label}`, (await verdict()) === 'DENIED' && got === expected, `expected ${expected}, got ${got}`);
  const marked = await page.evaluate(() => !!document.querySelector('#gutter .g-line.bad'));
  ok(`  ${label} → marks the offending line`, marked);
  const denies = await page.evaluate(() => document.querySelectorAll('#log .log-row.deny').length);
  ok(`  ${label} → exactly one DENY row`, denies === 1, `${denies} rows`);
  const failedSteps = await page.evaluate(() => document.querySelectorAll('#pipeline .p-box.err').length);
  ok(`  ${label} → the walk stops at one step`, failedSteps === 1, `${failedSteps} failed`);
}
const redButtons = await page.evaluate(() => [...document.querySelectorAll('.phase-grid .admin-btn.danger')]
  .filter((b) => !/refused at issuance/.test(b.querySelector('.sec-tag')?.textContent ?? '')).map((b) => b.firstChild.textContent));
ok('every red document button is covered above', redButtons.every((l) => l in EXPECTED), redButtons.filter((l) => !(l in EXPECTED)).join(', '));

// ── Refused at issuance ───────────────────────────────────────────────────
section('the Registry refuses to issue — the document is untouched');
const ISSUANCE = {
  'Drop a REQUIRED template field': 'ERR_TEMPLATE_NONCONFORMING',
  'Remove one attestation signature': 'ERR_TEMPLATE_SIGNATURE',
  'Edit a template after it was signed': 'ERR_TEMPLATE_SIGNATURE',
  'Replay the spawn request': 'ERR_NONCE_REUSED',
  'Stale spawn timestamp (61 s)': 'ERR_SPAWN_STALE',
  'Future spawn timestamp (61 s)': 'ERR_SPAWN_STALE',
};
for (const [label, expected] of Object.entries(ISSUANCE)) {
  await click('Reset Certs');
  const before = JSON.stringify(await doc());
  await click(label);
  const got = await code();
  ok(`not issued: ${label}`, (await verdict()) === 'NOT ISSUED' && got === expected, `expected ${expected}, got ${got}`);
  ok(`  ${label} → the document did not change`, JSON.stringify(await doc()) === before);
  ok(`  ${label} → the log shows row 0 and nine not-reached stages`,
    await page.evaluate(() => document.querySelectorAll('#log .log-row.deny').length === 1
      && [...document.querySelectorAll('#log .log-row .detail')].filter((d) => /no certificate was issued/.test(d.textContent)).length === 9));
}
ok('the stale refusal names the measured offset', await page.evaluate(() => /61\.0 s in the (past|future)/i.test(document.querySelector('.banner-sub')?.textContent ?? '')));

// ── Freeform edits in the editor ──────────────────────────────────────────
section('freeform edits — typing into the document');
const editDocument = (fn) => page.evaluate((src) => {
  const box = document.getElementById('doc');
  const d = JSON.parse(box.value);
  (new Function('d', src))(d);
  box.value = JSON.stringify(d, null, 2);
  box.dispatchEvent(new Event('input', { bubbles: true }));
}, fn);

await click('Reset Certs'); await click('Validate');
await editDocument('d.current_policy_version = 0;');
await click('Validate');
ok('green edit: lowering the version in force stays VALID', await verdict() === 'ALL STAGES PASSED', await code());

await click('Reset Certs'); await click('Validate');
await editDocument("const c = d.chain.find((n) => n.metadata?.parent_agent_id); c.requested_scopes = ['admin:all'];");
await click('Validate');
const redCode = await code();
ok('red edit: a hand-widened request is REFUSED', await verdict() === 'DENIED' && redCode === 'ERR_SCOPE_ESCALATION', `got ${redCode}`);
ok('red edit: the refusal cites §10.3', await page.evaluate(() => (document.querySelector('.banner-code')?.textContent || '').includes('§10.3')));
ok('red edit: the walk names DELEGATION', (await flow()).some((f) => f === 'DELEGATION=REFUSED'), (await flow()).join(' '));
ok('red edit: the editor line is marked', await page.evaluate(() => !!document.querySelector('#gutter .g-line.bad')));

await click('Reset Certs'); await click('Validate');
await editDocument("d.policy.body.scopes = ['admin:all'];");
await click('Validate');
ok('red edit: hand-editing a signed body breaks its signature — the attacker cannot re-sign',
  await verdict() === 'DENIED' && (await code()) === 'ERR_OWNER_SIG_INVALID', await code());

await click('Reset Certs'); await click('Validate');
await editDocument("const c = d.chain.find((n) => n.metadata?.parent_agent_id); c.metadata.allowed_scopes = ['admin:all'];");
await click('Validate');
ok('red edit: a -02 bound typed into the metadata is refused as an unknown field, never read',
  await verdict() === 'DENIED' && (await code()) === 'ERR_SCHEMA_VIOLATION', await code());

await click('Reset Certs');
await page.evaluate(() => { const b = document.getElementById('doc'); b.value = b.value.replace('"chain": [', '"chain": [ {{{'); b.dispatchEvent(new Event('input', { bubbles: true })); });
await click('Validate');
ok('red edit: unparseable JSON is a clean DENY, not a crash', await verdict() === 'DENIED' && (await code()) === 'ERR_MALFORMED_JSON', await code());

await click('Reset Certs');
await page.evaluate(() => { const b = document.getElementById('doc'); b.value = b.value.replace('"crl": {', '"crl": {"revoked": []}, "crl": {'); b.dispatchEvent(new Event('input', { bubbles: true })); });
await click('Validate');
ok('red edit: a duplicate member is refused by the parser (§3)', (await code()) === 'ERR_DUPLICATE_MEMBER', await code());

// ── Reset ─────────────────────────────────────────────────────────────────
section('reset');
await click('Reset Certs'); await click('Validate');
ok('reset returns a broken chain to valid', await verdict() === 'ALL STAGES PASSED');

// ── Reference tabs ────────────────────────────────────────────────────────
section('reference tabs');
const tabs = await page.evaluate(() => [...document.querySelectorAll('.ref-tab')].map((t) => t.childNodes[0].textContent.trim()));
ok('two reference tabs', tabs.length === 2, tabs.join('|'));
for (const t of tabs) {
  await page.evaluate((x) => [...document.querySelectorAll('.ref-tab')].find((b) => b.childNodes[0].textContent.trim() === x).click(), t);
  await page.waitForTimeout(300);
  const filled = await page.evaluate(() => document.getElementById('ref-body').textContent.trim().length);
  ok(`tab renders: ${t}`, filled > 40, `${filled} chars`);
}

// The certificate view: openssl-shaped, both views of each profile extension.
await page.evaluate(() => [...document.querySelectorAll('.ref-tab')].find((b) => /Certificates/.test(b.textContent)).click());
await page.waitForFunction(() => document.querySelectorAll('.cert-block .cert-line').length > 50, { timeout: 10000 });
ok('five certificate blocks are decoded', await page.evaluate(() => document.querySelectorAll('.cert-block').length) === 5);
ok('the child block shows the Agent Template AND the Agent Spawn extension, decoded', await page.evaluate(() => {
  const child = [...document.querySelectorAll('.cert-block')].find((b) => b.querySelector('.cert-role')?.textContent === 'CHILD AGENT');
  const t = child?.textContent ?? '';
  return /agentTemplate/.test(t) && /agentSpawn/.test(t) && /allowed_scopes: \[read:events\]/.test(t) && /spawn_nonce:/.test(t);
}));
ok('both views of the extension are shown', await page.evaluate(() => {
  const t = document.querySelector('.cert-block')?.parentElement?.textContent ?? '';
  return /any X\.509 stack/.test(t) && /a conformant validator/.test(t);
}));
ok('the parent link in the child block points at the parent block', await page.evaluate(() => {
  const link = document.querySelector('.cert-block .cert-link');
  const parent = [...document.querySelectorAll('.cert-block')].find((b) => b.querySelector('.cert-role')?.textContent === 'PARENT AGENT');
  return !!link && parent?.dataset.id === link.textContent;
}));
await click('Escalate the scope'); await click('Validate');
await page.evaluate(() => [...document.querySelectorAll('.ref-tab')].find((b) => /Certificates/.test(b.textContent)).click());
await page.waitForFunction(() => document.querySelectorAll('.cert-block .cert-line').length > 50, { timeout: 10000 });
ok('after a refusal the offending certificate block and field are highlighted', await page.evaluate(() => {
  const bad = document.querySelector('.cert-block.bad');
  return bad?.querySelector('.cert-role')?.textContent === 'CHILD AGENT'
    && /allowed_scopes/.test(bad.querySelector('.cert-line.bad-field')?.textContent ?? '');
}));
await click('Reset Certs');

await page.evaluate(() => [...document.querySelectorAll('.ref-tab')].find((b) => /Audit/.test(b.textContent)).click());
ok('returning to the audit chain keeps its rows', await page.evaluate(() => document.querySelectorAll('.audit-row:not(.head)').length) >= 3);
const auditCols = await page.evaluate(() => [...document.querySelectorAll('.audit-row.head span')].map((c) => c.textContent.trim()));
ok('the audit log names the agent and its place in the chain', auditCols.includes('Agent') && auditCols.includes('Relationship'));
ok('each entry links to the hash of the entry above it', await page.evaluate(() => {
  const heads = [...document.querySelectorAll('.audit-row.head span')].map((c) => c.textContent.trim());
  const linksTo = heads.indexOf('Links to'); const hash = heads.indexOf('Hash');
  const rows = [...document.querySelectorAll('.audit-row:not(.head)')];
  return rows.slice(1).every((r, i) => r.children[linksTo].textContent.trim() === rows[i].children[hash].textContent.trim());
}));

// ── Privacy and export guarantees ─────────────────────────────────────────
section('privacy and export');
ok('no external network request, ever', requests.filter((u) => !u.startsWith('file://')).length === 0);
ok('no cookies', await page.evaluate(() => document.cookie) === '');
ok('no localStorage or sessionStorage', await page.evaluate(() => { try { return localStorage.length === 0 && sessionStorage.length === 0; } catch { return true; } }));
ok('no download links', await page.evaluate(() => document.querySelectorAll('a[download]').length) === 0);
ok('Copy JSON is present as the only export', await page.evaluate(() => [...document.querySelectorAll('.admin-btn')].some((b) => b.firstChild.textContent === 'Copy JSON')));
const footerText = await page.evaluate(() => document.getElementById('footer').textContent);
ok('the footer names -03 and keeps its privacy claims', /draft-tonyai-a2a-trust-03/.test(footerText) && /nothing is transmitted/i.test(footerText));
ok('no back link — the tool opens in its own tab', await page.evaluate(() => document.querySelectorAll('.back, #back-link').length) === 0);
ok('every link is http(s) or a same-file anchor', await page.evaluate(() => [...document.querySelectorAll('a[href]')].every((a) => /^(https?:|#)/.test(a.getAttribute('href')))));

// ── Layout ────────────────────────────────────────────────────────────────
section('layout');
for (const width of [1600, 1280, 1024, 820, 640]) {
  await page.setViewportSize({ width, height: 1000 });
  ok(`no horizontal overflow at ${width}px`, !(await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth + 1)));
}
await page.setViewportSize({ width: 1500, height: 1000 });
ok('page stays a sane height', await page.evaluate(() => document.documentElement.scrollHeight) < 4200);

// ── The audit chain ───────────────────────────────────────────────────────
section('audit chain');
await click('Reset Certs'); await click('Validate');
await click('Alter an audit entry'); await click('Validate');
ok('altering an entry breaks the chain, naming the entry', (await verdict()) === 'DENIED'
  && (await page.evaluate(() => document.querySelector('.banner-sub')?.textContent))?.toUpperCase().includes('ENTRY 0'));
ok('a tampered audit chain reads BROKEN, not REFUSED', (await flow()).some((f) => f === 'AUDIT CHAIN=BROKEN'));
await click('Alter an audit entry'); await click('Validate');
ok('pressing the sabotage twice leaves it broken', (await verdict()) === 'DENIED');
await click('Reset the audit chain'); await click('Validate');
ok('Reset the audit chain repairs it', (await verdict()) === 'ALL STAGES PASSED', await code());

// ── The refusal has to be visible ─────────────────────────────────────────
section('the marked line is brought into view');
const lineState = () => page.evaluate(() => {
  const box = document.getElementById('doc');
  const bad = document.querySelector('#gutter .g-line.bad');
  const lh = parseFloat(getComputedStyle(box).lineHeight) || 17;
  const line = bad ? [...document.querySelectorAll('#gutter .g-line')].indexOf(bad) + 1 : null;
  return { line, from: Math.floor(box.scrollTop / lh) + 1, to: Math.floor((box.scrollTop + box.clientHeight) / lh) + 1,
    scrollTop: box.scrollTop, focused: document.activeElement?.id === 'doc', selected: box.selectionEnd - box.selectionStart };
});
for (const label of ['Revoke the parent', 'Sign with one key only', 'Submit as the wrong owner', 'Expired grant']) {
  await click('Reset Certs'); await click(label);
  await page.evaluate(() => { document.getElementById('doc').scrollTop = 0; });
  await click('Validate');
  const r = await lineState();
  ok(`${label} -> marked line is on screen`, r.line !== null && r.line >= r.from && r.line <= r.to, `line ${r.line}, view ${r.from}-${r.to}`);
}
await click('Reset Certs'); await click('Revoke the parent');
await page.evaluate(() => { const b = document.getElementById('doc'); b.blur(); b.scrollTop = 0; });
await click('Validate');
const noSteal = await lineState();
ok('validating does not steal focus', !noSteal.focused);
ok('validating does not select text', noSteal.selected === 0);
await click('Reset Certs');

// ── Browser-side security properties ──────────────────────────────────────
section('browser security');
const BASELINE_ELEMENTS = await page.evaluate(() => document.querySelectorAll('img, iframe, svg, object, embed').length);
const XSS = [
  '<img src=x onerror="window.__pwned=1">', '<script>window.__pwned=1<\/script>', '"><svg onload="window.__pwned=1">',
  'javascript:window.__pwned=1', '<iframe src="javascript:window.__pwned=1">', '<img src=x onerror=window.__pwned=1>',
  '{{constructor.constructor("window.__pwned=1")()}}', '<a href="https://evil.example">click</a>',
];
for (const payload of XSS) {
  // The audit table renders event details verbatim, and the policy owner is
  // named in refusals: the two fields a real attacker would reach for.
  await page.evaluate((p) => {
    const box = document.getElementById('doc');
    const d = JSON.parse(box.value);
    d.audit.chain[0].event.detail = p;
    d.policy.body.owner = p;
    box.value = JSON.stringify(d, null, 2);
    box.dispatchEvent(new Event('input', { bubbles: true }));
  }, payload);
  await click('Validate');
  ok(`XSS payload does not execute: ${payload.slice(0, 34)}`, !(await page.evaluate(() => window.__pwned === 1)));
}
ok('no injected element entered the DOM while payloads were rendered',
  await page.evaluate(() => document.querySelectorAll('img, iframe, svg, object, embed').length) === BASELINE_ELEMENTS);
ok('no <script> beyond the single inlined bundle', await page.evaluate(() => document.querySelectorAll('script').length) === 1);
ok('no inline event handler exists anywhere in the page',
  await page.evaluate(() => [...document.querySelectorAll('*')].every((n) => ![...n.attributes].some((a) => a.name.startsWith('on')))));
ok('external links carry rel=noopener',
  await page.evaluate(() => [...document.querySelectorAll('a[target]')].every((a) => (a.getAttribute('rel') || '').includes('noopener'))));
ok('the page reads nothing from the URL', await page.evaluate(() => {
  const src = document.querySelector('script:not([src])')?.textContent ?? '';
  return !/location\.(search|hash)|URLSearchParams|new URL\(location/.test(src);
}));
for (const [label, text] of Object.entries({
  'empty': '', 'not JSON': 'hello', 'an array root': '[1,2,3]', 'truncated': '{"chain":',
  'invalid escape': '{"\\q": 1}', 'a 300-deep nest': '{"n":'.repeat(300) + '1' + '}'.repeat(300),
})) {
  await page.evaluate((t) => { const box = document.getElementById('doc'); box.value = t; box.dispatchEvent(new Event('input', { bubbles: true })); }, text);
  await click('Validate');
  ok(`hostile input is refused cleanly, not crashed on: ${label}`, (await verdict()) === 'DENIED', await verdict());
}
await click('Reset Certs');

// ── Console ───────────────────────────────────────────────────────────────
section('console');
ok('no console or page errors across the whole run', consoleErrors.length === 0, consoleErrors.slice(0, 2).join(' | '));

await browser.close();
console.log(`\n${passed} passed, ${failures.length} failed`);
if (failures.length) { for (const f of failures) console.log(`  FAILED: ${f}`); process.exit(1); }
