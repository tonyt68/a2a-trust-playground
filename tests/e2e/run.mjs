/**
 * End-to-end regression suite — drives the BUILT single file in a real browser.
 *
 * Everything here was, at some point this build, a bug found by clicking around
 * by hand: the vanishing agent roster, the CSP blocking the back link, the
 * flow blaming the wrong subject, the page growing to 4000px. Unit tests were
 * green through all of it, because none of those are questions a unit test asks.
 *
 * Runs against dist/a2a.html over file:// with the network DISCONNECTED, which
 * is the strictest environment the page ever sees and the one that proves the
 * "nothing leaves your browser" claim rather than asserting it.
 *
 *   pnpm test:e2e
 *
 * Uses the system Chrome rather than a downloaded browser, and skips with a
 * clear message if it is absent — a missing browser must not read as a failure.
 */
import { chromium } from 'playwright';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const CHROME = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
const BUILT = fileURLToPath(new URL('../../dist/a2a.html', import.meta.url));

if (!existsSync(BUILT)) {
  console.error('dist/a2a.html is missing — run `pnpm build` first.');
  process.exit(1);
}
if (!existsSync(CHROME)) {
  console.log('SKIP: Google Chrome not found at the expected path.');
  process.exit(0);
}

let lastStep = 'startup';
let passed = 0;
const failures = [];
const ok = (name, cond, detail = '') => {
  if (cond) { passed += 1; console.log(`  ok    ${name}`); }
  else { failures.push(`${name}${detail ? ` — ${detail}` : ''}`); console.log(`  FAIL  ${name}${detail ? ` — ${detail}` : ''}`); }
};
const section = (t) => { lastStep = t; console.log(`\n${t}`); };

// `lastStep` is declared above, next to `passed`: "no console errors across the
// whole run" is a useful assertion and a useless diagnostic, failing at the end
// of the file having lost all context about which of 150 steps caused it.

const browser = await chromium.launch({ executablePath: CHROME });
const context = await browser.newContext({ viewport: { width: 1500, height: 1000 } });
await context.setOffline(true);           // the page must never need the network
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
const code = () => page.evaluate(() =>
  (document.querySelector('.banner-code')?.textContent || '').split(' · ')[0]);
const flow = () => page.evaluate(() => [...document.querySelectorAll('#pipeline .p-box')]
  .map((b) => `${b.querySelector('.p-name').textContent}=${b.querySelector('.p-sub').textContent}`));

// ── Load ──────────────────────────────────────────────────────────────────
await page.goto(`file://${BUILT}`);
// Wait for the seed to COMPLETE, not merely for the buttons to exist. Waiting
// on `settle()` alone raced the initial mint and read a blank editor.
await page.waitForFunction(
  () => document.querySelector('.banner-main')?.textContent === 'NOT VALIDATED'
    && ![...document.querySelectorAll('.admin-btn')].some((b) => b.disabled),
  { timeout: 40000 });

section('load');
ok('seeds a chain without validating it', await verdict() === 'NOT VALIDATED', await verdict());
ok('flow starts with nothing claimed', (await flow()).every((f) => f.endsWith('=—')));
ok('editor holds a parseable document', await page.evaluate(() => {
  try { const d = JSON.parse(document.getElementById('doc').value); return Array.isArray(d.chain) && d.chain.length === 3; }
  catch { return false; }
}));
// The separate agent roster was removed: it rendered from the last validation
// and then sat there, so editing a scope left it reporting the old value.
// Identity now lives on the audit log, which is the record that is actually
// tamper-evident and cannot drift from the document.
ok('the audit log carries the seeded entries before any validation',
  await page.evaluate(() => document.querySelectorAll('.audit-row:not(.head)').length) >= 3);

// ── Validate ──────────────────────────────────────────────────────────────
section('validate');
const auditBefore = await page.evaluate(() =>
  (JSON.parse(document.getElementById('doc').value).audit?.chain ?? []).length);
await click('Validate');
ok('a fresh chain validates', await verdict() === 'ALL STAGES PASSED', await code());
ok('all six walk steps are VALID', (await flow()).every((f) => f.endsWith('=VALID')), (await flow()).join(' '));
ok('nine stages logged, none skipped',
  await page.evaluate(() => [...document.querySelectorAll('#log .log-row')]
    .filter((r) => r.children[2].textContent === 'PASS').length) === 9);
ok('a validation run appends exactly one audit entry',
  (await page.evaluate(() =>
    (JSON.parse(document.getElementById('doc').value).audit?.chain ?? []).length)) === auditBefore + 1,
  `before ${auditBefore}`);

// ── Modifications the draft ALLOWS ────────────────────────────────────────
section('modifications the draft allows — must stay valid');
const allowed = await page.evaluate(() =>
  [...document.querySelectorAll('#controls-allowed .admin-btn, .phase-grid .admin-btn.ok')]
    .map((b) => b.firstChild.textContent));
for (const label of allowed) {
  await click('Reset Certs');
  await click('Validate');
  await click(label);
  await click('Validate');
  ok(`allowed: ${label}`, await verdict() === 'ALL STAGES PASSED', await code());
}

// ── Modifications the draft REFUSES ───────────────────────────────────────
section('modifications the draft refuses — must name the clause');
const EXPECTED = {
  'Disable the agent': 'ERR_AGENT_DISABLED',
  'Forge the issuer': 'ERR_FORGED_ISSUER',
  'Corrupt the certificate': 'ERR_CHAIN_INVALID',
  'Revoke the parent': 'ERR_AGENT_REVOKED',
  'Expire the cert': 'ERR_TTL_EXPIRED',
  'Sign with one key only': 'ERR_PA_SIG_MISSING',
  'Tamper with the policy doc': 'ERR_PA_SIG_INVALID',
  'Alter the stored hash only': 'ERR_CONTENT_HASH',
  'Edit can_spawn via policy': 'ERR_IMMUTABLE_FIELD',
  'Submit as the wrong owner': 'ERR_OWNER_MISMATCH',
  'Escalate the scope': 'ERR_SCOPE_ESCALATION',
  'Exceed max_children': 'ERR_MAX_CHILDREN',
  'Spawn a non-whitelisted child': 'ERR_CHILD_NOT_WHITELISTED',
  'Widen policy past the ceiling': 'ERR_POLICY_EXCEEDS_TEMPLATE',
  'Alter an audit entry': 'ERR_AUDIT_CHAIN_BROKEN',
};
for (const [label, expected] of Object.entries(EXPECTED)) {
  await click('Reset Certs');
  await click('Validate');                       // seeds an audit entry to tamper with
  await click(label);
  await click('Validate');
  const got = await code();
  ok(`refused: ${label}`, (await verdict()) === 'DENIED' && got === expected, `expected ${expected}, got ${got}`);
  const marked = await page.evaluate(() => !!document.querySelector('#gutter .g-line.bad'));
  const isAudit = label === 'Alter an audit entry';
  ok(`  ${label} → marks the offending line`, marked || isAudit);
  const denies = await page.evaluate(() => document.querySelectorAll('#log .log-row.deny').length);
  ok(`  ${label} → exactly one DENY row`, denies === 1, `${denies} rows`);
  // Counted by state class, not by the word. A denied step says REFUSED for a
  // request and BROKEN for the audit chain, and the count is about how many
  // steps failed, not about how they are phrased.
  const failedSteps = await page.evaluate(() =>
    document.querySelectorAll('#pipeline .p-box.err').length);
  ok(`  ${label} → the walk stops at one step`, failedSteps === 1, `${failedSteps} failed`);
}

// ── Freeform edits in the editor (AC-14) ──────────────────────────────────
// The buttons are shortcuts; the editor is the primary surface. DESIGN.md is
// explicit that the freeform path must reach the same verdict as the preset —
// so these type into the textarea rather than pressing anything.
section('freeform edits — typing into the document');

/** Replace text in the editor the way a person editing it would. */
const editDocument = (find, replace, occurrence = 1) => page.evaluate(([f, r, n]) => {
  const box = document.getElementById('doc');
  let seen = 0;
  box.value = box.value.replace(new RegExp(f.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'),
    (m) => (++seen === n ? r : m));
  box.dispatchEvent(new Event('input', { bubbles: true }));
  return seen >= n;
}, [find, replace, occurrence]);

// GREEN: a hand edit the draft permits. template_version is neither signed nor
// bounded, so changing it must leave the chain valid.
await click('Reset Certs');
await click('Validate');
ok('green edit: found the field to change', await editDocument('"template_version": "1.0"', '"template_version": "1.1"', 1));
await click('Validate');
ok('green edit: hand-edited template_version stays VALID',
  await verdict() === 'ALL STAGES PASSED', await code());
ok('green edit: the change really is in the document',
  await page.evaluate(() => document.getElementById('doc').value.includes('"template_version": "1.1"')));

// RED-1: edit ONE copy of the child's bounds and not its duplicate. This is the
// most likely hand-editing mistake, and it must be refused rather than silently
// resolved in the editor's favour.
await click('Reset Certs');
await click('Validate');
await page.evaluate(() => {
  const box = document.getElementById('doc');
  const d = JSON.parse(box.value);
  const child = d.chain.find((n) => n.metadata?.parent_agent_id);
  child.metadata.allowed_scopes = ['admin:all'];   // top-level copy only
  box.value = JSON.stringify(d, null, 2);
  box.dispatchEvent(new Event('input', { bubbles: true }));
});
await click('Validate');
ok('red edit: bounds copies disagreeing is refused, not reconciled',
  await verdict() === 'DENIED' && (await code()) === 'ERR_BOUNDS_UNPARSEABLE', await code());

// RED-2: widen the child properly — both copies and the request — so the run
// reaches §8.3. This is AC-14: the freeform path must reach the same verdict as
// the preset button.
await click('Reset Certs');
await click('Validate');
await page.evaluate(() => {
  const box = document.getElementById('doc');
  const d = JSON.parse(box.value);
  const child = d.chain.find((n) => n.metadata?.parent_agent_id);
  child.metadata.allowed_scopes = ['admin:all'];
  child.metadata.authorization_bounds.allowed_scopes = ['admin:all'];
  child.requested_scopes = ['admin:all'];
  delete d.policy_update;             // isolate §8.3 from the §7.2 ceiling
  box.value = JSON.stringify(d, null, 2);
  box.dispatchEvent(new Event('input', { bubbles: true }));
});
await click('Validate');
const redCode = await code();
ok('red edit: hand-widened child scope is REFUSED (AC-14)',
  await verdict() === 'DENIED' && redCode === 'ERR_SCOPE_ESCALATION', `got ${redCode}`);
ok('red edit: the refusal cites §8.3',
  await page.evaluate(() => (document.querySelector('.banner-code')?.textContent || '').includes('§8.3')));
ok('red edit: the walk names DELEGATION',
  (await flow()).some((f) => f.startsWith('DELEGATION') && f.endsWith('=REFUSED')), (await flow()).join(' '));
ok('red edit: the editor line is marked',
  await page.evaluate(() => !!document.querySelector('#gutter .g-line.bad')));

// RED: a broken document must refuse cleanly, never throw.
await click('Reset Certs');
await editDocument('"chain": [', '"chain": [ {{{', 1);
await click('Validate');
ok('red edit: unparseable JSON is a clean DENY, not a crash',
  await verdict() === 'DENIED' && (await code()) === 'ERR_MALFORMED_JSON', await code());

// ── Reset ─────────────────────────────────────────────────────────────────
section('reset');
await click('Reset Certs');
await click('Validate');
ok('reset returns a broken chain to valid', await verdict() === 'ALL STAGES PASSED');
ok('reset clears every report flag',
  await page.evaluate(() => document.querySelectorAll('table.report tr.bad').length) === 0);

// ── Reference tabs ────────────────────────────────────────────────────────
section('reference tabs');
const tabs = await page.evaluate(() =>
  [...document.querySelectorAll('.ref-tab')].map((t) => t.childNodes[0].textContent.trim()));
ok('two reference tabs', tabs.length === 2, tabs.join('|'));
for (const t of tabs) {
  await page.evaluate((x) => [...document.querySelectorAll('.ref-tab')]
    .find((b) => b.childNodes[0].textContent.trim() === x).click(), t);
  const filled = await page.evaluate(() => document.getElementById('ref-body').textContent.trim().length);
  ok(`tab renders: ${t}`, filled > 40, `${filled} chars`);
}
await page.evaluate(() => [...document.querySelectorAll('.ref-tab')]
  .find((b) => b.childNodes[0].textContent.trim() === 'Audit chain').click());
ok('returning to the audit chain keeps its rows',
  await page.evaluate(() => document.querySelectorAll('.audit-row:not(.head)').length) >= 3);

// Identity moved here from the removed roster, so it has to actually be here.
const auditCols = await page.evaluate(() =>
  [...document.querySelectorAll('.audit-row.head span')].map((c) => c.textContent.trim()));
ok('the audit log names the agent and its place in the chain',
  auditCols.includes('Agent') && auditCols.includes('Relationship'), auditCols.join('|'));
// Located by HEADER position rather than a hardcoded index: this broke once
// already when a Time column was inserted ahead of it.
ok('a spawn entry names the agent and its place in the chain', await page.evaluate(() => {
  const heads = [...document.querySelectorAll('.audit-row.head span')].map((c) => c.textContent.trim());
  const agent = heads.indexOf('Agent');
  const rel = heads.indexOf('Relationship');
  const row = [...document.querySelectorAll('.audit-row:not(.head)')]
    .find((r) => r.textContent.includes('spawn_child'));
  return !!row && agent > -1 && rel > -1
    && row.children[agent].textContent.trim().length > 20
    && row.children[rel].textContent.trim() === 'child';
}));

ok('the root agent reads as parent, not child', await page.evaluate(() => {
  const heads = [...document.querySelectorAll('.audit-row.head span')].map((c) => c.textContent.trim());
  const rel = heads.indexOf('Relationship');
  const row = [...document.querySelectorAll('.audit-row:not(.head)')]
    .find((r) => r.textContent.includes('issue_template'));
  return row?.children[rel].textContent.trim() === 'parent';
}));

// An audit record is read after the session that produced it, so a bare
// wall-clock time would be ambiguous. The zone is stated rather than assumed.
ok('timestamps carry a date and state their zone', await page.evaluate(() => {
  const heads = [...document.querySelectorAll('.audit-row.head span')].map((c) => c.textContent.trim());
  const when = heads.findIndex((h) => h.startsWith('Timestamp'));
  const stamped = document.querySelector('.audit-row:not(.head)')?.children[when]?.textContent.trim();
  return heads[when].includes('UTC') && /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(stamped);
}));

// The chain has to be readable as a chain: each row links to the one above it.
ok('each entry links to the hash of the entry above it', await page.evaluate(() => {
  const heads = [...document.querySelectorAll('.audit-row.head span')].map((c) => c.textContent.trim());
  const linksTo = heads.indexOf('Links to');
  const hash = heads.indexOf('Hash');
  const rows = [...document.querySelectorAll('.audit-row:not(.head)')];
  if (linksTo < 0 || hash < 0 || rows.length < 2) return false;
  return rows.slice(1).every((r, i) =>
    r.children[linksTo].textContent.trim() === rows[i].children[hash].textContent.trim());
}));
ok('the first entry links to genesis', await page.evaluate(() => {
  const heads = [...document.querySelectorAll('.audit-row.head span')].map((c) => c.textContent.trim());
  const linksTo = heads.indexOf('Links to');
  const first = document.querySelector('.audit-row:not(.head)');
  return first?.children[linksTo].textContent.trim() === 'genesis';
}));

// ── Privacy and export guarantees ─────────────────────────────────────────
section('privacy and export (AC-10, AC-12)');
const external = requests.filter((u) => !u.startsWith('file://'));
ok('no external network request, ever', external.length === 0, external[0]);
ok('no cookies', await page.evaluate(() => document.cookie) === '');
ok('no localStorage or sessionStorage', await page.evaluate(() => {
  try { return localStorage.length === 0 && sessionStorage.length === 0; } catch { return true; }
}));
ok('no download links', await page.evaluate(() => document.querySelectorAll('a[download]').length) === 0);
ok('Copy JSON is present as the only export',
  await page.evaluate(() => [...document.querySelectorAll('.admin-btn')]
    .some((b) => b.firstChild.textContent === 'Copy JSON')));

// The footer makes privacy claims a visitor mostly cannot verify. It must not
// also make one they CAN — it used to say "there is no reset button because
// refresh is the reset", which stopped being true the moment Reset Certs and
// Reset the audit chain existed. A visibly false claim discredits the ones
// beside it that have to be taken on trust.
section('the footer does not contradict the page');
const footerText = await page.evaluate(() => document.getElementById('footer').textContent);
const resetButtons = await page.evaluate(() => [...document.querySelectorAll('button')]
  .map((b) => b.firstChild?.textContent?.trim() ?? '')
  .filter((t) => /^Reset\b/.test(t)));
ok('the page has reset buttons', resetButtons.length >= 2, resetButtons.join(', '));
ok('the footer does not deny that they exist',
  !/no reset button/i.test(footerText), footerText.slice(0, 90));
ok('the footer still makes its privacy claims',
  /nothing is transmitted/i.test(footerText)
  && /no cookies/i.test(footerText)
  && /localStorage/i.test(footerText));
ok('and still says a refresh discards everything',
  /refresh/i.test(footerText) && /discard/i.test(footerText));

// ── Navigation ────────────────────────────────────────────────────────────
section('navigation');
ok('back link points one level up, at the filename',
  await page.evaluate(() => document.querySelector('.back').getAttribute('href')) === '../index.html');

// ── Layout ────────────────────────────────────────────────────────────────
section('layout');
for (const width of [1600, 1280, 1024, 820, 640]) {
  await page.setViewportSize({ width, height: 1000 });
  const bad = await page.evaluate(() =>
    document.documentElement.scrollWidth > document.documentElement.clientWidth + 1);
  ok(`no horizontal overflow at ${width}px`, !bad);
}
await page.setViewportSize({ width: 1500, height: 1000 });
ok('page stays a sane height', await page.evaluate(() => document.documentElement.scrollHeight) < 3200);

// ── The audit chain (§16.6) ───────────────────────────────────────────────
//
// The default document used to seed `audit: { chain: [] }`, so stage 9 passed
// vacuously and `Alter an audit entry` had no entry to alter. The button
// silently did nothing on a fresh load, which reads as a broken control rather
// than a demonstration.
section('audit chain');

await click('Reset Certs');
const seeded = await page.evaluate(() =>
  (JSON.parse(document.getElementById('doc').value).audit?.chain ?? []).length);
ok('a fresh document seeds a real audit chain', seeded >= 3, `${seeded} entries`);

await click('Validate');
ok('the seeded chain verifies', (await verdict()) === 'ALL STAGES PASSED');

await click('Alter an audit entry');
await click('Validate');
ok('altering an entry breaks the chain', (await verdict()) === 'DENIED', await code());
ok('the refusal names the entry',
  (await page.evaluate(() => document.querySelector('.banner-sub')?.textContent)) 
    ?.toUpperCase().includes('ENTRY 0'));

// The marker must land on the entry, not on the enclosing `audit` object.
const auditMark = await page.evaluate(() => {
  const box = document.getElementById('doc');
  const bad = document.querySelector('#gutter .g-line.bad');
  if (!bad) return null;
  const n = [...document.querySelectorAll('#gutter .g-line')].indexOf(bad) + 1;
  const lh = parseFloat(getComputedStyle(box).lineHeight) || 17;
  return {
    n,
    within: box.value.split('\n').slice(n - 1, n + 4).join(' '),
    from: Math.floor(box.scrollTop / lh) + 1,
    to: Math.floor((box.scrollTop + box.clientHeight) / lh) + 1,
  };
});
ok('the audit failure marks a line at all', auditMark !== null);
ok('it marks the altered ENTRY, not the audit container',
  auditMark?.within.includes('"index": 0'), auditMark?.within.slice(0, 60));
ok('the marked audit line is on screen',
  auditMark && auditMark.n >= auditMark.from && auditMark.n <= auditMark.to);

// Idempotent: this used to FLIP `decision`, so a second press repaired the
// chain. A red button must not fix things when pressed twice.
await click('Alter an audit entry');
await click('Validate');
ok('pressing the sabotage twice leaves it broken', (await verdict()) === 'DENIED', await code());

await click('Reset Certs');
await click('Validate');
ok('Reset Certs restores a verifying chain', (await verdict()) === 'ALL STAGES PASSED');

// `Reset the audit chain` is a repair sitting next to the button that breaks it.
// Reset Certs also fixes a broken chain, but it is at the top of the page and it
// discards every other edit with it.
const parentScopes = () => page.evaluate(() => {
  const d = JSON.parse(document.getElementById('doc').value);
  return d.chain.find((n) => n.role === 'agent' && !n.metadata.parent_agent_id)
    .metadata.allowed_scopes.join(',');
});

await click('Narrow the parent to read-only');
const narrowed = await parentScopes();
await click('Alter an audit entry');
await click('Validate');
ok('audit is broken with an unrelated edit in place', (await verdict()) === 'DENIED');

// A step must answer the question it asks. "is the record intact?" is a
// question about state, so REFUSED there reads as though detection failed.
const stepWord = (name) => page.evaluate((n) => {
  const box = [...document.querySelectorAll('#pipeline .p-box')]
    .find((b) => b.querySelector('.p-name')?.textContent === n);
  return box?.querySelector('.p-sub')?.textContent;
}, name);
ok('a tampered audit chain reads BROKEN, not REFUSED',
  (await stepWord('AUDIT CHAIN')) === 'BROKEN', await stepWord('AUDIT CHAIN'));

// The table is ~1130px of fixed columns. It must scroll inside its own container
// rather than either being clipped or making the page scroll sideways. It was
// clipped: on a 390px viewport the Agent, Relationship, Links to and Hash
// columns were unreachable, with nothing on screen to say they existed.
for (const [w, h, label] of [[390, 844, 'phone'], [768, 1024, 'tablet']]) {
  await page.setViewportSize({ width: w, height: h });
  await page.waitForTimeout(200);
  const r = await page.evaluate(() => {
    const sc = document.querySelector('.audit-scroll');
    if (!sc) return null;
    sc.scrollLeft = 99999;
    const last = document.querySelector('.audit-row:not(.head)')?.lastElementChild;
    return {
      scrolls: sc.scrollWidth > sc.clientWidth,
      pageSideways: document.documentElement.scrollWidth > document.documentElement.clientWidth + 1,
      lastReachable: last ? last.getBoundingClientRect().right <= window.innerWidth + 2 : false,
    };
  });
  ok(`${label}: the audit log scrolls rather than clipping`, r?.scrolls === true);
  ok(`${label}: the page itself never scrolls sideways`, r?.pageSideways === false);
  ok(`${label}: the Hash column can be reached`, r?.lastReachable === true);
}
await page.setViewportSize({ width: 1500, height: 1000 });
await page.waitForTimeout(200);

// Header and rows share one scroller; two would desync and the labels would
// drift off their columns as soon as you scrolled.
ok('every heading sits over its own column', await page.evaluate(() => {
  const head = [...document.querySelectorAll('.audit-row.head span')];
  const row = [...(document.querySelector('.audit-row:not(.head)')?.children ?? [])];
  return head.length === row.length && head.every((h, i) =>
    Math.round(h.getBoundingClientRect().left) === Math.round(row[i].getBoundingClientRect().left));
}));

await click('Reset the audit chain');
await click('Validate');
ok('Reset the audit chain repairs it', (await verdict()) === 'ALL STAGES PASSED', await code());
ok('and it KEEPS the unrelated edit', (await parentScopes()) === narrowed,
  `expected ${narrowed}, got ${await parentScopes()}`);

await click('Reset Certs');
ok('whereas Reset Certs discards that edit', (await parentScopes()) !== narrowed);

// Every audit row must name WHAT was attempted. The denied row used to render
// `reason ?? action`, so it showed only the error code and the action vanished:
// "DENIED  ERR_AUDIT_CHAIN_BROKEN" reads as though the code is the thing that
// was denied, while every row above it named an action.
await click('Alter an audit entry');
await click('Validate');
await page.evaluate(() => {
  [...document.querySelectorAll('.ref-tab')].find((t) => /audit/i.test(t.textContent))?.click();
});
const auditRows = await page.evaluate(() => [...document.querySelectorAll('.audit-row')]
  .map((r) => ({
    decision: r.children[1]?.textContent.trim(),
    detail: r.children[2]?.textContent.trim(),
  })));
ok('the audit panel lists rows', auditRows.length >= 4, `${auditRows.length} rows`);
ok('no audit row leads with an error code',
  auditRows.every((r) => !r.detail.startsWith('ERR_')),
  auditRows.map((r) => r.detail).join(' | '));
ok('denied rows name the action AND the reason',
  auditRows.filter((r) => r.decision === 'DENIED')
    .every((r) => r.detail.includes('verify_chain') && r.detail.includes('ERR_')),
  auditRows.filter((r) => r.decision === 'DENIED').map((r) => r.detail).join(' | '));

await click('Reset the audit chain');

// ── The refusal has to be visible ─────────────────────────────────────────
//
// A gutter marker the visitor cannot see is worse than no marker: the banner
// says DENIED and points at nothing on screen. Measured before this was fixed —
// scroll to the top, escalate a scope, press Validate, and the marker landed on
// line 68 while the editor was showing lines 1 to 28.
section('the marked line is brought into view');

const lineState = () => page.evaluate(() => {
  const box = document.getElementById('doc');
  const bad = document.querySelector('#gutter .g-line.bad');
  const lh = parseFloat(getComputedStyle(box).lineHeight) || 17;
  const line = bad ? [...document.querySelectorAll('#gutter .g-line')].indexOf(bad) + 1 : null;
  return {
    line,
    from: Math.floor(box.scrollTop / lh) + 1,
    to: Math.floor((box.scrollTop + box.clientHeight) / lh) + 1,
    scrollTop: box.scrollTop,
    focused: document.activeElement?.id === 'doc',
    selected: box.selectionEnd - box.selectionStart,
  };
});

for (const label of ['Escalate the scope', 'Sign with one key only',
                     'Submit as the wrong owner', 'Expire the cert']) {
  await click('Reset Certs');
  await click(label);
  // The visitor scrolls elsewhere before validating, which is entirely normal.
  await page.evaluate(() => { document.getElementById('doc').scrollTop = 0; });
  await click('Validate');
  const r = await lineState();
  ok(`${label} -> marked line is on screen`,
    r.line !== null && r.line >= r.from && r.line <= r.to,
    `line ${r.line}, view ${r.from}-${r.to}`);
}

// Validation is not a request to go there, so it must not take the caret.
await click('Reset Certs');
await click('Escalate the scope');
await page.evaluate(() => {
  const b = document.getElementById('doc');
  b.blur(); b.scrollTop = 0;
});
await click('Validate');
const noSteal = await lineState();
ok('validating does not steal focus', !noSteal.focused);
ok('validating does not select text', noSteal.selected === 0);
ok('validating still scrolled to the failure', noSteal.scrollTop > 0);

// And it must not yank the view when the failure is already visible.
const settled = (await lineState()).scrollTop;
await page.evaluate(() => { document.getElementById('doc').scrollTop -= 20; });
const nudged = await page.evaluate(() => document.getElementById('doc').scrollTop);
await click('Validate');
ok('re-validating leaves an already-visible failure alone',
  (await lineState()).scrollTop === nudged, `settled ${settled}, nudged ${nudged}`);

await click('Reset Certs');

await click('Reset Certs');
await click('Escalate the scope');
await click('Validate');
ok('a genuine refusal still reads REFUSED',
  (await page.evaluate(() => [...document.querySelectorAll('#pipeline .p-box')]
    .find((b) => b.querySelector('.p-name')?.textContent === 'DELEGATION')
    ?.querySelector('.p-sub')?.textContent)) === 'REFUSED');
await click('Reset Certs');

// ── Browser-side security properties ──────────────────────────────────────
//
// The unit suite proves the VALIDATOR refuses hostile documents. These prove the
// PAGE cannot be turned into a weapon by one — a different question, because a
// correctly-refused document is still rendered: its fields appear in the editor,
// in the highlight, and in the error banner. Rendering attacker-controlled text
// is where a validator becomes an XSS vector.
//
// These run against the BUILT single file at file://, which is how it ships.
section('browser security');

// Every string the page renders comes from the document, so the payloads go into
// fields the UI is known to display: the banner, the flow, the audit table.
const BASELINE_ELEMENTS = await page.evaluate(() =>
  document.querySelectorAll('img, iframe, svg, object, embed').length);

const XSS = [
  '<img src=x onerror="window.__pwned=1">',
  '<script>window.__pwned=1<\/script>',
  '"><svg onload="window.__pwned=1">',
  'javascript:window.__pwned=1',
  '<iframe src="javascript:window.__pwned=1">',
  '<img src=x onerror=window.__pwned=1>',
  '{{constructor.constructor("window.__pwned=1")()}}',
  '<a href="https://evil.example">click</a>',
];

for (const payload of XSS) {
  await page.evaluate((p) => {
    const box = document.getElementById('doc');
    const d = JSON.parse(box.value);
    const child = d.chain.find((n) => n.role === 'agent' && n.metadata?.parent_agent_id);
    // Owner and description are free text in the draft, so they are the fields a
    // real attacker would reach for.
    child.metadata.owner = p;
    if (d.policy_doc) d.policy_doc.description = p;
    box.value = JSON.stringify(d, null, 2);
    box.dispatchEvent(new Event('input', { bubbles: true }));
  }, payload);
  await click('Validate');

  const pwned = await page.evaluate(() => window.__pwned === 1);
  ok(`XSS payload does not execute: ${payload.slice(0, 34)}`, !pwned);
}

// The payloads above are inert only because nothing builds DOM from strings.
// Assert the mechanism, not just the outcome — the outcome would also hold by
// luck if a payload happened not to fire.
// The page ships one legitimate inline <svg> (the shield). What matters is that
// the count did not MOVE while eight payloads were rendered — an absolute zero
// would be asserting the page has no graphics, which is a different claim.
ok('no injected element entered the DOM while payloads were rendered',
  await page.evaluate(() => document.querySelectorAll('img, iframe, svg, object, embed').length) === BASELINE_ELEMENTS,
  `baseline ${BASELINE_ELEMENTS}`);
ok('no <script> beyond the single inlined bundle',
  await page.evaluate(() => document.querySelectorAll('script').length) === 1);
ok('no inline event handler exists anywhere in the page',
  await page.evaluate(() => [...document.querySelectorAll('*')]
    .every((n) => ![...n.attributes].some((a) => a.name.startsWith('on')))));
ok('every link is http(s) or a same-file anchor',
  await page.evaluate(() => [...document.querySelectorAll('a[href]')]
    .every((a) => /^(https?:|#|\.\.?\/)/.test(a.getAttribute('href')))));
ok('external links carry rel=noopener',
  await page.evaluate(() => [...document.querySelectorAll('a[target="_blank"]')]
    .every((a) => (a.getAttribute('rel') || '').includes('noopener'))));

// "Point some poor soul at a URL that preloads a hostile document" is the attack
// that would make this page a delivery mechanism. It is impossible only because
// the page reads no URL input at all — so that is what gets asserted.
ok('the page reads nothing from the URL',
  await page.evaluate(() => {
    const src = document.querySelector('script:not([src])')?.textContent ?? '';
    return !/location\.(search|hash)|URLSearchParams|new URL\(location/.test(src);
  }));
const withHostileUrl = `${BUILT}#${encodeURIComponent(JSON.stringify({ chain: [{ role: 'ca' }] }))}`;
const probe = await context.newPage();
await probe.goto(`file://${withHostileUrl}?doc=${encodeURIComponent('{"chain":[]}')}`);
await probe.waitForFunction(() => document.getElementById('doc')?.value.length > 0);
ok('a document supplied in the URL is ignored',
  (await probe.evaluate(() => JSON.parse(document.getElementById('doc').value).chain.length)) === 3);
await probe.close();

// Nothing is transmitted. Asserted against the real request log for the whole
// run, not against a claim in the page copy.
ok('no network request beyond the file itself',
  requests.filter((u) => !u.startsWith('file://')).length === 0,
  requests.filter((u) => !u.startsWith('file://')).slice(0, 2).join(' | '));
ok('no storage written', await page.evaluate(() =>
  localStorage.length === 0 && sessionStorage.length === 0 && document.cookie === ''));

// The editor is the only input, so it must survive whatever is pasted into it.
for (const [label, text] of Object.entries({
  'empty': '',
  'not JSON': 'hello',
  'an array root': '[1,2,3]',
  'truncated': '{"chain":',
  'invalid escape': '{"\\q": 1}',
  'a 300-deep nest': '{"n":'.repeat(300) + '1' + '}'.repeat(300),
})) {
  await page.evaluate((t) => {
    const box = document.getElementById('doc');
    box.value = t;
    box.dispatchEvent(new Event('input', { bubbles: true }));
  }, text);
  await click('Validate');
  const banner = await verdict();
  ok(`hostile input is refused cleanly, not crashed on: ${label}`,
    banner === 'DENIED' || banner === 'INVALID DOCUMENT', banner);
}

await click('Reset Certs');

// ── Console ───────────────────────────────────────────────────────────────
section('console');
ok('no console or page errors across the whole run',
  consoleErrors.length === 0, consoleErrors.slice(0, 2).join(' | '));

await browser.close();

console.log(`\n${passed} passed, ${failures.length} failed`);
if (failures.length) { for (const f of failures) console.log(`  FAILED: ${f}`); process.exit(1); }
