/**
 * The page.
 *
 * The JSON document in the editor is the source of truth; everything rendered
 * here is a view over it. Nothing is stored anywhere else — no hidden state
 * object the UI mutates behind the editor's back — because the moment those two
 * diverge, a sabotage button is lying about what it did.
 *
 * ── Rendering rule, non-negotiable ─────────────────────────────────────────
 *
 * `textContent` only. There is no `innerHTML` in this file for any value that
 * came from the document, and the document is whatever a stranger pasted. Every
 * field on this page ends up displayed, so every field is an XSS vector, and an
 * XSS in a Zero Trust demo is not a bug — it is a refutation.
 *
 * ── Sabotage buttons write into the editor ─────────────────────────────────
 *
 * Each one applies its change to the document, re-serialises it into the
 * textarea, scrolls to the line it changed, and only then verifies. The visitor
 * sees WHAT changed rather than watching a verdict flip for invisible reasons.
 */

import { buildDefaultDocument, seedAuditChain } from './defaults.js';
import { mintChain } from './mint.js';
import { policyContentHash } from './policy.js';
import { extractPolicyFields, extractIdentityFields, canonicalize } from './canonical.js';
import { privateKeyFromPem, signCanonical } from './crypto-sign.js';
import { runPipeline, NOT_APPLICABLE, DRAFT } from './pipeline.js';
import { parseDocument } from './validate-input.js';
import { DenyError } from './errors.js';
import { locateFailure, lineRange } from './locate.js';

const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;   // textContent, always
  return n;
};

/** Build stamp, replaced at build time. */
const VERSION = '1.0.0+dev';

const STAGE_LABELS = {
  1: 'AGENT ID', 2: 'X.509', 3: 'REVOCATION', 4: 'DUAL SIG',
  5: 'FIELD GUARD', 6: 'REQUIRED', 7: 'BOUNDS', 8: 'SCOPE', 9: 'AUDIT',
};
const STAGE_NAMES = {
  1: 'agent_id_format', 2: 'x509_identity', 3: 'revocation', 4: 'dual_signature',
  5: 'policy_field_guard', 6: 'required_fields', 7: 'authorization_bounds',
  8: 'scope_subset', 9: 'audit_chain',
};

let lastResult = null;
/**
 * What the reference pane is currently showing. Before the first Validate this
 * is a view derived from the seeded document (the agents exist, nothing has
 * been claimed about them); afterwards it is the real pipeline result.
 *
 * Tab clicks re-render from THIS, not from `lastResult` — reading `lastResult`
 * meant switching tabs before validating wiped the roster to "0 nodes",
 * because no result existed yet.
 */
let referenceView = null;

// ── Editor ────────────────────────────────────────────────────────────────

const docBox = $('doc');
const gutter = $('gutter');

function setDocument(obj, { keepScroll = false } = {}) {
  const top = keepScroll ? docBox.scrollTop : 0;
  docBox.value = JSON.stringify(obj, null, 2);
  // Open at the top. Landing on line 154 of the audit chain shows a newcomer
  // base64 blobs and hashes — the least legible part of the document.
  docBox.scrollTop = top;
  // Every button that changes the document goes through here, so this is the one
  // place that guarantees the views follow. The previous verdict is discarded
  // because it describes a document that no longer exists: keeping it would show
  // a stale BROKEN badge over a chain that was just reset.
  publish({ result: null, badLine: null });
}

/** Read the editor. Throws DenyError — the caller renders it as a stage-1 refusal. */
function readDocument() {
  return parseDocument(docBox.value);
}

function renderGutter(badLine = null) {
  const count = docBox.value.split('\n').length;
  gutter.replaceChildren();
  for (let i = 1; i <= count; i++) {
    const line = el('span', 'g-line', String(i).padStart(4, ' '));
    if (i === badLine) line.classList.add('bad');
    gutter.appendChild(line);
  }
  gutter.scrollTop = docBox.scrollTop;
}

docBox.addEventListener('scroll', () => { gutter.scrollTop = docBox.scrollTop; });
docBox.addEventListener('input', () => publish());

/**
 * ── View bus: one publish, every view fans out ─────────────────────────────
 *
 * There used to be three call sites rendering the same panels from three
 * different shapes — the validation RESULT after a run, a document after a reset
 * with `audit: { entries: 0 }` hardcoded, and nothing at all on a hand-edit. So
 * the roster sat frozen while you typed, and the audit badge read "0 entries"
 * over a document holding three. That is not carelessness at any one call site;
 * it is what having three owners of one view produces.
 *
 * Now there is one state and one publish. Views subscribe and are re-rendered
 * together, so a new panel cannot be added and quietly forgotten: it subscribes
 * or it does not exist. The bus is deliberately tiny — this is a page with four
 * views, not an application, and a framework here would be more machinery than
 * the problem has.
 *
 * The document is read from the EDITOR every time, which is what the panel
 * header claims: "every panel is a view over this JSON". The result is carried
 * alongside for the things a document cannot know about itself — whether the
 * chain it holds actually verified.
 */
const views = [];

/** Subscribe a view. Called once per view at module load. */
function view(name, fn) { views.push({ name, fn }); }

let busState = { document: null, result: null, badLine: null };

/**
 * Publish a change. Any field left out keeps its current value, so a caller that
 * only knows about one part of the state does not have to invent the rest.
 *
 * Parsing is best-effort: the editor is invalid JSON on most keystrokes, and on
 * those the views keep their last good render rather than flickering.
 */
function publish(patch = {}) {
  let doc = busState.document;
  // parseDocument, not a bare JSON.parse. This is a read for DISPLAY, which is
  // exactly the reasoning that let a bare parse onto the export path earlier:
  // the byte cap, the prototype-pollution guard and the depth limit all live in
  // parseDocument, and a second unguarded entrance to the editor is still a
  // second entrance. A document too malformed to validate is also a document
  // whose roster would be misleading to draw.
  try { doc = parseDocument(docBox.value); } catch { /* keep the last good parse */ }
  busState = { ...busState, ...patch, document: doc };
  // Each view is isolated. A fan-out where one failing subscriber takes down the
  // others is worse than no fan-out: the page would half-render with no
  // indication which half is stale. A view that throws is reported and skipped;
  // the rest still draw.
  for (const { name, fn } of views) {
    try {
      fn(busState);
    } catch (err) {
      console.error(`view "${name}" failed to render`, err);
    }
  }
}

// ── Subscribers ───────────────────────────────────────────────────────────

view('gutter', ({ badLine }) => renderGutter(badLine));

view('reference', ({ document: doc, result }) => {
  if (!doc || typeof doc !== 'object') return;
  renderReference({
    chain: Array.isArray(doc.chain) ? doc.chain : [],
    crl: doc.crl ?? { revoked: [], disabled: [] },
    audit: {
      entries: doc.audit?.chain?.length ?? 0,
      chain: doc.audit?.chain ?? [],
      // The head is the last entry's hash. Derived rather than carried, so the
      // strip reads the same before a validation as after one instead of
      // showing "head —" over a chain that plainly has a head.
      head_hash: doc.audit?.chain?.length
        ? doc.audit.chain[doc.audit.chain.length - 1].hash : null,
    },
    error_code: result?.error_code ?? null,
    // Carried so the strip can name WHICH entry broke. Without it renderAudit
    // falls back to "an entry was altered", which is exactly the vagueness the
    // per-entry marker work was undoing.
    stages: result?.stages ?? [],
  });
});

view('pipeline', ({ result }) => renderPipeline(result));



/**
 * Scroll to a line and select it — the pattern from the code reviewer UI:
 * native selection rather than an overlay, and the target placed two lines from
 * the top so there is context above it.
 */
function revealLine(lineNumber) {
  const range = lineRange(docBox.value, lineNumber);
  if (!range) return;
  docBox.focus();
  docBox.setSelectionRange(range.start, range.end);
  scrollLineIntoView(lineNumber, { always: true });
  publish({ badLine: lineNumber });
}

/**
 * Bring a line into view WITHOUT taking focus or moving the caret.
 *
 * Validation needs this and a deliberate click does not. Clicking a log row is
 * the visitor asking to go somewhere, so `revealLine` selects the text and
 * takes focus. Pressing Validate is not that request — but marking a line the
 * visitor cannot see is worse than not marking one, because the banner says
 * DENIED and the marker points at nothing on screen. Measured before this
 * existed: scroll to the top, escalate a scope, press Validate, and the marker
 * landed on line 68 while the editor was showing lines 1 to 28.
 *
 * Scrolls only when the line is genuinely off-screen, so re-validating a
 * document whose failure is already visible does not jump the view out from
 * under someone mid-read.
 */
function scrollLineIntoView(lineNumber, { always = false } = {}) {
  const lh = parseFloat(getComputedStyle(docBox).lineHeight) || 17;
  const y = (lineNumber - 1) * lh;
  if (!always && y >= docBox.scrollTop && y <= docBox.scrollTop + docBox.clientHeight - lh) return;
  docBox.scrollTop = Math.max(0, (lineNumber - 3) * lh);
  gutter.scrollTop = docBox.scrollTop;
}

// ── Rendering ─────────────────────────────────────────────────────────────

/**
 * The nine checks, grouped into five phases.
 *
 * Nine boxes plus two not-applicable ones is eleven units of dense text in a
 * row — technically complete and unreadable at a glance. The phases are the
 * question each group answers, in plain language; the per-stage detail lives in
 * the decision log, which is where someone goes once they want it.
 */
/**
 * What a step says when it denies.
 *
 * Every step but one answers "was this permitted?", so REFUSED is right there:
 * a delegation was refused, a policy was refused. AUDIT CHAIN asks a different
 * question — "is the record intact?" — and nobody requested that the log be
 * broken, it simply is. Answering a question about STATE with a verdict about a
 * REQUEST reads as though detection had failed rather than succeeded, which is
 * the opposite of what a red audit step means.
 */
const DENY_WORD = { 'AUDIT CHAIN': 'BROKEN' };

/**
 * The flow walks the CHAIN, not the check list.
 *
 * "Break the child certificate and see what happens" is the thing people
 * actually do, so the flow answers it directly: TRUST ANCHOR › PARENT › CHILD ›
 * DELEGATION › POLICY › AUDIT, stopping at the first refusal. Grouping by check
 * type instead reported "IDENTITY refused" without saying whose, which is the
 * one detail the person who just edited the child already knows they need.
 *
 * The nine spec stages have not moved — they are still the decision log below,
 * and still the JSON export. This is the map; that is the receipt.
 */
const WALK_ORDER = ['TRUST ANCHOR', 'PARENT AGENT', 'CHILD AGENT',
  'DELEGATION', 'POLICY UPDATE', 'AUDIT CHAIN'];

const WALK_ASKS = {
  'TRUST ANCHOR': 'is the CA sound?',
  'PARENT AGENT': 'who is the parent?',
  'CHILD AGENT': 'who is the child?',
  'DELEGATION': 'was the grant permitted?',
  'POLICY UPDATE': 'who approved the change?',
  'AUDIT CHAIN': 'is the record intact?',
};

function renderPipeline(result) {
  const row = $('pipeline');
  row.replaceChildren();
  const bySubject = new Map((result?.walk ?? []).map((w) => [w.subject, w]));

  WALK_ORDER.forEach((subject, i) => {
    const w = bySubject.get(subject);
    const box = el('div', 'p-box');
    box.classList.add(w?.result === 'PASS' ? 'ok' : w?.result === 'DENY' ? 'err' : 'skip');
    box.appendChild(el('div', 'p-label', `STEP ${i + 1}`));
    box.appendChild(el('div', 'p-name', subject));
    box.appendChild(el('div', 'p-ask', WALK_ASKS[subject]));
    box.appendChild(el('div', 'p-sub',
      w?.result === 'PASS' ? 'VALID' : w?.result === 'DENY' ? (DENY_WORD[subject] ?? 'REFUSED')
        : result ? 'not reached' : '—'));
    if (w?.detail) box.title = w.detail;
    row.appendChild(box);

    if (i < WALK_ORDER.length - 1) {
      const arrow = el('div', 'p-arrow', '\u203A');
      arrow.classList.add(w?.result === 'PASS' ? 'ok' : w?.result === 'DENY' ? 'err' : 'skip');
      row.appendChild(arrow);
    }
  });
}

/**
 * Where in the document a refusal points. The error code implies the field; the
 * detail string carries the offending values, which the locator falls back to.
 */
function failureLocation(result) {
  const code = result.error_code;
  const detail = result?.stages?.find((s) => s.result === 'DENY')?.detail ?? '';
  const quoted = [...detail.matchAll(/[a-z0-9_:-]+:[a-z0-9_:-]+/gi)].map((m) => m[0]);

  const paths = {
    ERR_POLICY_EXCEEDS_TEMPLATE: 'policy_doc.scopes',
    ERR_SPAWN_EXCEEDS_TEMPLATE: 'policy_doc.can_spawn',
    ERR_IMMUTABLE_FIELD: 'policy_doc',
    ERR_UNKNOWN_POLICY_FIELD: 'policy_doc',
    ERR_REQUIRED_FIELD: 'policy_doc',
    ERR_OWNER_MISMATCH: 'policy_doc.owner',
    ERR_ORG_MISMATCH: 'policy_doc.owner',
    ERR_CONTENT_HASH: 'policy_content_hash',
    ERR_POLICY_VERSION: 'version',
    ERR_PA_SIG_MISSING: 'pa_sig',
    ERR_PA_SIG_INVALID: 'pa_sig',
    ERR_OWNER_SIG_MISSING: 'owner_sig',
    ERR_OWNER_SIG_INVALID: 'owner_sig',
    ERR_SINGLE_SIGNATURE: 'owner_sig',
    ERR_AGENT_REVOKED: 'crl.revoked',
    ERR_TTL_EXPIRED: 'chain[2].metadata.expires_at',
    ERR_AGENT_DISABLED: 'chain[2].metadata.state',
    ERR_MAX_CHILDREN: 'chain[1].metadata.max_children',
    ERR_CHILD_NOT_WHITELISTED: 'chain[1].metadata.can_spawn',
    ERR_SCOPE_ESCALATION: 'chain[2].metadata.allowed_scopes',
    ERR_AUDIT_CHAIN_BROKEN: 'audit',
    // §6 certificate checks. Without these a refusal marks nothing at all,
    // which is how the basicConstraints and digest checks shipped: they deny
    // correctly and pointed at no line.
    ERR_MALFORMED_PEM: 'chain[2].cert_pem',
    ERR_KEY_TOO_SMALL: 'chain[2].cert_pem',
    ERR_BASIC_CONSTRAINTS: 'chain[2].cert_pem',
    ERR_WEAK_SIGNATURE: 'chain[2].cert_pem',
    ERR_AGENT_ID_FORMAT: 'chain[2].metadata.agent_id',
    ERR_TIMESTAMP_FORMAT: 'chain[2].metadata.expires_at',
    ERR_CHAIN_INVALID: 'chain[2].cert_pem',
    ERR_FORGED_ISSUER: 'chain[2].cert_pem',
    ERR_SELF_SIGNED: 'chain[2].cert_pem',
    ERR_CERT_EXPIRED: 'chain[2].cert_pem',
    ERR_SUBJECT_MISMATCH: 'chain[2].metadata.agent_id',
    ERR_NAME_CONSTRAINT: 'chain[2].cert_pem',
    ERR_UNKNOWN_CRITICAL_EXT: 'chain[2].cert_pem',
    ERR_AUTHORITY_CHAIN: 'authorities',
    ERR_BOUNDS_UNPARSEABLE: 'chain[2].metadata.authorization_bounds',
    ERR_EMPTY_SCOPES: 'chain[2].requested_scopes',
  };
  let path = paths[code] ?? null;

  // The audit failure knows WHICH entry broke, so point at that entry rather
  // than at the `audit` container. "entry 0 content was altered" with a marker
  // on the enclosing object is technically correct and useless on a long chain:
  // the visitor still has to find the entry themselves.
  if (code === 'ERR_AUDIT_CHAIN_BROKEN') {
    const idx = /entry (\d+)/.exec(detail);
    if (idx) path = `audit.chain[${idx[1]}]`;
  }

  // Codes with no path are deliberate, not oversights: ERR_MALFORMED_JSON,
  // ERR_DOCUMENT_TOO_LARGE and ERR_INTERNAL are properties of the document as a
  // whole, and ERR_SCHEMA_VIOLATION / ERR_FIELD_CHARSET / ERR_FIELD_RANGE can
  // fire on any of a dozen fields. Guessing one would point confidently at the
  // wrong line, which is worse than pointing at none.
  return { path, values: quoted };
}

/**
 * Section titles from the published draft, so a clause reference explains itself.
 *
 * "§6.1" on its own tells a visitor nothing. The reference is the whole point of
 * the page -- the tool refuses something and names the clause -- so leaving it as
 * an opaque number asks the reader to go and look it up, which nobody does.
 *
 * Generated from the -02 text rather than typed: -02 inserted sections, which
 * renumbered everything after them, and the code was still citing -01 positions.
 * ERR_AUDIT_CHAIN_BROKEN pointed at §16.6, which in -02 is "PKI Does Not Enforce
 * Authorization" rather than "Audit Integrity" -- a confidently wrong citation,
 * which is worse than a missing one.
 */
const SECTION_TITLES = {
  '6': 'Agent Identity',
  '6.1': 'Certificate Profile',
  '6.2': 'Certificate Signing Request Flow',
  '7': 'Template Structure',
  '7.2': 'Dynamic Policy Bounds',
  '8.1': 'Two-Check Spawn Rule',
  '8.3': 'Scope Constraint',
  '9': 'Dynamic Policy Governance',
  '9.2': 'Ownership',
  '9.3': 'Dual Signature Requirement',
  '9.4': 'Dynamic Policy Document Structure',
  '9.6': 'Signature and Hash Coverage',
  '10.4': 'Template Lifecycle',
  '12': 'Revocation',
  '12.3': 'Automation Requirement',
  '13.1': 'Fail Closed',
  '16.1': 'Scope Escalation',
  '16.2': 'Replay Attacks',
  '16.6': 'PKI Does Not Enforce Authorization',
  '16.7': 'Audit Integrity'
};

/** Deep link into the published draft, opened in one reused tab. */
const DRAFT_HTML = 'https://www.ietf.org/archive/id/draft-tonyai-a2a-trust-02.html';

/**
 * A clause reference: the number, its title on hover, and a link to the text.
 *
 * `target` is a NAMED window, not `_blank`. The first click opens a tab; every
 * later click navigates that same tab to the new anchor instead of leaving a
 * trail of them behind.
 */
function sectionRef(section, cls = 'sec') {
  if (!section) return el('span', cls, '\u2014');
  const title = SECTION_TITLES[section];
  const a = el('a', cls, `\u00A7${section}`);
  a.href = `${DRAFT_HTML}#section-${section}`;
  a.target = 'a2a-draft';
  a.rel = 'noopener';
  a.title = title
    ? `\u00A7${section} ${title} \u2014 opens the draft`
    : `\u00A7${section} \u2014 opens the draft`;
  return a;
}

/** Which phase each modification button exercises, for grouping the controls. */
const PHASES = [
  { name: 'IDENTITY',  asks: 'the certificates themselves' },
  { name: 'STANDING',  asks: 'revocation and lifetime' },
  { name: 'AUTHORITY', asks: 'who approved a policy change' },
  { name: 'BOUNDS',    asks: 'scopes, spawn rights, ceilings' },
  { name: 'AUDIT',     asks: 'the tamper-evident record' },
];

function renderVerdict(result) {
  const banner = $('verdict');
  const inner = $('verdict-inner');
  inner.replaceChildren();
  banner.className = result.verdict === 'PASS' ? 'ok' : 'err';

  if (result.verdict === 'PASS') {
    inner.appendChild(el('div', 'banner-alert', '◈ DELEGATION AUTHORIZED ◈'));
    inner.appendChild(el('div', 'banner-main', 'ALL STAGES PASSED'));
    inner.appendChild(el('div', 'banner-sub', 'AUDIT CHAIN SEALED · SCOPES WITHIN BOUNDS'));
    inner.appendChild(el('div', 'banner-code',
      `${result.audit.head_hash?.slice(0, 16) ?? ''} · ${result.generated_at}`));
  } else {
    const failed = result.stages.find((s) => s.result === 'DENY');
    inner.appendChild(el('div', 'banner-alert', '⚠ A2A TRUST VIOLATION — REFUSED ⚠'));
    inner.appendChild(el('div', 'banner-main', 'DENIED'));
    inner.appendChild(el('div', 'banner-sub', (failed?.detail ?? '').toUpperCase()));
    // The most screenshot-able element on the page.
    inner.appendChild(el('div', 'banner-code', `${result.banner} · ${result.generated_at}`));
  }
}

function renderLog(result) {
  const log = $('log');
  log.replaceChildren();

  // Show all nine, always. A stage that never ran because an earlier one
  // refused is SKIPPED — rendering only the stages that executed leaves gaps in
  // the numbering, and a reader cannot tell a skipped check from a forgotten
  // one. Fail-closed applies to the explanation too.
  const byNumber = new Map(result.stages.map((s) => [s.n, s]));
  const rows = [];
  for (let n = 1; n <= 9; n++) {
    rows.push(byNumber.get(n) ?? {
      n, check: STAGE_NAMES[n], section: null, result: 'SKIPPED',
      detail: 'not reached — an earlier stage refused',
    });
  }
  // Anything the pipeline recorded outside 1..9 (a parse failure, say).
  for (const s of result.stages) if (s.n < 1 || s.n > 9) rows.push(s);

  for (const stage of rows) {
    const cls = stage.result === 'PASS' ? 'pass' : stage.result === 'DENY' ? 'deny' : 'na';
    const row = el('div', `log-row ${cls}`);
    row.appendChild(el('span', 'ln', String(stage.n)));
    row.appendChild(sectionRef(stage.section));
    row.appendChild(el('span', 'res', stage.result));
    row.appendChild(el('span', 'detail', stage.detail));

    if (stage.result === 'DENY') {
      // Clicking a refusal jumps to the field, and marks the row active — the
      // bidirectional link the code reviewer UI uses.
      row.addEventListener('click', () => {
        for (const other of log.querySelectorAll('.log-row.active')) other.classList.remove('active');
        row.classList.add('active');
        const line = locateFailure(docBox.value, failureLocation(result));
        if (line) revealLine(line);
      });
      row.title = 'jump to the field this refusal is about';
    }
    log.appendChild(row);
  }

  for (const na of NOT_APPLICABLE) {
    const row = el('div', 'log-row na');
    row.appendChild(el('span', 'ln', '—'));
    row.appendChild(sectionRef(na.section));
    row.appendChild(el('span', 'res', 'N/A'));
    row.appendChild(el('span', 'detail', `${na.check.replace(/_/g, ' ')} — ${na.reason}`));
    log.appendChild(row);
  }
}


function renderAudit(result, container) {
  const broken = result?.error_code === 'ERR_AUDIT_CHAIN_BROKEN';
  if (!result) {
    container.appendChild(el('div', 'audit-strip',
      'no audit entries yet — press Validate to append one'));
    return;
  }
  const strip = el('div', `audit-strip ${broken ? 'broken' : 'valid'}`);
  strip.appendChild(el('span', `dot ${broken ? 'red' : 'green'}`));
  strip.appendChild(el('span', null, broken
    ? `HASH CHAIN BROKEN — ${result.stages?.find((s) => s.result === 'DENY')?.detail ?? 'an entry was altered'}`
    : `HASH CHAIN VALID · ${result?.audit?.entries ?? 0} entr${(result?.audit?.entries ?? 0) === 1 ? 'y' : 'ies'} · head ${result?.audit?.head_hash?.slice(0, 16) ?? '—'}`));
  container.appendChild(strip);

  const head = el('div', 'audit-row head');
  for (const [cls, label] of [['ln', '#'], ['when', 'Timestamp · UTC'], ['res', 'Decision'],
    ['detail', 'Action'], ['who', 'Agent'], ['rel', 'Relationship'],
    ['hash', 'Links to'], ['hash', 'Hash']]) {
    head.appendChild(el('span', cls, label));
  }

  // The table is ~1130px of fixed columns. On a phone that is three times the
  // container, and with overflow visible it did not scroll and the page did not
  // either -- Agent, Relationship, Links to and Hash were simply unreachable,
  // with nothing on screen to say they existed. An audit panel that hides its
  // own hashes is the wrong failure for the one view whose job is proof.
  //
  // The header goes in the SAME scroller as the rows: two scrollers desync and
  // the labels drift off their columns, which is the bug this just fixed at
  // desktop width.
  const scroller = el('div', 'audit-scroll');
  scroller.appendChild(head);

  // One row per entry: who, what was decided, and the hash that seals it.
  //
  // The Agent and Parent columns are here because the separate roster panel was
  // removed. That panel rendered from the last validation and then sat there, so
  // editing a scope left it reporting the old value — a view that disagrees with
  // the document it claims to show. Identity belongs on the record that is
  // actually tamper-evident, not on a second table that can drift from it.
  // Full identities, not truncated. There is room for them here, and an audit
  // log whose whole purpose is attribution should not make you hover to find out
  // who did something. CSS ellipsis handles narrow viewports.
  const idCell = (value, full) => {
    const span = el('span', 'who mono', value ?? '');
    if (full) span.title = full;
    return span;
  };

  // Where each agent sits in the chain, read from the document rather than from
  // the event. An event knows it spawned a child; it does not know whether the
  // agent it names is itself somebody's child, and that is the question the
  // column answers. An id the document no longer contains reports nothing rather
  // than guessing.
  const relationship = new Map();
  for (const node of result?.chain ?? []) {
    if (node.role !== 'agent') continue;
    const id = node.metadata?.agent_id;
    if (id) relationship.set(id, node.metadata?.parent_agent_id ? 'child' : 'parent');
  }

  // Full date and time, UTC. An audit record is read later, often much later,
  // and a bare wall-clock time is ambiguous the moment the log outlives the
  // session that produced it. The seeded entries are also backdated relative to
  // each other, which only reads correctly with a date attached.
  const clock = (iso) => {
    const d = new Date(iso);
    return Number.isNaN(d.getTime()) ? '' : d.toISOString().slice(0, 19).replace('T', ' ');
  };

  const list = el('div', 'audit-list');
  for (const b of result?.audit?.chain ?? []) {
    const row = el('div', 'audit-row');
    row.appendChild(el('span', 'ln', String(b.index)));
    row.appendChild(el('span', 'when mono', clock(b.timestamp)));
    row.appendChild(el('span', `res ${b.event?.decision === 'DENIED' ? 'bad' : 'ok'}`,
      b.event?.decision ?? '—'));
    // Always say WHAT was attempted, then why it was refused. This used to
    // render `reason ?? action`, so a denied row showed only the error code and
    // the action vanished — "DENIED  ERR_AUDIT_CHAIN_BROKEN" reads as though the
    // error code is the thing that was denied. Every other row names an action,
    // so the one row that did not was the confusing one.
    const detail = el('span', 'detail', b.event?.action ?? '—');
    if (b.event?.reason) {
      detail.appendChild(el('span', 'why', ` · ${b.event.reason}`));
    } else if (b.event?.detail) {
      // The seeded events carry a description of what happened and it was never
      // rendered. On an ALLOWED row there is no reason to show, so this is the
      // column's natural content rather than empty space.
      detail.appendChild(el('span', 'note', ` · ${b.event.detail}`));
    }
    row.appendChild(detail);

    // A run-level entry names every agent it covered rather than a single one,
    // so it reports the count with the full list on hover instead of silently
    // showing the first.
    const agents = Array.isArray(b.event?.agents) ? b.event.agents : null;
    row.appendChild(agents
      ? idCell(`${agents.length} agents`, agents.join('\n'))
      : idCell(b.event?.agent, b.event?.agent));

    // A run-level entry covers the whole chain, so it has no single role.
    const rel = agents ? 'whole chain' : (relationship.get(b.event?.agent) ?? '');
    const relCell = el('span', `rel ${rel === 'child' ? 'is-child' : rel === 'parent' ? 'is-parent' : ''}`, rel);
    if (rel === 'child' && b.event?.parent) relCell.title = `parent: ${b.event.parent}`;
    row.appendChild(relCell);

    // The link back. A panel that asserts HASH CHAIN VALID while hiding the
    // links is asking to be taken on trust — the whole point of the structure is
    // that entry N carries entry N-1's hash, and you should be able to read that
    // off the table rather than believe it.
    const prev = String(b.previous_hash ?? '');
    row.appendChild(el('span', 'hash prev',
      prev === 'genesis' ? 'genesis' : `${prev.slice(0, 16)}…`));
    const hashCell = el('span', 'hash', `${String(b.hash).slice(0, 16)}…`);
    hashCell.title = String(b.hash);
    row.appendChild(hashCell);
    list.appendChild(row);
  }
  scroller.appendChild(list);
  container.appendChild(scroller);
}

/**
 * Reference pane. Roster, audit chain, certificate properties and stated limits
 * are all things you consult AFTER a result, never things you act on — so they
 * sit behind tabs instead of competing with the panes you actually use.
 */
let refTab = 'audit';

function renderReference(result) {
  referenceView = result;
  const tabs = $('ref-tabs');
  const body = $('ref-body');
  tabs.replaceChildren(); body.replaceChildren();

  const broken = result?.error_code === 'ERR_AUDIT_CHAIN_BROKEN';
  const entries = result?.audit?.entries ?? 0;
  const defs = [
    { id: 'audit', label: 'Audit chain',
      badge: broken ? 'BROKEN' : `${entries} entr${entries === 1 ? 'y' : 'ies'}`,
      cls: broken ? 'bad' : 'ok' },
    { id: 'certs', label: 'Certificate properties', badge: '', cls: '' },
  ];

  for (const d of defs) {
    const t = el('button', `ref-tab${d.id === refTab ? ' active' : ''}`);
    t.appendChild(document.createTextNode(d.label));
    t.appendChild(el('span', `badge ${d.cls}`, d.badge));
    t.addEventListener('click', () => { refTab = d.id; renderReference(referenceView); });
    tabs.appendChild(t);
  }

  if (refTab === 'audit') renderAudit(result, body);
  else renderCerts(body);
}

const CERT_FACTS = [
  ['VALID', 'green', 'Genuinely well-formed X.509. openssl verify returns OK for the whole chain. '
    + 'That is deliberate — the round-trip proof against the reference implementation depends on '
    + 'these being real certificates, not mock-ups.'],
  ['NOT TRUSTED', 'red', 'The CA is generated in this tab and exists in nobody\u2019s trust store, so no '
    + 'real relying party accepts it. Nothing here chains to a public root.'],
  ['NOT REPURPOSABLE', 'red', 'Even if someone deliberately imported this CA, its critical nameConstraints '
    + 'means it can only ever issue for OU=DEMO ONLY - NOT FOR PRODUCTION. Anything else is refused by any '
    + 'compliant validator \u2014 error 47: permitted subtree violation.'],
  ['NOT MODIFIABLE', 'red', 'The signature covers the tbsCertificate bytes, so any edit breaks it. Change one '
    + 'character of a certificate in the editor and the IDENTITY phase refuses the chain.'],
];

function renderCerts(body) {
  const grid = el('div', 'inert-grid');
  for (const [head, dot, text] of CERT_FACTS) {
    const item = el('div', 'inert-item');
    const h = el('div', 'inert-head');
    h.appendChild(el('span', `dot ${dot}`));
    h.appendChild(document.createTextNode(head));
    item.appendChild(h);
    item.appendChild(el('div', 'inert-body', text));
    grid.appendChild(item);
  }
  body.appendChild(grid);
}

/*
 * There is deliberately no "stated limits" panel.
 *
 * DESIGN.md asked for one, and it was built: six lines, every one beginning
 * "No" or "Not". Read together, with nothing positive beside them, they made a
 * page that had just demonstrated nine working checks read as a toy. Honesty
 * that costs the reader their trust in true statements is bad honesty.
 *
 * The information did not go away, it moved to where each piece belongs:
 *
 *   · The two checks the playground genuinely does not implement — §16.2 replay
 *     prevention and §9 Cedar evaluation — appear as N/A rows INLINE in the
 *     decision log, at the point in the run where each would have executed.
 *     That is contextual and unmissable, and it cannot be mistaken for an
 *     apology because it sits beside eight checks that did run.
 *
 *   · The rest were never unimplemented checks. Single trust anchor, in-memory
 *     CRL, "not an interoperability test", placeholder OID — those are
 *     architecture and scope notes about a browser demo. They belong in the
 *     README, where someone evaluating the implementation is already reading.
 */

function renderFooter() {
  const f = $('footer');
  f.replaceChildren();
  f.appendChild(el('div', null,
    // The claim "there is no reset button because refresh is the reset" was true
    // when written and stopped being true the moment Reset Certs and Reset the
    // audit chain existed. A privacy footer that states something a visitor can
    // see is false undermines the claims beside it that they cannot check.
    'Nothing is transmitted. No cookies, no localStorage, no analytics identifiers. '
    + 'Keys are generated in this tab by Web Crypto and never leave it. Reset Certs mints a '
    + 'fresh chain and Reset the audit chain rebuilds the log; refreshing discards '
    + 'everything, keys included.'));
  const line = el('div');
  line.appendChild(document.createTextNode(`${DRAFT} · build ${VERSION} · © ${new Date().getUTCFullYear()} `));
  const a = el('a', null, 'PhalanxAI Security');
  a.href = 'https://phalanxaisec.com';
  a.target = '_blank';
  a.rel = 'noopener';
  line.appendChild(a);
  line.appendChild(document.createTextNode(' · '));
  // The licence is a link, not a word. The page's argument is that the
  // validation logic is readable and worth reusing, and someone acting on that
  // should not have to go and guess the terms.
  const lic = el('a', null, 'Apache-2.0');
  lic.href = 'https://github.com/tonyt68/a2a-trust-playground/blob/main/LICENSE';
  lic.target = '_blank';
  lic.rel = 'noopener';
  line.appendChild(lic);
  f.appendChild(line);
  $('build-stamp').textContent = VERSION;
}

// ── Verify ────────────────────────────────────────────────────────────────

async function verify() {
  let result;
  try {
    const parsed = readDocument();
    result = await runPipeline({ document: parsed, version: VERSION });
  } catch (error) {
    // A document that will not even parse is a stage-1 refusal, rendered
    // through exactly the same path as any other. No special-case error UI.
    const deny = error instanceof DenyError ? error : new DenyError('ERR_INTERNAL', 'could not read the document');
    result = {
      playground_version: VERSION, draft: DRAFT, generated_at: new Date().toISOString(),
      demo_only: true, verdict: 'DENY', error_code: deny.code, draft_section: deny.section,
      banner: deny.banner,
      stages: [{ n: 1, check: 'document_parse', section: deny.section, result: 'DENY', detail: deny.detail || deny.title }],
      not_applicable: [], chain: [], authorities: {}, crl: { revoked: [], disabled: [] },
      audit: { entries: 0, head_hash: null, chain_valid: true, chain: [] },
    };
  }

  lastResult = result;

  // Write the audit chain back into the document. §16.6 describes an
  // accumulating record of decisions; without this the chain resets every
  // verify, and "alter an audit entry" has nothing to alter. Done by surgical
  // edit rather than re-serialising the whole document, so a verify never
  // silently reformats what the visitor typed.
  if (result.audit?.chain?.length) {
    try {
      const current = readDocument();
      current.audit = { chain: result.audit.chain };
      setDocument(current, { keepScroll: true });
    } catch { /* unparseable document: nothing to write back into */ }
  }

  renderVerdict(result);
  renderLog(result);
  publish({ result });

  // Mark the offending line AND bring it on screen, without stealing focus.
  const line = result.verdict === 'DENY'
    ? locateFailure(docBox.value, failureLocation(result)) : null;
  publish({ badLine: line, result });
  if (line) scrollLineIntoView(line);
  return result;
}

// ── Sabotage ──────────────────────────────────────────────────────────────

const agents = (d) => (d.chain ?? []).filter((n) => n.role === 'agent');
const childOf = (d) => agents(d).find((n) => n.metadata?.parent_agent_id) ?? agents(d)[1];
const parentOf = (d) => agents(d).find((n) => !n.metadata?.parent_agent_id) ?? agents(d)[0];

/**
 * Every sabotage is a pure function from document to document. The runner
 * applies it, writes the result into the editor, scrolls to the change, and
 * verifies — so the mechanism is always visible.
 */

/**
 * Modifications the draft ALLOWS.
 *
 * Every other button here produces a refusal, which by itself teaches only that
 * a wall exists. These show where the wall actually is: narrowing is fine,
 * widening is not; a dual-signed policy inside the ceiling applies, the same
 * policy one scope wider does not. The boundary is the lesson, not the wall.
 */
const ALLOWED = [
  { phase: 'AUDIT', label: 'Reset the audit chain', section: '16.6', apply: async (d) => {
      // A repair, not a modification. `Reset Certs` also fixes a broken chain,
      // but it throws away every other edit with it — so if you have narrowed a
      // scope, re-signed a policy and THEN broken the audit log, the only way
      // back was to lose all of it and start over.
      //
      // Rebuilds from the same seedAuditChain the default uses, rather than a
      // second copy of that logic, so a chain rebuilt here verifies exactly as
      // the seeded one does.
      const agents = (d.chain ?? []).filter((n) => n.role === 'agent');
      const child = agents.find((n) => n.metadata?.parent_agent_id);
      const parent = agents.find((n) => !n.metadata?.parent_agent_id);
      const chain = await seedAuditChain({
        parentId: parent?.metadata?.agent_id,
        childId: child?.metadata?.agent_id,
      });
      d.audit = chain.toJSON();
      return 'audit'; } },
  { phase: 'BOUNDS', label: 'Narrow the parent to read-only', section: '8.3', apply: (d) => {
      // Drop write:events from the PARENT. The child holds read:events, so the
      // delegation is still a subset and the chain still validates. Narrowing is
      // always permitted; only widening is refused.
      //
      // Note what is NOT here: narrowing to an EMPTY scope set. §16.1 requires
      // an agent to declare intent, so an empty set is refused
      // (ERR_EMPTY_SCOPES) — "less" is allowed, "none" is not.
      const p = parentOf(d);
      p.metadata.allowed_scopes = ['read:events'];
      p.metadata.authorization_bounds.allowed_scopes = ['read:events'];
      return 'chain[1].metadata.allowed_scopes'; } },

  { phase: 'BOUNDS', label: 'Policy: revoke write access', section: '7.2', apply: async (d) => {
      // A dual-signed policy update that REMOVES authority. Inside the ceiling,
      // so it applies — the same edit one scope wider is refused by §7.2.
      d.policy_doc.scopes = [];
      // §9.6: the version is inside the signed document now, so bumping it
      // requires re-signing — which is exactly the property that closes the
      // replay, and is visible here as an extra step the attacker cannot take.
      d.policy_doc.version = (d.policy_doc.version ?? 1) + 1;
      d.policy_content_hash = await policyContentHash(d.policy_doc);
      const paKey = await privateKeyFromPem(d.authorities.pa.key_pem);
      d.pa_sig = await signCanonical(canonicalize(extractPolicyFields(d.policy_doc)), paKey);
      return 'policy_doc.scopes'; } },

  { phase: 'IDENTITY', label: 'Re-issue the child, same bounds', section: '6', apply: async (d) => {
      // A fresh certificate for the same identity. The chain still verifies —
      // identity is the UUID, not the certificate.
      const c = childOf(d);
      const fresh = await mintChain({ agentIds: [c.metadata.agent_id] });
      // Re-issue under the EXISTING trust anchor, not the new one.
      const ca = d.chain.find((n) => n.role === 'ca');
      const reissued = await mintChain({ agentIds: [c.metadata.agent_id] });
      c.cert_pem = reissued.agents[0].cert_pem;
      c.key_pem = reissued.agents[0].key_pem;
      ca.cert_pem = reissued.ca.cert_pem;
      ca.key_pem = reissued.ca.key_pem;
      // The parent and the authorities must chain to the same anchor.
      const p = parentOf(d);
      const all = await mintChain({ agentIds: [p.metadata.agent_id, c.metadata.agent_id] });
      ca.cert_pem = all.ca.cert_pem; ca.key_pem = all.ca.key_pem;
      p.cert_pem = all.agents[0].cert_pem; p.key_pem = all.agents[0].key_pem;
      c.cert_pem = all.agents[1].cert_pem; c.key_pem = all.agents[1].key_pem;
      d.authorities.owner.cert_pem = all.authorities.owner.cert_pem;
      d.authorities.owner.key_pem = all.authorities.owner.key_pem;
      d.authorities.pa.cert_pem = all.authorities.pa.cert_pem;
      d.authorities.pa.key_pem = all.authorities.pa.key_pem;
      // Both signatures were made by the OLD authority keys; redo them.
      const ownerKey = await privateKeyFromPem(all.authorities.owner.key_pem);
      const paKey = await privateKeyFromPem(all.authorities.pa.key_pem);
      d.owner_sig = await signCanonical(
        canonicalize(extractIdentityFields(d.existing_cert)), ownerKey);
      d.pa_sig = await signCanonical(
        canonicalize(extractPolicyFields(d.policy_doc)), paKey);
      return 'chain[2].cert_pem'; } },
];

const SABOTAGE = [
  { phase: 'STANDING', label: 'Revoke the parent', section: '12', apply: (d) => {
      d.crl.revoked.push(parentOf(d).metadata.agent_id); return 'crl.revoked'; } },
  { phase: 'IDENTITY', label: 'Disable the agent', section: '10.4', apply: (d) => {
      childOf(d).metadata.state = 'DISABLED'; return 'chain[2].metadata.state'; } },
  { phase: 'STANDING', label: 'Expire the cert', section: '12.3', apply: (d) => {
      childOf(d).metadata.expires_at = '2020-01-02T00:00:00Z'; return 'chain[2].metadata.expires_at'; } },
  { phase: 'BOUNDS', label: 'Escalate the scope', section: '8.3', apply: (d) => {
      const c = childOf(d);
      c.metadata.allowed_scopes = ['admin:all'];
      c.metadata.authorization_bounds.allowed_scopes = ['admin:all'];
      c.requested_scopes = ['admin:all'];
      delete d.policy_update;          // isolate stage 8 from the §7.2 ceiling
      return 'chain[2].metadata.allowed_scopes'; } },
  { phase: 'BOUNDS', label: 'Exceed max_children', section: '7', apply: (d) => {
      const p = parentOf(d);
      p.metadata.max_children = 0;
      p.metadata.authorization_bounds.max_children = 0;
      return 'chain[1].metadata.max_children'; } },
  { phase: 'BOUNDS', label: 'Spawn a non-whitelisted child', section: '8.1', apply: (d) => {
      const p = parentOf(d);
      p.metadata.can_spawn = [];
      p.metadata.authorization_bounds.can_spawn = [];
      return 'chain[1].metadata.can_spawn'; } },
  { phase: 'IDENTITY', label: 'Forge the issuer', section: '6', apply: async (d) => {
      // A genuine forgery, not a corrupted byte: mint a SECOND CA and re-issue
      // the child under it. The certificate is perfectly well-formed and its
      // signature verifies — against the wrong authority. That is the attack
      // §6 actually describes, and it produces ERR_FORGED_ISSUER rather than
      // the ERR_CHAIN_INVALID a flipped byte would give.
      const c = childOf(d);
      const rogue = await mintChain({ agentIds: [c.metadata.agent_id],
        caCommonName: 'Rogue-CA-Not-The-Trust-Anchor' });
      c.cert_pem = rogue.agents[0].cert_pem;
      c.key_pem = rogue.agents[0].key_pem;
      return 'chain[2].cert_pem'; } },
  { phase: 'IDENTITY', label: 'Corrupt the certificate', section: '6', apply: (d) => {
      // The other §6 failure, kept distinct: the bytes no longer match the
      // signature over them.
      const c = childOf(d);
      const lines = c.cert_pem.split('\n');
      const mid = Math.floor(lines.length / 2);
      lines[mid] = lines[mid].startsWith('A') ? `B${lines[mid].slice(1)}` : `A${lines[mid].slice(1)}`;
      c.cert_pem = lines.join('\n');
      return 'chain[2].cert_pem'; } },
  { phase: 'BOUNDS', label: 'Widen policy past the ceiling', section: '7.2', apply: async (d) => {
      // Re-sign and re-hash after widening. Otherwise this only demonstrates
      // that editing a signed document breaks its signature — which is stage 4's
      // job, not §7.2's.
      //
      // The point of §7.2 is stronger and stranger: the Owner and the Policy
      // Authority BOTH legitimately signed this, every signature verifies, the
      // content hash matches, the submitter is the real owner — and it is still
      // refused, because a dynamic policy cannot grant beyond the static
      // template. Two valid signatures do not raise the ceiling.
      d.policy_doc.scopes = ['admin:all'];
      d.policy_content_hash = await policyContentHash(d.policy_doc);
      const paKey = await privateKeyFromPem(d.authorities.pa.key_pem);
      d.pa_sig = await signCanonical(canonicalize(extractPolicyFields(d.policy_doc)), paKey);
      return 'policy_doc.scopes'; } },
  { phase: 'AUTHORITY', label: 'Sign with one key only', section: '9.3', apply: (d) => {
      d.pa_sig = null; return 'pa_sig'; } },
  { phase: 'AUTHORITY', label: 'Tamper with the policy doc', section: '9.3', apply: async (d) => {
      // An attacker who edits a stored policy also recomputes its content hash —
      // a hash is not a secret. What they CANNOT do is re-sign, because they do
      // not hold the Policy Authority key. So this lands on ERR_PA_SIG_INVALID
      // rather than ERR_CONTENT_HASH, which is the point §9.3 is making.
      d.policy_doc.issued_at = new Date(Date.now() + 86_400_000).toISOString();
      d.policy_content_hash = await policyContentHash(d.policy_doc);
      return 'policy_doc.issued_at'; } },
  { phase: 'AUTHORITY', label: 'Replay an old policy, bump version', section: '9.6', apply: (d) => {
      // The attack -02 was written to close. Under -01 the version travelled on
      // the envelope, outside the signed preimage, so an attacker holding no key
      // could take a superseded but validly signed policy, increment one
      // integer, and have it accepted: both signatures verified, the content
      // hash matched, and the version read as current.
      //
      // §9.6 moved the version inside the signature. The same edit now breaks
      // pa_sig, because the attacker cannot re-sign what they have changed.
      d.current_policy_version = 5;
      d.policy_doc.version = 6;
      return 'policy_doc.version'; } },
  { phase: 'AUTHORITY', label: 'Alter the stored hash only', section: '9.4', apply: (d) => {
      d.policy_content_hash = '0'.repeat(64); return 'policy_content_hash'; } },
  { phase: 'AUTHORITY', label: 'Edit can_spawn via policy', section: '9.3', apply: (d) => {
      d.policy_doc.can_spawn = []; return 'policy_doc.can_spawn'; } },
  { phase: 'AUTHORITY', label: 'Submit as the wrong owner', section: '9.2', apply: (d) => {
      d.policy_doc.owner = 'attacker@example.com'; return 'policy_doc.owner'; } },
  { phase: 'AUDIT', label: 'Alter an audit entry', section: '16.6', apply: (d) => {
      if (!d.audit?.chain?.length) return null;
      // Idempotent on purpose. This used to FLIP `decision` to whatever it was
      // not, which made a second press restore the original content, recompute
      // to the same hash, and repair the chain — a red button that fixed things
      // when pressed twice, unlike every other sabotage here.
      //
      // Writing a fixed value instead means pressing it again leaves the chain
      // exactly as broken as it already was. `Reset Certs` is the way back, the
      // same as for every other red button.
      const entry = d.audit.chain[0];
      entry.event.detail = 'record altered after the block was sealed';
      return 'audit'; } },
];

async function runSabotage(entry) {
  let doc;
  try { doc = readDocument(); } catch { await verify(); return; }

  const path = await entry.apply(doc);
  setDocument(doc);

  // Show the change BEFORE the verdict — the point is seeing what moved.
  if (path) {
    const line = locateFailure(docBox.value, { path, values: [] });
    if (line) revealLine(line);
  }
  await verify();
}

// ── Controls ──────────────────────────────────────────────────────────────

function button(label, cls, tag, onClick) {
  const b = el('button', `admin-btn ${cls}`);
  b.appendChild(document.createTextNode(label));
  if (tag) { b.appendChild(el('br')); b.appendChild(el('span', 'sec-tag', tag)); }
  b.addEventListener('click', async () => {
    setBusy(true);
    try { await onClick(); } finally { setBusy(false); }
  });
  return b;
}

/** Disable every control while an async action is in flight. */
function setBusy(busy) {
  for (const b of document.querySelectorAll('.admin-btn')) b.disabled = busy;
}

async function loadDefaults() {
  // The buttons are only disabled by the click wrapper, so the INITIAL seed on
  // page load left them live for the ~200ms of key generation: the page looked
  // ready while the editor was still empty, and clicking Validate in that window
  // returned ERR_MALFORMED_JSON against a blank document. Found by the E2E suite
  // on its first run.
  setBusy(true);
  $('editor-hint').textContent = 'minting a fresh chain…';
  const doc = await buildDefaultDocument();
  setDocument(doc);
  $('editor-hint').textContent = 'every panel is a view over this JSON';
  // Deliberately NOT validated here. The page should not announce a verdict the
  // visitor did not ask for — "ALL STAGES PASSED" on arrival is indistinguishable
  // from a hardcoded banner. Seed it, then let them press Validate and watch the
  // checks actually run.
  lastResult = null;
  renderIdle('A fresh chain is loaded and has NOT been validated — press Validate.', doc);
  window.scrollTo({ top: 0 });
  setBusy(false);
}

/** The un-validated state: everything grey, nothing claimed. */
function renderIdle(message, doc) {
  const banner = $('verdict');
  const inner = $('verdict-inner');
  banner.className = 'idle';
  inner.replaceChildren();
  inner.appendChild(el('div', 'banner-main', 'NOT VALIDATED'));
  inner.appendChild(el('div', 'banner-sub', message));
  $('log').replaceChildren();
  // The agents exist, they just have not been checked yet. Published like
  // everything else so the audit badge reflects the real chain rather than a
  // hardcoded zero.
  publish({ result: null });
}

/**
 * The only export. No download, no Blob, no <a download>, nothing to disk.
 *
 * The promise is awaited and its rejection handled: `writeText` fails in an
 * insecure context and when the browser withholds clipboard permission, and the
 * previous version ignored both — the button would look like it had worked while
 * nothing reached the clipboard. Silent failure on the page's only export is
 * exactly the kind of thing this tool exists to argue against.
 *
 * Falls back to selecting the document so the visitor can copy it themselves,
 * which is worse but honest.
 */
async function copyJson(button) {
  // `parseDocument`, never a bare `JSON.parse`. The editor is the only input this
  // page has, and every check that makes it safe — the byte cap applied before
  // parsing, the prototype-pollution key guard, the depth limit — lives in
  // `parseDocument`. Exporting is still a read of that input, so it goes through
  // the same door as validation. A raw parse here would have been a second,
  // unguarded entrance to the same room.
  let payload;
  try {
    payload = JSON.stringify(lastResult ?? parseDocument(docBox.value || '{}'), null, 2);
  } catch (err) {
    payload = JSON.stringify({ error: err.code ?? 'ERR_UNPARSEABLE', message: err.message }, null, 2);
  }
  const say = (text, ok) => {
    const tag = button?.querySelector('.sec-tag');
    if (!tag) return;
    tag.textContent = text;
    button.classList.toggle('copied', ok);
    setTimeout(() => {
      tag.textContent = COPY_HINT;
      button.classList.remove('copied');
    }, 2200);
  };
  try {
    await navigator.clipboard.writeText(payload);
    say(`copied \u2713  ${payload.length.toLocaleString()} characters`, true);
  } catch {
    docBox.focus();
    docBox.select();
    say('clipboard blocked — document selected, press \u2318C', false);
  }
}

const COPY_HINT = 'copy the document to your clipboard';

/**
 * Controls, grouped by the SAME five phases as the flow diagram.
 *
 * Twenty-two buttons in one grid is a wall. Grouped under the phase each one
 * exercises, it becomes a map: the flow shows where a chain can fail, and the
 * buttons underneath show what makes it fail there. Allowed and refused
 * modifications sit side by side within a phase, which is the whole point —
 * the boundary is only visible when both halves are in view.
 */
function buildControls() {
  const main = $('controls-main');
  main.replaceChildren();
  main.appendChild(button('Reset Certs', 'primary',
    'mint a fresh valid chain — new keys, new identities', loadDefaults));
  const copy = button('Copy JSON', '', COPY_HINT, () => copyJson(copy));
  main.appendChild(copy);

  // Validate lives in the VALIDATE pane, not with the document actions: it
  // always runs against whatever is on screen right now, so it belongs beside
  // the result it produces rather than beside the things that change the input.
  $('controls-validate').replaceChildren(
    button('Validate', 'primary', 'run all nine checks over the document as it stands', verify));

  const box = $('controls-phases');
  box.replaceChildren();
  for (const phase of PHASES) {
    const allowed = ALLOWED.filter((e) => e.phase === phase.name);
    const refused = SABOTAGE.filter((e) => e.phase === phase.name);
    if (!allowed.length && !refused.length) continue;

    const group = el('div', 'phase-group');
    const head = el('div', 'phase-head');
    head.appendChild(el('span', 'phase-name', phase.name));
    head.appendChild(el('span', 'phase-ask', phase.asks));
    group.appendChild(head);

    const grid = el('div', 'phase-grid');
    for (const e of allowed) {
      grid.appendChild(button(e.label, 'ok', `§${e.section} · stays valid`, () => runSabotage(e)));
    }
    for (const e of refused) {
      grid.appendChild(button(e.label, 'danger', `§${e.section}`, () => runSabotage(e)));
    }
    group.appendChild(grid);
    box.appendChild(group);
  }
}

/*
 * There is no back link.
 *
 * The portfolio card opens this page with target="_blank", so a "back to
 * portfolio" control navigates the NEW tab to the portfolio -- leaving the
 * visitor with two portfolio tabs and the tool gone. It only made sense while
 * the tool replaced the page it was launched from.
 *
 * Closing the tab is the correct way back, and the browser already provides it.
 */

// ── Boot ──────────────────────────────────────────────────────────────────

buildControls();
renderFooter();
publish({ result: null });
loadDefaults();
