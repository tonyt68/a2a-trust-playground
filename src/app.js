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
 * ── Two kinds of button ─────────────────────────────────────────────────────
 *
 * Most buttons edit the document, re-serialise it into the editor, scroll to
 * the line they changed, and only then validate. The visitor sees WHAT changed
 * rather than watching a verdict flip for invisible reasons.
 *
 * The REGISTRY buttons are different: they ask the Registry to attest or issue
 * something it must refuse (§9.1, §9.2, §9.3, §19.2). Nothing is issued, so the
 * document does not change; the refusal is shown as a refusal at issuance.
 */

import { buildDefaultDocument, seedAuditChain, PARENT_TTL_SECONDS } from './defaults.js';
import { Registry, newAgentId, newNonce, FRESHNESS_WINDOW_MS } from './mint.js';
import { KEY_USAGE } from './x509.js';
import { signEnvelope, privateKeyFromPem, contentHash } from './crypto-sign.js';
import {
  childOf, parentOf, templateOf, reissueThroughRegistry, issueRaw, resignPolicy,
  spawnAcrossOrganizations, issueSecondChildWithNonce,
} from './scenarios.js';
import { describeCertificate } from './x509-explain.js';
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

const STAGE_NAMES = {
  1: 'agent_id_format', 2: 'x509_identity', 3: 'revocation', 4: 'dual_signature',
  5: 'policy_field_guard', 6: 'required_fields', 7: 'spawn_rule',
  8: 'scope_subset', 9: 'audit_chain',
};

let referenceView = null;

// ── Editor ────────────────────────────────────────────────────────────────

const docBox = $('doc');
const gutter = $('gutter');

function setDocument(obj, { keepScroll = false } = {}) {
  const top = keepScroll ? docBox.scrollTop : 0;
  docBox.value = JSON.stringify(obj, null, 2);
  docBox.scrollTop = top;
  // Every button that changes the document goes through here, so this is the one
  // place that guarantees the views follow. The previous verdict is discarded
  // because it describes a document that no longer exists.
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
 * One state and one publish. Views subscribe and are re-rendered together, so
 * a new panel cannot be added and quietly forgotten: it subscribes or it does
 * not exist. The document is read from the EDITOR every time, which is what
 * the panel header claims: "every panel is a view over this JSON".
 */
const views = [];
function view(name, fn) { views.push({ name, fn }); }

let busState = { document: null, result: null, badLine: null };

function publish(patch = {}) {
  let doc = busState.document;
  // parseDocument, not a bare JSON.parse: the byte cap, the strict parser, the
  // prototype-pollution guard and the depth limit all live there, and a second
  // unguarded entrance to the editor is still a second entrance.
  try { doc = parseDocument(docBox.value); } catch { /* keep the last good parse */ }
  busState = { ...busState, ...patch, document: doc };
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
    authorities: doc.authorities ?? {},
    crl: doc.crl ?? { revoked: [], disabled: [] },
    audit: {
      entries: doc.audit?.chain?.length ?? 0,
      chain: doc.audit?.chain ?? [],
      head_hash: doc.audit?.chain?.length
        ? doc.audit.chain[doc.audit.chain.length - 1].hash : null,
    },
    error_code: result?.error_code ?? null,
    stages: result?.stages ?? [],
  });
});

view('pipeline', ({ result }) => renderPipeline(result));

/**
 * Scroll to a line and select it — native selection rather than an overlay,
 * and the target placed two lines from the top so there is context above it.
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
 * Bring a line into view WITHOUT taking focus or moving the caret. Scrolls only
 * when the line is genuinely off-screen, so re-validating a document whose
 * failure is already visible does not jump the view out from under someone.
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
 * What a step says when it does not pass. Every step but one answers "was this
 * permitted?", so REFUSED is right there. AUDIT CHAIN asks "is the record
 * intact?" — nobody requested that the log be broken, it simply is.
 */
const DENY_WORD = { 'AUDIT CHAIN': 'BROKEN' };

/**
 * The flow walks the CHAIN, not the check list: TRUST ANCHOR › PARENT › CHILD ›
 * GRANT › POLICY › DELEGATION › AUDIT, in execution order, stopping at the
 * first refusal. The nine
 * spec stages are the decision log below. This is the map; that is the receipt.
 */
const WALK_ORDER = ['TRUST ANCHOR', 'PARENT AGENT', 'CHILD AGENT', 'CROSS-ORG GRANT',
  'POLICY UPDATE', 'DELEGATION', 'AUDIT CHAIN'];

const WALK_ASKS = {
  'TRUST ANCHOR': 'is the CA sound?',
  'PARENT AGENT': 'who is the parent?',
  'CHILD AGENT': 'who is the child?',
  'CROSS-ORG GRANT': 'was a foreign spawn granted?',
  'DELEGATION': 'was the spawn permitted?',
  'POLICY UPDATE': 'who approved the change?',
  'AUDIT CHAIN': 'is the record intact?',
};

const stateClass = (r) => (r === 'PASS' ? 'ok' : r === 'DENY' ? 'err' : r === 'ADVISORY' ? 'warn' : 'skip');

function renderPipeline(result) {
  const row = $('pipeline');
  row.replaceChildren();
  const bySubject = new Map((result?.walk ?? []).map((w) => [w.subject, w]));

  WALK_ORDER.forEach((subject, i) => {
    const w = bySubject.get(subject);
    const box = el('div', 'p-box');
    box.classList.add(stateClass(w?.result));
    box.appendChild(el('div', 'p-label', `STEP ${i + 1}`));
    box.appendChild(el('div', 'p-name', subject));
    box.appendChild(el('div', 'p-ask', WALK_ASKS[subject]));
    box.appendChild(el('div', 'p-sub',
      w?.result === 'PASS' ? 'VALID'
        : w?.result === 'DENY' ? (DENY_WORD[subject] ?? 'REFUSED')
          : w?.result === 'ADVISORY' ? 'ADVISORY'
            : result ? 'not reached' : '—'));
    if (w?.detail) box.title = w.detail;
    row.appendChild(box);

    if (i < WALK_ORDER.length - 1) {
      const arrow = el('div', 'p-arrow', '›');
      arrow.classList.add(stateClass(w?.result));
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
  const failed = result?.stages?.find((s) => s.result === 'DENY');
  const detail = failed?.detail ?? '';
  const quoted = [...detail.matchAll(/[a-z0-9_:-]+:[a-z0-9_:-]+/gi)].map((m) => m[0]);

  // Which certificate a §7 refusal is about, from the walk step that failed.
  const node = failed?.subject === 'PARENT AGENT' ? 'chain[1]'
    : failed?.subject === 'TRUST ANCHOR' ? 'chain[0]' : 'chain[2]';

  const paths = {
    ERR_POLICY_EXCEEDS_TEMPLATE: 'policy.body.scopes',
    ERR_SPAWN_EXCEEDS_TEMPLATE: 'policy.body.spawn_targets',
    ERR_IMMUTABLE_FIELD: 'policy.body',
    ERR_UNKNOWN_POLICY_FIELD: 'policy.body',
    ERR_REQUIRED_FIELD: 'policy.body',
    ERR_ENVELOPE_MEMBER: 'policy',
    ERR_OWNER_MISMATCH: 'policy.body.owner',
    ERR_ORG_MISMATCH: 'policy.body.org_id',
    ERR_SUBJECT_UNKNOWN: 'policy.body.subject',
    ERR_OWNER_CERT_MISMATCH: 'authorities.owner',
    ERR_CONTENT_HASH: 'policy.content_hash',
    ERR_POLICY_VERSION: 'policy.body.version',
    ERR_POLICY_EXPIRED: 'policy.body.not_after',
    ERR_PA_SIG_MISSING: 'policy.pa_sig',
    ERR_PA_SIG_INVALID: 'policy.pa_sig',
    ERR_OWNER_SIG_MISSING: 'policy.owner_sig',
    ERR_OWNER_SIG_INVALID: 'policy.owner_sig',
    ERR_SINGLE_SIGNATURE: 'authorities.pa',
    ERR_SIGNATURE_ALGORITHM: 'policy.owner_sig',
    ERR_AGENT_REVOKED: 'crl.revoked',
    ERR_AGENT_DISABLED: 'crl.disabled',
    ERR_MAX_CHILDREN: 'chain[1].cert_pem',
    ERR_CHILD_NOT_WHITELISTED: 'chain[1].cert_pem',
    ERR_SPAWN_NOT_PERMITTED: 'chain[1].cert_pem',
    ERR_SCOPE_ESCALATION: 'chain[2].cert_pem',
    ERR_EMPTY_SCOPES: 'chain[2].requested_scopes',
    ERR_AUDIT_CHAIN_BROKEN: 'audit',
    ERR_GRANT_MISSING: 'chain[2].cert_pem',
    ERR_GRANT_INVALID: 'grant',
    ERR_GRANT_EXPIRED: 'grant.body.issued_at',
    ERR_GRANT_EXCEEDS_TEMPLATE: 'grant.body.allowed_scopes',
    ERR_MAX_SPAWNS: 'grant.body.max_spawns',
    ERR_AUTHORITY_CHAIN: 'authorities',
    ERR_DUPLICATE_SUBJECT: 'chain[3]',
    ERR_NONCE_REUSED: 'chain[3].cert_pem',
    ERR_PARENT_MISMATCH: `${node}.metadata.parent_agent_id`,
    ERR_AGENT_ID_FORMAT: `${node}.metadata.agent_id`,
    ERR_SUBJECT_MISMATCH: `${node}.metadata.agent_id`,
    ERR_TIMESTAMP_FORMAT: 'policy.body.issued_at',
  };
  let path = paths[code] ?? null;
  // Every §7 / §8.2 / §10.5 / §9.3 refusal is about one certificate's bytes.
  if (!path && (failed?.n === 2 || /^ERR_(MALFORMED_PEM|KEY_TOO_SMALL|BASIC_CONSTRAINTS|WEAK_SIGNATURE|KEY_USAGE|SERIAL_ENTROPY|NO_REVOCATION_SOURCE|TEMPLATE_EXT_|TTL_TOO_LONG|VALIDITY_EXCEEDS_TTL|SPAWN_EXT_INVALID|CHAIN_INVALID|FORGED_ISSUER|SELF_SIGNED|CERT_EXPIRED|NAME_CONSTRAINT|UNKNOWN_CRITICAL_EXT)/.test(code))) {
    path = `${node}.cert_pem`;
  }

  // The audit failure knows WHICH entry broke, so point at that entry.
  if (code === 'ERR_AUDIT_CHAIN_BROKEN') {
    const idx = /entry (\d+)/.exec(detail);
    if (idx) path = `audit.chain[${idx[1]}]`;
  }
  return { path, values: quoted };
}

/**
 * Section titles from the published draft, so a clause reference explains
 * itself on hover. Kept in step with the draft by tests/citations.test.js,
 * which pins every title here to the text.
 */
const SECTION_TITLES = {
  '3': 'Document Encoding',
  '3.1': 'Signature Envelope',
  '7': 'Agent Identity',
  '7.1': 'Certificate Profile',
  '7.2': 'Binding Identity to the Certificate',
  '7.3': 'Certificate Signing Request Flow',
  '8.2': 'Encoding of Static Fields',
  '8.3': 'Dynamic Policy Bounds',
  '9.1': 'Conformance Gate',
  '9.2': 'Dual Attestation',
  '9.3': 'Issuance',
  '10.1': 'Two-Check Spawn Rule',
  '10.2': 'Spawn Validation Sequence',
  '10.3': 'Scope Constraint',
  '10.5': 'Encoding of Spawn Provenance',
  '11.2': 'Ownership',
  '11.3': 'Dual Signature Requirement',
  '11.4': 'Dynamic Policy Document Structure',
  '11.6': 'Signature and Hash Coverage',
  '11.7': 'Policy Change Sequence',
  '12.1': 'Full Re-Verification Required',
  '12.4': 'Template Lifecycle',
  '13.1': 'Explicit Grant Requirement',
  '13.2': 'Grant Structure',
  '14': 'Revocation',
  '14.4': 'Locating Revocation State',
  '15.1': 'Fail Closed',
  '19.2': 'Replay Attacks',
  '19.7': 'Audit Integrity'
};

/** Deep link into the published draft, opened in one reused tab. */
const DRAFT_HTML = 'https://www.ietf.org/archive/id/draft-tonyai-a2a-trust-03.html';

/**
 * A clause reference: the number, its title on hover, and a link to the text.
 * `target` is a NAMED window: the first click opens a tab; every later click
 * navigates that same tab to the new anchor.
 */
function sectionRef(section, cls = 'sec') {
  if (!section) return el('span', cls, '—');
  const title = SECTION_TITLES[section];
  const a = el('a', cls, `§${section}`);
  a.href = `${DRAFT_HTML}#section-${section}`;
  a.target = 'a2a-draft';
  a.rel = 'noopener';
  a.title = title
    ? `§${section} ${title} — opens the draft`
    : `§${section} — opens the draft`;
  return a;
}

/** The groups the buttons fall into, in the order the walk meets them. */
const PHASES = [
  { name: 'REGISTRY',  asks: 'what the Registry refuses to issue — the document is untouched' },
  { name: 'IDENTITY',  asks: 'the certificates themselves' },
  { name: 'STANDING',  asks: 'revocation and the Registry lifecycle' },
  { name: 'GRANT',     asks: 'authority across organizations' },
  { name: 'BOUNDS',    asks: 'scopes, spawn rights, ceilings' },
  { name: 'AUTHORITY', asks: 'who approved a policy change' },
  { name: 'AUDIT',     asks: 'the tamper-evident record' },
];

function renderVerdict(result) {
  const banner = $('verdict');
  const inner = $('verdict-inner');
  inner.replaceChildren();
  banner.className = result.verdict === 'PASS' ? 'ok' : 'err';

  if (result.verdict === 'PASS') {
    const adv = result.advisories?.length ?? 0;
    inner.appendChild(el('div', 'banner-alert', '◈ DELEGATION AUTHORIZED ◈'));
    inner.appendChild(el('div', 'banner-main', 'ALL STAGES PASSED'));
    inner.appendChild(el('div', 'banner-sub', adv
      ? `AUDIT CHAIN SEALED · SCOPES WITHIN BOUNDS · ${adv} ADVISORY (§${result.advisories[0].section}, SHOULD NOT — NOT A REFUSAL)`
      : 'AUDIT CHAIN SEALED · SCOPES WITHIN BOUNDS'));
    inner.appendChild(el('div', 'banner-code',
      `${result.audit.head_hash?.slice(0, 16) ?? ''} · ${result.generated_at}`));
  } else {
    const failed = result.stages.find((s) => s.result === 'DENY');
    const atIssuance = result.refused_at === 'issuance';
    inner.appendChild(el('div', 'banner-alert', atIssuance
      ? '⚠ REFUSED AT ISSUANCE — NOTHING WAS MINTED ⚠'
      : '⚠ A2A TRUST VIOLATION — REFUSED ⚠'));
    inner.appendChild(el('div', 'banner-main', atIssuance ? 'NOT ISSUED' : 'DENIED'));
    inner.appendChild(el('div', 'banner-sub', (failed?.detail ?? '').toUpperCase()));
    // The most screenshot-able element on the page.
    inner.appendChild(el('div', 'banner-code', `${result.banner} · ${result.generated_at}`));
  }
}

function renderLog(result) {
  const log = $('log');
  log.replaceChildren();

  // Show all nine, always. A stage that never ran because an earlier one
  // refused is SKIPPED — a reader cannot tell a skipped check from a forgotten
  // one. Fail-closed applies to the explanation too.
  const byNumber = new Map(result.stages.map((s) => [s.n, s]));
  const rows = [];
  for (const s of result.stages) if (s.n < 1) rows.push(s);
  for (let n = 1; n <= 9; n++) {
    rows.push(byNumber.get(n) ?? {
      n, check: STAGE_NAMES[n], section: null, result: 'SKIPPED',
      detail: result.refused_at === 'issuance'
        ? 'not reached — no certificate was issued to validate'
        : 'not reached — an earlier stage refused',
    });
  }
  for (const s of result.stages) if (s.n > 9) rows.push(s);

  for (const stage of rows) {
    const cls = stage.result === 'PASS' ? 'pass' : stage.result === 'DENY' ? 'deny'
      : stage.result === 'ADVISORY' ? 'warn' : 'na';
    const row = el('div', `log-row ${cls}`);
    row.appendChild(el('span', 'ln', stage.n < 1 ? '0' : String(stage.n)));
    row.appendChild(sectionRef(stage.section));
    row.appendChild(el('span', 'res', stage.result));
    row.appendChild(el('span', 'detail', stage.detail));

    if (stage.result === 'DENY' && result.refused_at !== 'issuance') {
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

  // The header goes in the SAME scroller as the rows: two scrollers desync and
  // the labels drift off their columns.
  const scroller = el('div', 'audit-scroll');
  scroller.appendChild(head);

  const idCell = (value, full) => {
    const span = el('span', 'who mono', value ?? '');
    if (full) span.title = full;
    return span;
  };

  // Where each agent sits in the chain, read from the document. An id the
  // document no longer contains reports nothing rather than guessing.
  const relationship = new Map();
  for (const node of result?.chain ?? []) {
    if (node.role !== 'agent') continue;
    const id = node.metadata?.agent_id;
    if (id) relationship.set(id, node.metadata?.parent_agent_id ? 'child' : 'parent');
  }

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
    // Always say WHAT was attempted, then why it was refused.
    const detail = el('span', 'detail', b.event?.action ?? '—');
    if (b.event?.reason) {
      detail.appendChild(el('span', 'why', ` · ${b.event.reason}`));
    } else if (b.event?.detail) {
      detail.appendChild(el('span', 'note', ` · ${b.event.detail}`));
    }
    row.appendChild(detail);

    const agents = Array.isArray(b.event?.agents) ? b.event.agents : null;
    row.appendChild(agents
      ? idCell(`${agents.length} agents`, agents.join('\n'))
      : idCell(b.event?.agent, b.event?.agent));

    const rel = agents ? 'whole chain' : (relationship.get(b.event?.agent) ?? '');
    const relCell = el('span', `rel ${rel === 'child' ? 'is-child' : rel === 'parent' ? 'is-parent' : ''}`, rel);
    if (rel === 'child' && b.event?.parent) relCell.title = `parent: ${b.event.parent}`;
    row.appendChild(relCell);

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
 * Reference pane. The audit chain and the certificate views are things you
 * consult AFTER a result, so they sit behind tabs instead of competing with the
 * panes you actually use.
 */
let refTab = 'audit';

function renderReference(result) {
  referenceView = result;
  const tabs = $('ref-tabs');
  const body = $('ref-body');
  tabs.replaceChildren(); body.replaceChildren();

  // Plain labels. The only badge is the audit tab's BROKEN flag, so a broken
  // chain is visible while the Certificates tab is open; counts live in the
  // panels themselves.
  const broken = result?.error_code === 'ERR_AUDIT_CHAIN_BROKEN';
  const defs = [
    { id: 'audit', label: 'Audit chain', badge: broken ? 'BROKEN' : null },
    { id: 'certs', label: 'Certificates', badge: null },
  ];

  for (const d of defs) {
    const t = el('button', `ref-tab${d.id === refTab ? ' active' : ''}`);
    t.appendChild(document.createTextNode(d.label));
    if (d.badge) t.appendChild(el('span', 'badge bad', d.badge));
    t.addEventListener('click', () => { refTab = d.id; renderReference(referenceView); });
    tabs.appendChild(t);
  }

  if (refTab === 'audit') renderAudit(result, body);
  else renderCerts(result, body);
}

// ── The certificate view ───────────────────────────────────────────────────

/**
 * Which line of which certificate a §7-family refusal is about. The subject of
 * the failing walk step names the certificate; the code names the line.
 */
/** Refusals raised at a walk step that is not a certificate still point at one. */
const CERT_SUBJECT_FOR_CODE = {
  ERR_SCOPE_ESCALATION: 'CHILD AGENT', ERR_EMPTY_SCOPES: 'CHILD AGENT', ERR_GRANT_MISSING: 'CHILD AGENT',
  ERR_GRANT_INVALID: 'CHILD AGENT', ERR_GRANT_EXPIRED: 'CHILD AGENT', ERR_GRANT_EXCEEDS_TEMPLATE: 'CHILD AGENT',
  ERR_MAX_SPAWNS: 'CHILD AGENT', ERR_MAX_CHILDREN: 'PARENT AGENT', ERR_CHILD_NOT_WHITELISTED: 'PARENT AGENT',
  ERR_SPAWN_NOT_PERMITTED: 'PARENT AGENT', ERR_OWNER_CERT_MISMATCH: 'CHILD AGENT', ERR_SINGLE_SIGNATURE: 'POLICY AUTHORITY',
  ERR_POLICY_EXCEEDS_TEMPLATE: 'CHILD AGENT', ERR_SPAWN_EXCEEDS_TEMPLATE: 'CHILD AGENT',
};
const CERT_FIELD_FOR_CODE = {
  ERR_KEY_TOO_SMALL: 'public_key', ERR_WEAK_SIGNATURE: 'sig_alg', ERR_SERIAL_ENTROPY: 'serial',
  ERR_CERT_EXPIRED: 'validity', ERR_VALIDITY_EXCEEDS_TTL: 'validity', ERR_TTL_TOO_LONG: 'tpl:ttl_seconds',
  ERR_SUBJECT_MISMATCH: 'subject', ERR_NAME_CONSTRAINT: 'subject', ERR_AGENT_ID_FORMAT: 'subject',
  ERR_FORGED_ISSUER: 'issuer', ERR_CHAIN_INVALID: 'issuer', ERR_SELF_SIGNED: 'issuer',
  ERR_BASIC_CONSTRAINTS: 'ext:2.5.29.19', ERR_KEY_USAGE: 'ext:2.5.29.15',
  ERR_NO_REVOCATION_SOURCE: 'extensions', ERR_UNKNOWN_CRITICAL_EXT: 'extensions',
  ERR_TEMPLATE_EXT_MISSING: 'extensions', ERR_TEMPLATE_EXT_INVALID: 'template',
  ERR_SPAWN_EXT_INVALID: 'spawn', ERR_PARENT_MISMATCH: 'spawn:parent_agent_id', ERR_NONCE_REUSED: 'spawn:spawn_nonce',
  ERR_SCOPE_ESCALATION: 'tpl:allowed_scopes', ERR_POLICY_EXCEEDS_TEMPLATE: 'tpl:allowed_scopes', ERR_MAX_CHILDREN: 'tpl:max_children',
  ERR_CHILD_NOT_WHITELISTED: 'tpl:can_spawn', ERR_SPAWN_NOT_PERMITTED: 'tpl:permitted_operations',
  ERR_GRANT_MISSING: 'tpl:org_id', ERR_OWNER_CERT_MISMATCH: 'tpl:owner',
};

let certRenderToken = 0;

/**
 * Every certificate in the document, rendered the way `openssl x509 -text`
 * renders one — the shape every engineer already reads — with both profile
 * extensions decoded beside what an ordinary X.509 stack sees of them.
 */
function renderCerts(result, body) {
  const token = ++certRenderToken;
  const items = [];
  const chain = result?.chain ?? [];
  const labels = (() => {
    let child = 0;
    return chain.map((n) => (n.role === 'ca' ? 'TRUST ANCHOR'
      : n.metadata?.parent_agent_id ? (++child > 1 ? `CHILD AGENT ${child}` : 'CHILD AGENT') : 'PARENT AGENT'));
  })();
  chain.forEach((n, i) => items.push({ label: labels[i], pem: n.cert_pem, id: n.metadata?.agent_id ?? n.metadata?.subject }));
  for (const [role, a] of Object.entries(result?.authorities ?? {})) {
    items.push({ label: role === 'owner' ? 'OWNER AUTHORITY' : 'POLICY AUTHORITY', pem: a.cert_pem, id: a.common_name });
  }

  const failed = result?.stages?.find((s) => s.result === 'DENY');
  const certSubjects = new Set(items.map((i) => i.label));
  const badSubject = certSubjects.has(failed?.subject) ? failed.subject
    : result?.error_code === 'ERR_AUTHORITY_CHAIN'
      ? (/^Owner/.test(failed?.detail ?? '') ? 'OWNER AUTHORITY' : 'POLICY AUTHORITY')
      : (CERT_SUBJECT_FOR_CODE[result?.error_code] ?? null);
  const badField = CERT_FIELD_FOR_CODE[result?.error_code] ?? null;

  const lede = el('p', 'cert-lede',
    'What any X.509 stack sees, beside what a conformant validator sees. The two profile '
    + 'extensions are critical OCTET STRINGs holding JCS: an ordinary stack must refuse the '
    + 'certificate (RFC 5280 §4.2); a validator that implements the draft reads the members. '
    + 'Read-only — edit the document to change anything.');
  body.appendChild(lede);
  const wrap = el('div', 'cert-list');
  body.appendChild(wrap);
  const blocks = new Map();

  for (const item of items) {
    const block = el('div', 'cert-block');
    block.dataset.id = item.id ?? '';
    const head = el('div', 'cert-head');
    head.appendChild(el('span', 'cert-role', item.label));
    if (item.id) head.appendChild(el('span', 'cert-id mono', item.id));
    block.appendChild(head);
    const pre = el('div', 'cert-text', 'decoding…');
    block.appendChild(pre);
    if (item.label === badSubject) block.classList.add('bad');
    wrap.appendChild(block);
    blocks.set(item.id, block);
    if (typeof item.pem !== 'string') { pre.textContent = 'no certificate'; continue; }
    describeCertificate(item.pem).then((d) => {
      if (token !== certRenderToken) return;
      pre.replaceChildren();
      const line = (indent, text, key = null) => {
        const l = el('div', 'cert-line', `${' '.repeat(indent)}${text}`);
        if (key && item.label === badSubject && key === badField) l.classList.add('bad-field');
        pre.appendChild(l);
        return l;
      };
      line(0, 'Certificate:');
      line(4, 'Data:');
      line(8, `Version: ${d.version} (0x${(d.version - 1).toString(16)})`);
      line(8, `Serial Number: ${d.serial_number.toLowerCase()}`, 'serial');
      line(8, `Signature Algorithm: ${d.signature.algorithm}`, 'sig_alg');
      line(8, `Issuer: ${d.issuer.rfc4514}`, 'issuer');
      line(8, 'Validity', 'validity');
      line(12, `Not Before: ${d.validity.not_before}`, 'validity');
      line(12, `Not After : ${d.validity.not_after}   (${d.validity.duration_seconds} s)`, 'validity');
      line(8, `Subject: ${d.subject.rfc4514}`, 'subject');
      line(8, 'Subject Public Key Info:', 'public_key');
      line(12, `Public Key Algorithm: ${d.public_key.algorithm}${d.public_key.type ? ` (${d.public_key.type})` : ''}`, 'public_key');
      line(16, `${d.public_key.bits ?? '?'}-bit key, ${d.public_key.security_bits ?? '?'}-bit security — ${d.public_key.meets_minimum ? 'meets' : 'BELOW'} the §7.1 floor`, 'public_key');
      line(8, 'X509v3 extensions:', 'extensions');
      for (const x of d.extensions) {
        if (x.decoded) {
          // Two views of the same bytes.
          line(12, `${x.oid}: ${x.critical ? 'critical' : 'not critical'}    ← any X.509 stack`, x.label === 'Agent Template' ? 'template' : 'spawn');
          line(16, x.views.any_x509_stack, x.label === 'Agent Template' ? 'template' : 'spawn');
          line(12, `${x.name}    ← a conformant validator`, x.label === 'Agent Template' ? 'template' : 'spawn');
          if (x.decoded.problem) {
            line(16, `refused — ${x.decoded.problem}`, x.label === 'Agent Template' ? 'template' : 'spawn');
          } else {
            for (const m of x.decoded.members) {
              const key = `${x.label === 'Agent Template' ? 'tpl' : 'spawn'}:${m.member}`;
              const val = Array.isArray(m.value) ? `[${m.value.join(', ')}]` : String(m.value);
              const l = line(16, `${m.member}: ${val}`, key);
              if (x.label === 'Agent Spawn' && m.member === 'parent_agent_id') {
                // The parent link, as a link: to the parent's own block.
                l.textContent = `${' '.repeat(16)}${m.member}: `;
                const a = el('a', 'cert-link mono', String(m.value));
                a.href = '#';
                a.title = 'jump to the parent certificate';
                a.addEventListener('click', (ev) => {
                  ev.preventDefault();
                  blocks.get(String(m.value))?.scrollIntoView({ behavior: 'smooth', block: 'start' });
                });
                l.appendChild(a);
                if (!blocks.has(String(m.value))) l.appendChild(el('span', 'cert-note', '   (not in this chain)'));
              }
            }
          }
          continue;
        }
        line(12, `${x.name ?? x.oid}: ${x.critical ? 'critical' : 'not critical'}`, `ext:${x.oid}`);
        line(16, x.summary, `ext:${x.oid}`);
      }
      line(4, `Signature Algorithm: ${d.signature.algorithm}`, 'sig_alg');
      line(8, `${d.signature.bits} bits over tbsCertificate (${d.signed_bytes.length} bytes, sha256 ${d.signed_bytes.sha256.slice(0, 16)}…)`);
      line(4, `SHA-256 fingerprint: ${d.fingerprint_sha256}`);
      line(4, `${d.der_bytes} bytes DER`);
    }).catch(() => {
      if (token !== certRenderToken) return;
      pre.textContent = 'could not be decoded — the validator will say why';
    });
  }
}

function renderFooter() {
  const f = $('footer');
  f.replaceChildren();
  f.appendChild(el('div', null,
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
  const lic = el('a', null, 'Apache-2.0');
  lic.href = 'https://github.com/tonyt68/a2a-trust-playground/blob/main/LICENSE';
  lic.target = '_blank';
  lic.rel = 'noopener';
  line.appendChild(lic);
  f.appendChild(line);
  $('build-stamp').textContent = VERSION;
}

// ── Verify ────────────────────────────────────────────────────────────────

/** A result-shaped object for a refusal that happened outside the pipeline. */
function refusalResult(deny, { refusedAt, subject = null } = {}) {
  return {
    playground_version: VERSION, draft: DRAFT, generated_at: new Date().toISOString(),
    demo_only: true, verdict: 'DENY', error_code: deny.code, draft_section: deny.section,
    banner: deny.banner, refused_at: refusedAt, walk: [], advisories: [],
    stages: [{ n: refusedAt === 'issuance' ? 0 : 1,
      check: refusedAt === 'issuance' ? 'registry_issuance' : 'document_parse',
      section: deny.section, result: 'DENY', detail: deny.detail || deny.title, subject }],
    not_applicable: [], chain: [], authorities: {}, crl: { revoked: [], disabled: [] },
    audit: { entries: 0, head_hash: null, chain_valid: true, chain: [] },
  };
}

async function verify() {
  let result;
  try {
    const parsed = readDocument();
    result = await runPipeline({ document: parsed, version: VERSION });
  } catch (error) {
    // A document that will not even parse is a stage-1 refusal, rendered
    // through exactly the same path as any other. No special-case error UI.
    const deny = error instanceof DenyError ? error : new DenyError('ERR_INTERNAL', 'could not read the document');
    result = refusalResult(deny, { refusedAt: 'parse' });
  }

  // Write the audit chain back into the document. §19.7 describes an
  // accumulating record of decisions; without this the chain resets every
  // verify, and "alter an audit entry" has nothing to alter.
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

  const line = result.verdict === 'DENY'
    ? locateFailure(docBox.value, failureLocation(result)) : null;
  publish({ badLine: line, result });
  if (line) scrollLineIntoView(line);
  return result;
}

/** A refusal at issuance: nothing was minted, so the document is untouched. */
function showIssuanceRefusal(deny) {
  const result = refusalResult(deny, { refusedAt: 'issuance' });
  renderVerdict(result);
  renderLog(result);
  publish({ result, badLine: null });
}

// ── Sabotage ──────────────────────────────────────────────────────────────
// The document manipulations live in scenarios.js so the unit tests exercise
// the exact code these buttons run, rather than a parallel copy of it.

/**
 * Modifications the draft ALLOWS. Every other button here produces a refusal,
 * which by itself teaches only that a wall exists. These show where the wall
 * actually is.
 */
const ALLOWED = [
  { phase: 'AUDIT', label: 'Reset the audit chain', section: '19.7', apply: async (d) => {
      const child = childOf(d);
      const parent = parentOf(d);
      const chain = await seedAuditChain({
        parentId: parent?.metadata?.agent_id,
        childId: child?.metadata?.agent_id,
      });
      d.audit = chain.toJSON();
      return 'audit'; } },
  { phase: 'BOUNDS', label: 'Narrow the parent to read-only', section: '10.3', apply: async (d) => {
      // Re-issue the PARENT with a narrower ceiling. The child holds
      // read:events, so the delegation is still a subset. Narrowing is always
      // permitted; only widening is refused.
      await reissueThroughRegistry(d, parentOf(d), { allowed_scopes: ['read:events'] });
      return 'chain[1].cert_pem'; } },
  { phase: 'BOUNDS', label: 'Policy: revoke write access', section: '8.3', apply: async (d) => {
      // A dual-signed policy that REMOVES authority. Inside the ceiling, so it
      // applies. §11.6: version is inside the signed body, so bumping it means
      // re-signing — the step an attacker cannot take.
      d.policy.body.scopes = [];
      d.policy.body.version = (d.policy.body.version ?? 1) + 1;
      await resignPolicy(d);
      return 'policy.body.scopes'; } },
  { phase: 'IDENTITY', label: 'Re-issue the child, same bounds', section: '7', apply: async (d) => {
      // A fresh certificate for the same identity, through the Registry's
      // gates: fresh keys, fresh nonce, same template. Identity is the UUID.
      await reissueThroughRegistry(d, childOf(d));
      return 'chain[2].cert_pem'; } },
  { phase: 'GRANT', label: 'Spawn across organizations', section: '13.2', apply: async (d) => {
      await spawnAcrossOrganizations(d);
      return 'grant'; } },
];

/** SHOULD-level findings: the chain stays valid and the page says so. */
const ADVISORY = [
  { phase: 'BOUNDS', label: 'Child outlives its parent', section: '10.3', apply: async (d) => {
      // §10.3: a child's ttl_seconds SHOULD NOT exceed its parent's. A SHOULD,
      // so the tool reports it and does not refuse — which is the honest
      // demonstration of the difference between SHOULD and MUST.
      await reissueThroughRegistry(d, childOf(d), { ttl_seconds: PARENT_TTL_SECONDS * 2 });
      return 'chain[2].cert_pem'; } },
];

const SABOTAGE = [
  // ── REGISTRY: refused at issuance; the document is untouched ─────────────
  { phase: 'REGISTRY', label: 'Drop a REQUIRED template field', section: '9.1', registry: true, apply: async (d) => {
      const registry = await Registry.fromDocument(d);
      const t = templateOf(childOf(d));
      delete t.ttl_seconds;
      await registry.attest(t); } },
  { phase: 'REGISTRY', label: 'Remove one attestation signature', section: '9.2', registry: true, apply: async (d) => {
      const registry = await Registry.fromDocument(d);
      const attested = await registry.attest(templateOf(childOf(d)));
      delete attested.pa_sig;
      await registry.spawn({ attested, parent: templateOf(parentOf(d)) }); } },
  { phase: 'REGISTRY', label: 'Edit a template after it was signed', section: '9.3', registry: true, apply: async (d) => {
      // Signed while conforming, edited afterwards. The edit is to a member the
      // spawn checks of §10.2 never consult, so the only thing standing between
      // it and a certificate is issuance re-verifying both signatures — which
      // is why §9.3 re-verifies.
      const registry = await Registry.fromDocument(d);
      const attested = await registry.attest(templateOf(childOf(d)));
      attested.body.max_children = 99;
      await registry.spawn({ attested, parent: templateOf(parentOf(d)) }); } },
  { phase: 'REGISTRY', label: 'Replay the spawn request', section: '19.2', registry: true, apply: async (d) => {
      const registry = await Registry.fromDocument(d);
      const attested = await registry.attest(templateOf(childOf(d)));
      const parent = templateOf(parentOf(d));
      const nonce = newNonce();
      await registry.spawn({ attested, parent, nonce });   // accepted once
      await registry.spawn({ attested, parent, nonce }); } }, // the replay
  { phase: 'REGISTRY', label: 'Stale spawn timestamp (61 s)', section: '19.2', registry: true, apply: async (d) => {
      const registry = await Registry.fromDocument(d);
      const attested = await registry.attest(templateOf(childOf(d)));
      const at = new Date(Date.now() - FRESHNESS_WINDOW_MS - 1000).toISOString();
      await registry.spawn({ attested, parent: templateOf(parentOf(d)), requestedAt: at }); } },
  { phase: 'REGISTRY', label: 'Future spawn timestamp (61 s)', section: '19.2', registry: true, apply: async (d) => {
      const registry = await Registry.fromDocument(d);
      const attested = await registry.attest(templateOf(childOf(d)));
      const at = new Date(Date.now() + FRESHNESS_WINDOW_MS + 1000).toISOString();
      await registry.spawn({ attested, parent: templateOf(parentOf(d)), requestedAt: at }); } },

  // ── IDENTITY: the certificates themselves ────────────────────────────────
  { phase: 'IDENTITY', label: 'Forge the issuer', section: '7', apply: async (d) => {
      // A genuine forgery: a SECOND Registry, with its own CA, attests and
      // issues the child. Well-formed, correctly signed — by the wrong authority.
      const rogue = await Registry.create({ caCommonName: 'Rogue-CA-Not-The-Trust-Anchor' });
      const c = childOf(d);
      const issued = await rogue.spawn({
        attested: await rogue.attest(templateOf(c)), parent: templateOf(parentOf(d)),
      });
      c.cert_pem = issued.cert_pem; c.key_pem = issued.key_pem;
      return 'chain[2].cert_pem'; } },
  { phase: 'IDENTITY', label: 'Corrupt the certificate', section: '7', apply: (d) => {
      const c = childOf(d);
      const lines = c.cert_pem.split('\n');
      const mid = Math.floor(lines.length / 2);
      lines[mid] = lines[mid].startsWith('A') ? `B${lines[mid].slice(1)}` : `A${lines[mid].slice(1)}`;
      c.cert_pem = lines.join('\n');
      return 'chain[2].cert_pem'; } },
  { phase: 'IDENTITY', label: 'Forge the parent link', section: '10.5', apply: (d) => {
      // The chain names a different parent than the CA attested. Under -02 the
      // parent lived only in this unsigned field; now the certificate says.
      childOf(d).metadata.parent_agent_id = newAgentId();
      return 'chain[2].metadata.parent_agent_id'; } },
  { phase: 'IDENTITY', label: 'Expire the certificate', section: '7', apply: async (d) => {
      const at = new Date('2020-01-01T00:00:00Z');
      await issueRaw(d, childOf(d), { notBefore: at, notAfter: new Date(at.getTime() + 3600_000) });
      return 'chain[2].cert_pem'; } },
  { phase: 'IDENTITY', label: 'Agent cert claims keyCertSign', section: '7.1', apply: async (d) => {
      await issueRaw(d, childOf(d), { keyUsageBits: [KEY_USAGE.digitalSignature, KEY_USAGE.keyCertSign] });
      return 'chain[2].cert_pem'; } },
  { phase: 'IDENTITY', label: 'Outlive the template TTL', section: '9.3', apply: async (d) => {
      const c = childOf(d);
      const ttl = templateOf(c).ttl_seconds;
      const now = new Date();
      await issueRaw(d, c, { notBefore: now, notAfter: new Date(now.getTime() + (ttl + 3600) * 1000) });
      return 'chain[2].cert_pem'; } },
  { phase: 'IDENTITY', label: 'Drop the revocation pointer', section: '14.4', apply: async (d) => {
      await issueRaw(d, childOf(d), { revocationSource: false });
      return 'chain[2].cert_pem'; } },
  { phase: 'IDENTITY', label: 'One identity, two certificates', section: '12.1', apply: (d) => {
      const c = childOf(d);
      d.chain.push(JSON.parse(JSON.stringify(c)));
      return 'chain[3]'; } },
  { phase: 'IDENTITY', label: 'Duplicate nonce in the chain', section: '19.2', apply: async (d) => {
      // A second child issued under the FIRST child's nonce. The Registry never
      // does this; a CA key in the wrong hands, or a Registry that forgot its
      // nonces, does. The relying party catches it (§10.5, last paragraph).
      await issueSecondChildWithNonce(d);
      return 'chain[3].cert_pem'; } },

  // ── STANDING ─────────────────────────────────────────────────────────────
  { phase: 'STANDING', label: 'Revoke the parent', section: '14', apply: (d) => {
      d.crl.revoked.push(parentOf(d).metadata.agent_id); return 'crl.revoked'; } },
  { phase: 'STANDING', label: 'Disable the template at the Registry', section: '12.4', apply: (d) => {
      d.crl.disabled.push(childOf(d).metadata.agent_id); return 'crl.disabled'; } },

  // ── GRANT ────────────────────────────────────────────────────────────────
  { phase: 'GRANT', label: 'Cross-org spawn with no grant', section: '13.1', apply: async (d) => {
      await spawnAcrossOrganizations(d);
      delete d.grant;
      return 'chain[2].cert_pem'; } },
  { phase: 'GRANT', label: 'Expired grant', section: '13.2', apply: async (d) => {
      await spawnAcrossOrganizations(d, { issued_at: new Date(Date.now() - 7200_000).toISOString(), ttl_seconds: 3600 });
      return 'grant.body.issued_at'; } },
  { phase: 'GRANT', label: 'Grant exceeds the template', section: '13.2', apply: async (d) => {
      await spawnAcrossOrganizations(d, { allowed_scopes: ['read:events', 'admin:all'] });
      return 'grant.body.allowed_scopes'; } },
  { phase: 'GRANT', label: 'Remove one grant signature', section: '13.2', apply: async (d) => {
      await spawnAcrossOrganizations(d);
      delete d.grant.pa_sig;
      return 'grant'; } },
  { phase: 'GRANT', label: 'Drop the grant’s issued_at', section: '13.2', apply: async (d) => {
      await spawnAcrossOrganizations(d);
      delete d.grant.body.issued_at;
      return 'grant.body'; } },
  { phase: 'GRANT', label: 'Grant allows no spawns', section: '13.2', apply: async (d) => {
      await spawnAcrossOrganizations(d, { max_spawns: 0 });
      return 'grant.body.max_spawns'; } },

  // ── BOUNDS ───────────────────────────────────────────────────────────────
  { phase: 'BOUNDS', label: 'Escalate the scope', section: '10.3', apply: async (d) => {
      // The CA key issues the child a WIDER ceiling than its parent holds.
      // Every signature verifies; §10.3 still refuses it.
      const c = childOf(d);
      await issueRaw(d, c, { template: { allowed_scopes: ['admin:all'] } });
      c.requested_scopes = ['admin:all'];
      delete d.policy;          // isolate §10.3 from the §8.3 ceiling
      return 'chain[2].cert_pem'; } },
  { phase: 'BOUNDS', label: 'Exceed max_children', section: '10.2', apply: async (d) => {
      await issueRaw(d, parentOf(d), { template: { max_children: 0 } });
      return 'chain[1].cert_pem'; } },
  { phase: 'BOUNDS', label: 'Spawn a non-whitelisted child', section: '10.1', apply: async (d) => {
      await issueRaw(d, parentOf(d), { template: { can_spawn: [] } });
      return 'chain[1].cert_pem'; } },
  { phase: 'BOUNDS', label: 'Parent may not spawn at all', section: '10.1', apply: async (d) => {
      // CanSpawn still names the child; PermittedOperations omits spawn. §8.1
      // calls that "permitted to spawn specific children and not permitted to spawn".
      await issueRaw(d, parentOf(d), { template: { permitted_operations: ['read', 'write'] } });
      return 'chain[1].cert_pem'; } },
  { phase: 'BOUNDS', label: 'Widen policy past the ceiling', section: '8.3', apply: async (d) => {
      // Both authorities legitimately sign, the hash matches, the owner is
      // right — and it is still refused. Two valid signatures do not raise the
      // ceiling.
      d.policy.body.scopes = ['admin:all'];
      await resignPolicy(d);
      return 'policy.body.scopes'; } },

  // ── AUTHORITY ────────────────────────────────────────────────────────────
  { phase: 'AUTHORITY', label: 'Sign with one key only', section: '11.3', apply: (d) => {
      d.policy.pa_sig = null; return 'policy.pa_sig'; } },
  { phase: 'AUTHORITY', label: 'One key, both roles', section: '3.1', apply: async (d) => {
      // The Policy Authority "certificate" is the Owner's. Both signatures verify
      // — under the same key. §3.1 compares keys, not signature octets.
      d.authorities.pa = { ...d.authorities.owner };
      const key = await privateKeyFromPem(d.authorities.owner.key_pem);
      d.policy = await signEnvelope(d.policy.body, key, key, { withHash: true });
      return 'authorities.pa'; } },
  { phase: 'AUTHORITY', label: 'Tamper with the policy body', section: '11.3', apply: async (d) => {
      // An attacker who edits a stored policy also recomputes its content hash —
      // a hash is not a secret. What they CANNOT do is re-sign.
      d.policy.body.issued_at = new Date(Date.now() + 86_400_000).toISOString();
      d.policy.content_hash = await contentHash(d.policy.body);
      return 'policy.body.issued_at'; } },
  { phase: 'AUTHORITY', label: 'Replay an old policy, bump version', section: '11.6', apply: (d) => {
      // The attack -02 was written to close: version is inside the signed body,
      // so incrementing it breaks both signatures.
      d.current_policy_version = 5;
      d.policy.body.version = 6;
      return 'policy.body.version'; } },
  { phase: 'AUTHORITY', label: 'Alter the stored hash only', section: '11.6', apply: (d) => {
      d.policy.content_hash = '0'.repeat(64); return 'policy.content_hash'; } },
  { phase: 'AUTHORITY', label: 'Edit can_spawn via policy', section: '11.4', apply: (d) => {
      d.policy.body.can_spawn = []; return 'policy.body.can_spawn'; } },
  { phase: 'AUTHORITY', label: 'Submit as the wrong owner', section: '11.2', apply: (d) => {
      d.policy.body.owner = 'attacker@example.com'; return 'policy.body.owner'; } },
  { phase: 'AUTHORITY', label: 'Owner certificate does not match the template', section: '9.2', apply: async (d) => {
      // The template names an owner the Owner certificate does not: the string
      // in `owner` is bound to nothing.
      await issueRaw(d, childOf(d), { template: { owner: 'another-owner' } });
      d.policy.body.owner = 'another-owner';
      await resignPolicy(d);
      return 'chain[2].cert_pem'; } },

  // ── AUDIT ────────────────────────────────────────────────────────────────
  { phase: 'AUDIT', label: 'Alter an audit entry', section: '19.7', apply: (d) => {
      if (!d.audit?.chain?.length) return null;
      // Idempotent on purpose: a fixed value, so pressing it twice leaves the
      // chain exactly as broken as it already was.
      const entry = d.audit.chain[0];
      entry.event.detail = 'record altered after the block was sealed';
      return 'audit'; } },
];

async function runSabotage(entry) {
  let doc;
  try { doc = readDocument(); } catch { await verify(); return; }

  if (entry.registry) {
    // The Registry is asked to do something it must refuse. Nothing is issued
    // and the document does not change; the refusal is the demonstration.
    try {
      await entry.apply(doc);
      showIssuanceRefusal(new DenyError('ERR_INTERNAL',
        'the Registry ACCEPTED this request — that is a bug in the playground, not a property of the draft'));
    } catch (e) {
      const deny = e instanceof DenyError ? e : new DenyError('ERR_INTERNAL', 'the Registry failed for an unexpected reason');
      showIssuanceRefusal(deny);
    }
    return;
  }

  let path;
  try {
    path = await entry.apply(doc);
  } catch (e) {
    // A button that fails to apply must say so rather than validate the
    // unchanged document as though it had.
    const deny = e instanceof DenyError ? e : new DenyError('ERR_INTERNAL', 'the modification could not be applied');
    showIssuanceRefusal(deny);
    return;
  }
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
  setBusy(true);
  $('editor-hint').textContent = 'minting a fresh chain…';
  const doc = await buildDefaultDocument();
  setDocument(doc);
  $('editor-hint').textContent = 'every panel is a view over this JSON';
  // Deliberately NOT validated here. The page should not announce a verdict the
  // visitor did not ask for.
  renderIdle('A fresh chain is loaded and has NOT been validated — press Validate.', doc);
  window.scrollTo({ top: 0 });
  setBusy(false);
}

/** The un-validated state: everything grey, nothing claimed. */
function renderIdle(message) {
  const banner = $('verdict');
  const inner = $('verdict-inner');
  banner.className = 'idle';
  inner.replaceChildren();
  inner.appendChild(el('div', 'banner-main', 'NOT VALIDATED'));
  inner.appendChild(el('div', 'banner-sub', message));
  $('log').replaceChildren();
  publish({ result: null });
}

/**
 * The only export. No download, no Blob, no <a download>, nothing to disk.
 * Falls back to selecting the document so the visitor can copy it themselves.
 */
async function copyJson(button) {
  // "Copy the document to your clipboard" — the editor's own content, always,
  // not the pipeline's last export: that view drops the private keys, the
  // policy and grant envelopes and current_policy_version (see
  // scripts/roundtrip-export.mjs, which re-adds exactly those fields for the
  // same reason), so copying it produced a document that re-validated
  // differently from the one on screen.
  let payload;
  try {
    payload = JSON.stringify(parseDocument(docBox.value || '{}'), null, 2);
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
    say(`copied ✓  ${payload.length.toLocaleString()} characters`, true);
  } catch {
    docBox.focus();
    docBox.select();
    say('clipboard blocked — document selected, press ⌘C', false);
  }
}

const COPY_HINT = 'copy the document to your clipboard';

/**
 * Controls, grouped by the step of the chain each one exercises. Allowed,
 * advisory and refused modifications sit side by side within a group, which is
 * the whole point — the boundary is only visible when both halves are in view.
 */
function buildControls() {
  const main = $('controls-main');
  main.replaceChildren();
  main.appendChild(button('Reset Certs', 'primary',
    'mint a fresh valid chain — new keys, new identities', loadDefaults));
  const copy = button('Copy JSON', '', COPY_HINT, () => copyJson(copy));
  main.appendChild(copy);

  $('controls-validate').replaceChildren(
    button('Validate', 'primary', 'run all nine checks over the document as it stands', verify));

  const box = $('controls-phases');
  box.replaceChildren();
  for (const phase of PHASES) {
    const allowed = ALLOWED.filter((e) => e.phase === phase.name);
    const advisory = ADVISORY.filter((e) => e.phase === phase.name);
    const refused = SABOTAGE.filter((e) => e.phase === phase.name);
    if (!allowed.length && !advisory.length && !refused.length) continue;

    const group = el('div', 'phase-group');
    const head = el('div', 'phase-head');
    head.appendChild(el('span', 'phase-name', phase.name));
    head.appendChild(el('span', 'phase-ask', phase.asks));
    group.appendChild(head);

    const grid = el('div', 'phase-grid');
    for (const e of allowed) {
      grid.appendChild(button(e.label, 'ok', `§${e.section} · stays valid`, () => runSabotage(e)));
    }
    for (const e of advisory) {
      grid.appendChild(button(e.label, 'warn', `§${e.section} · advisory, stays valid`, () => runSabotage(e)));
    }
    for (const e of refused) {
      grid.appendChild(button(e.label, 'danger', e.registry ? `§${e.section} · refused at issuance` : `§${e.section}`, () => runSabotage(e)));
    }
    group.appendChild(grid);
    box.appendChild(group);
  }
}

// ── Boot ──────────────────────────────────────────────────────────────────

buildControls();
renderFooter();
publish({ result: null });
loadDefaults();
