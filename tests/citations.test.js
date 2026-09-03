/**
 * Every clause this page cites must exist in the draft, and say what we claim.
 *
 * `-02` inserted new sections, which renumbered everything after them, and the
 * code went on citing the `-01` positions. `ERR_AUDIT_CHAIN_BROKEN` pointed at
 * §16.6, which in `-02` was "PKI Does Not Enforce Authorization" rather than
 * "Audit Integrity". The refusal still rendered, still looked authoritative, and
 * sent the reader to the wrong clause. `-03` did it again on a larger scale:
 * Document Encoding became §3 and pushed every later section down.
 *
 * So this pins the section TITLE, not the number. Titles are the stable thing:
 * a renumbering moves them, it does not rename them. Verified by reintroducing
 * the -02 bug: an existence check did not notice, a title check did.
 *
 * The draft lives in `docs/draft/`, which IS tracked, so this runs on a fresh
 * clone. The skip is a guard for anyone who removes the file, not the normal path.
 */
import { describe, it, expect } from 'vitest';
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { ERRORS } from '../src/errors.js';
import { NOT_APPLICABLE } from '../src/pipeline.js';

const DRAFT = fileURLToPath(
  new URL('../docs/draft/draft-tonyai-a2a-trust-03.txt', import.meta.url),
);

/** Section number -> title, parsed from the draft body (not its table of contents). */
function draftSections() {
  const text = readFileSync(DRAFT, 'utf8');
  const start = text.indexOf('1.  Introduction', text.indexOf('1.  Introduction') + 10);
  const body = text.slice(start);
  const out = new Map();
  for (const m of body.matchAll(/^([0-9]+(?:\.[0-9]+)*)\.\s+([A-Z].*?)\s*$/gm)) {
    if (!out.has(m[1])) out.set(m[1], m[2].trim());
  }
  return out;
}

const available = existsSync(DRAFT);
const describeIfDraft = available ? describe : describe.skip;

describeIfDraft('every cited clause exists in the draft', () => {
  const sections = available ? draftSections() : new Map();

  it('the draft parsed into a usable section map, with the -03 sentinels in place', () => {
    expect(sections.size).toBeGreaterThan(40);
    // Sentinels: one per section a future renumber would move. If any of these
    // fails, work through the citation failures rather than re-pointing them.
    expect(sections.get('3')).toBe('Document Encoding');
    expect(sections.get('7')).toBe('Agent Identity');
    expect(sections.get('10.5')).toBe('Encoding of Spawn Provenance');
    expect(sections.get('18')).toBe('Implementation Status');
    expect(sections.get('19.7')).toBe('Audit Integrity');
  });

  /** What each refusal is ABOUT, by title rather than by number. */
  const MEANS = {
    ERR_AGENT_ID_FORMAT: 'Binding Identity to the Certificate',
    ERR_DUPLICATE_MEMBER: 'Document Encoding',
    ERR_OBJECT_NOT_FLAT: 'Document Encoding',
    ERR_SCOPE_SYNTAX: 'Scope Constraint',
    ERR_TIMESTAMP_FORMAT: 'Document Encoding',
    ERR_CHAIN_INVALID: 'Agent Identity',
    ERR_FORGED_ISSUER: 'Agent Identity',
    ERR_SELF_SIGNED: 'Certificate Signing Request Flow',
    ERR_CERT_EXPIRED: 'Agent Identity',
    ERR_KEY_TOO_SMALL: 'Certificate Profile',
    ERR_SUBJECT_MISMATCH: 'Binding Identity to the Certificate',
    ERR_UNKNOWN_CRITICAL_EXT: 'Certificate Profile',
    ERR_NAME_CONSTRAINT: 'Certificate Profile',
    ERR_BASIC_CONSTRAINTS: 'Certificate Profile',
    ERR_WEAK_SIGNATURE: 'Certificate Profile',
    ERR_KEY_USAGE: 'Certificate Profile',
    ERR_SERIAL_ENTROPY: 'Certificate Profile',
    ERR_NO_REVOCATION_SOURCE: 'Locating Revocation State',
    ERR_TEMPLATE_EXT_MISSING: 'Encoding of Static Fields',
    ERR_TEMPLATE_EXT_INVALID: 'Encoding of Static Fields',
    ERR_TTL_TOO_LONG: 'Issuance',
    ERR_VALIDITY_EXCEEDS_TTL: 'Issuance',
    ERR_SPAWN_EXT_INVALID: 'Encoding of Spawn Provenance',
    ERR_PARENT_MISMATCH: 'Encoding of Spawn Provenance',
    ERR_NONCE_REUSED: 'Replay Attacks',
    ERR_DUPLICATE_SUBJECT: 'Full Re-Verification Required',
    ERR_AGENT_DISABLED: 'Template Lifecycle',
    ERR_AGENT_REVOKED: 'Revocation',
    ERR_AUTHORITY_CHAIN: 'Dual Attestation',
    ERR_ENVELOPE_MEMBER: 'Signature Envelope',
    ERR_SIGNATURE_ALGORITHM: 'Signature Envelope',
    ERR_OWNER_SIG_MISSING: 'Dual Signature Requirement',
    ERR_PA_SIG_MISSING: 'Dual Signature Requirement',
    ERR_OWNER_SIG_INVALID: 'Dual Signature Requirement',
    ERR_PA_SIG_INVALID: 'Dual Signature Requirement',
    ERR_SINGLE_SIGNATURE: 'Signature Envelope',
    ERR_OWNER_CERT_MISMATCH: 'Dual Attestation',
    ERR_IMMUTABLE_FIELD: 'Dynamic Policy Document Structure',
    ERR_UNKNOWN_POLICY_FIELD: 'Dynamic Policy Document Structure',
    ERR_REQUIRED_FIELD: 'Dynamic Policy Document Structure',
    ERR_POLICY_EXCEEDS_TEMPLATE: 'Dynamic Policy Bounds',
    ERR_SPAWN_EXCEEDS_TEMPLATE: 'Dynamic Policy Bounds',
    ERR_OWNER_MISMATCH: 'Ownership',
    ERR_ORG_MISMATCH: 'Ownership',
    ERR_SUBJECT_UNKNOWN: 'Dynamic Policy Document Structure',
    ERR_POLICY_VERSION: 'Dynamic Policy Document Structure',
    ERR_POLICY_EXPIRED: 'Dynamic Policy Document Structure',
    ERR_CONTENT_HASH: 'Signature and Hash Coverage',
    ERR_SPAWN_NOT_PERMITTED: 'Two-Check Spawn Rule',
    ERR_CHILD_NOT_WHITELISTED: 'Two-Check Spawn Rule',
    ERR_MAX_CHILDREN: 'Spawn Validation Sequence',
    ERR_GRANT_MISSING: 'Explicit Grant Requirement',
    ERR_GRANT_INVALID: 'Grant Structure',
    ERR_GRANT_EXPIRED: 'Grant Structure',
    ERR_GRANT_EXCEEDS_TEMPLATE: 'Grant Structure',
    ERR_MAX_SPAWNS: 'Grant Structure',
    ERR_SCOPE_ESCALATION: 'Scope Constraint',
    ERR_EMPTY_SCOPES: 'Scope Constraint',
    ERR_AUDIT_CHAIN_BROKEN: 'Audit Integrity',
    ERR_TEMPLATE_NONCONFORMING: 'Conformance Gate',
    ERR_TEMPLATE_SIGNATURE: 'Dual Attestation',
    ERR_SPAWN_STALE: 'Replay Attacks',
    ERR_INTERNAL: 'Fail Closed',
  };

  it('every code with a section has a pinned meaning', () => {
    const unpinned = Object.values(ERRORS).filter((e) => e.section && !MEANS[e.code]).map((e) => e.code);
    expect(unpinned).toEqual([]);
  });

  for (const { code, section } of Object.values(ERRORS)) {
    if (!section) continue;
    it(`${code} cites §${section}, which is still the right clause`, () => {
      expect(sections.has(section), `§${section} is not a section of -03`).toBe(true);
      expect(sections.get(section),
        `${code} cites §${section}, which -03 titles "${sections.get(section)}" `
        + `rather than "${MEANS[code]}" -- the section was probably renumbered`)
        .toBe(MEANS[code]);
    });
  }

  it('the not-applicable entries cite the clauses they name', () => {
    const titles = { max_children_enforcement: 'Spawn Validation Sequence', policy_engine_gate: 'Policy Change Sequence' };
    for (const na of NOT_APPLICABLE) expect(sections.get(na.section)).toBe(titles[na.check]);
  });

  it('the titles embedded in the page match the draft', async () => {
    const app = readFileSync(new URL('../src/app.js', import.meta.url), 'utf8');
    const block = app.slice(app.indexOf('const SECTION_TITLES = {'));
    const embedded = [...block.slice(0, block.indexOf('};')).matchAll(/'([0-9.]+)':\s*'([^']+)'/g)];
    expect(embedded.length).toBeGreaterThan(20);
    for (const [, number, title] of embedded) {
      expect(sections.get(number), `§${number} title drifted from the draft`).toBe(title);
    }
  });

  it('no cited clause is missing a title — on the page or in the pipeline', () => {
    const app = readFileSync(new URL('../src/app.js', import.meta.url), 'utf8');
    const block = app.slice(app.indexOf('const SECTION_TITLES = {'));
    const embedded = new Set([...block.slice(0, block.indexOf('};')).matchAll(/'([0-9.]+)':/g)].map((m) => m[1]));
    const cited = new Set([
      ...Object.values(ERRORS).map((e) => e.section).filter(Boolean),
      ...NOT_APPLICABLE.map((n) => n.section),
      // sections the pipeline records on PASS rows, and the buttons cite
      ...[...app.matchAll(/section: '([0-9.]+)'/g)].map((m) => m[1]),
    ]);
    const missing = [...cited].filter((s) => !embedded.has(s));
    expect(missing, `cited without a title: ${missing.join(', ')}`).toEqual([]);
  });

  it('the pipeline records -03 sections on its PASS rows', () => {
    const src = readFileSync(new URL('../src/pipeline.js', import.meta.url), 'utf8');
    for (const s of [...src.matchAll(/record\(stages, \d, '([0-9.]+)'/g)].map((m) => m[1])) {
      expect(sections.has(s), `pipeline records §${s}, which is not in -03`).toBe(true);
    }
  });
});
