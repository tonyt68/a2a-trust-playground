/**
 * Every clause this page cites must exist in the draft, and say what we claim.
 *
 * `-02` inserted new sections, which renumbered everything after them, and the
 * code went on citing the `-01` positions. `ERR_AUDIT_CHAIN_BROKEN` pointed at
 * §16.6, which in `-02` is "PKI Does Not Enforce Authorization" rather than
 * "Audit Integrity". The refusal still rendered, still looked authoritative, and
 * sent the reader to the wrong clause.
 *
 * DRAFT-IMPACT.md warns about exactly this: "a renumbered section turns every
 * citation in the code into a wrong citation, which is worse than a stale
 * version number -- a stale number is visibly out of date, a wrong clause
 * reference looks authoritative." The warning was written and then walked into,
 * which is the argument for checking it mechanically rather than remembering.
 *
 * The draft now lives in `docs/draft/`, which IS tracked, so this runs on a
 * fresh clone rather than skipping. It was under `docs/private/` while the
 * revision was unpublished; once `-02` was posted to the IETF archive the file
 * was already public, and keeping a private copy only meant the check ran for
 * one person. The skip is kept as a guard for anyone who removes the file, not
 * as the normal path.
 */
import { describe, it, expect } from 'vitest';
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { ERRORS } from '../src/errors.js';

const DRAFT = fileURLToPath(
  new URL('../docs/draft/draft-tonyai-a2a-trust-02.txt', import.meta.url),
);

/** Section number -> title, parsed from the draft body (not its table of contents). */
function draftSections() {
  const text = readFileSync(DRAFT, 'utf8');
  // The ToC repeats every heading with dot leaders; start after it so the first
  // match of a heading is the real one.
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

  it('the draft parsed into a usable section map', () => {
    expect(sections.size).toBeGreaterThan(30);
    expect(sections.get('6')).toBe('Agent Identity');
  });

  /**
   * What each refusal is ABOUT, by title rather than by number.
   *
   * Checking only that a cited section exists is worthless: when `-02` moved
   * "Audit Integrity" from §16.6 to §16.7, §16.6 still existed -- it had simply
   * become "PKI Does Not Enforce Authorization". The stale citation resolved,
   * the test passed, and the page sent readers to the wrong clause. Verified by
   * reintroducing that exact bug: the existence check did not notice.
   *
   * Titles are the stable thing. A renumbering moves them; it does not rename
   * them. So this pins the title and lets the number float.
   */
  const MEANS = {
  ERR_CHAIN_INVALID: 'Agent Identity',
  ERR_FORGED_ISSUER: 'Agent Identity',
  ERR_SELF_SIGNED: 'Certificate Signing Request Flow',
  ERR_CERT_EXPIRED: 'Agent Identity',
  ERR_KEY_TOO_SMALL: 'Certificate Profile',
  ERR_SUBJECT_MISMATCH: 'Agent Identity',
  ERR_UNKNOWN_CRITICAL_EXT: 'Certificate Profile',
  ERR_NAME_CONSTRAINT: 'Certificate Profile',
  ERR_BASIC_CONSTRAINTS: 'Certificate Profile',
  ERR_WEAK_SIGNATURE: 'Certificate Profile',
  ERR_AGENT_DISABLED: 'Template Lifecycle',
  ERR_AGENT_REVOKED: 'Revocation',
  ERR_TTL_EXPIRED: 'Automation Requirement',
  ERR_AUTHORITY_CHAIN: 'Dual Signature Requirement',
  ERR_OWNER_SIG_MISSING: 'Dual Signature Requirement',
  ERR_PA_SIG_MISSING: 'Dual Signature Requirement',
  ERR_OWNER_SIG_INVALID: 'Dual Signature Requirement',
  ERR_PA_SIG_INVALID: 'Dual Signature Requirement',
  ERR_SINGLE_SIGNATURE: 'Dual Signature Requirement',
  ERR_IMMUTABLE_FIELD: 'Dual Signature Requirement',
  ERR_UNKNOWN_POLICY_FIELD: 'Dual Signature Requirement',
  ERR_REQUIRED_FIELD: 'Dual Signature Requirement',
  ERR_POLICY_EXCEEDS_TEMPLATE: 'Dynamic Policy Bounds',
  ERR_SPAWN_EXCEEDS_TEMPLATE: 'Dynamic Policy Bounds',
  ERR_OWNER_MISMATCH: 'Ownership',
  ERR_ORG_MISMATCH: 'Ownership',
  ERR_POLICY_VERSION: 'Dynamic Policy Document Structure',
  ERR_CONTENT_HASH: 'Signature and Hash Coverage',
  ERR_BOUNDS_UNPARSEABLE: 'Template Structure',
  ERR_MAX_CHILDREN: 'Template Structure',
  ERR_CHILD_NOT_WHITELISTED: 'Two-Check Spawn Rule',
  ERR_SCOPE_ESCALATION: 'Scope Constraint',
  ERR_EMPTY_SCOPES: 'Scope Escalation',
  ERR_AUDIT_CHAIN_BROKEN: 'Audit Integrity',
  ERR_INTERNAL: 'Fail Closed',
  };

  for (const { code, section } of Object.values(ERRORS)) {
    if (!section) continue;
    it(`${code} cites §${section}, which is still the right clause`, () => {
      expect(sections.has(section), `§${section} is not a section of -02`).toBe(true);
      const expected = MEANS[code];
      if (expected) {
        expect(sections.get(section),
          `${code} cites §${section}, which -02 titles "${sections.get(section)}" `
          + `rather than "${expected}" -- the section was probably renumbered`)
          .toBe(expected);
      }
    });
  }

  it('the titles embedded in the page match the draft', async () => {
    // The page carries titles so a clause reference explains itself on hover.
    // They were generated from the draft once; this is what keeps them true.
    const app = readFileSync(new URL('../src/app.js', import.meta.url), 'utf8');
    const block = app.slice(app.indexOf('const SECTION_TITLES = {'));
    const embedded = [...block.slice(0, block.indexOf('};')).matchAll(/'([0-9.]+)':\s*'([^']+)'/g)];
    expect(embedded.length).toBeGreaterThan(10);

    for (const [, number, title] of embedded) {
      expect(sections.get(number), `§${number} title drifted from the draft`).toBe(title);
    }
  });

  it('no cited clause is missing a title', () => {
    const app = readFileSync(new URL('../src/app.js', import.meta.url), 'utf8');
    const block = app.slice(app.indexOf('const SECTION_TITLES = {'));
    const embedded = new Set(
      [...block.slice(0, block.indexOf('};')).matchAll(/'([0-9.]+)':/g)].map((m) => m[1]),
    );
    const cited = new Set(Object.values(ERRORS).map((e) => e.section).filter(Boolean));
    const missing = [...cited].filter((s) => !embedded.has(s));
    // A citation with no title still renders and still links; it just shows the
    // bare number on hover. Worth knowing about rather than discovering later.
    expect(missing, `cited without a title: ${missing.join(', ')}`).toEqual([]);
  });
});
