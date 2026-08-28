/**
 * Signature wrapping, path traversal, and the single-entrance property.
 *
 * Companion to `security.test.js`, split out because these three ask a different
 * question. That file asks "is this mutation refused." These ask "can the thing
 * that was CHECKED be made to differ from the thing that is USED" — which is the
 * shape of attack that survives a validator passing every one of its own tests.
 *
 * ── Why this document is a candidate for wrapping ───────────────────────────
 *
 * XML Signature Wrapping (the SAML attack) works when the verifier and the
 * consumer resolve a name to DIFFERENT objects: the attacker leaves the signed
 * element where the verifier looks and puts the payload where the application
 * reads. One valid signature, two objects, and every cryptographic check passes.
 *
 * Neither signature here covers the whole document:
 *
 *   owner_sig -> an identity projection of `existing_cert`
 *   pa_sig    -> the complete -02 §9.4 policy document, `version` and `subject`
 *                included — both were outside the preimage under -01, and the
 *                first of those omissions was an exploitable replay
 *   unsigned  -> chain, certs, crl, audit, requested_scopes, authorization_bounds
 *
 * Every unsigned field adjacent to a signed one is somewhere the two can be made
 * to disagree. These cases pass today. They are written down because the field
 * projections are exactly the kind of thing a later change widens or narrows
 * without considering this property, and the failure mode would be silent: a
 * document that verifies, and then does something other than what was signed.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { readFile } from 'node:fs/promises';
import { runPipeline } from '../src/pipeline.js';
import { parseDocument } from '../src/validate-input.js';
import { buildDefaultDocument } from '../src/defaults.js';
import { assertSafePaths } from '../src/bounds.js';
import { locateFailure } from '../src/locate.js';
import { DenyError } from '../src/errors.js';

let base;
beforeAll(async () => { base = await buildDefaultDocument(); }, 60_000);

const kid = (d) => d.chain.find((n) => n.role === 'agent' && n.metadata?.parent_agent_id);

async function attack(mutate) {
  const d = JSON.parse(JSON.stringify(base));
  mutate(d, kid(d));
  try {
    const r = await runPipeline({ document: parseDocument(JSON.stringify(d)) });
    return { verdict: r.verdict, code: r.error_code };
  } catch (e) {
    if (e instanceof DenyError) return { verdict: 'DENY', code: e.code };
    return { verdict: 'THREW', code: `${e.constructor.name}: ${e.message}` };
  }
}

describe('signature wrapping (the JSON analogue of SAML XSW)', () => {
  it('refuses existing_cert describing a different agent than the chain', async () => {
    // The purest wrapping attempt: point the signed template at the PARENT while
    // the chain still carries the child, so the ceiling checked in §7.2 is not
    // the ceiling belonging to the subject being governed.
    //
    // It fails because owner_sig covers `agent_id`, `subject` and `agent_uuid` —
    // substituting the object changes the signed bytes. This is the reason the
    // identity projection must keep covering those three fields.
    const r = await attack((d) => { d.existing_cert = JSON.parse(JSON.stringify(d.chain[1].metadata)); });
    expect(r.verdict).toBe('DENY');
    // Under -02 this is caught EARLIER than it was under -01. §9.4 puts Subject
    // inside the policy document, so `assertOwnership` can see that the policy
    // does not name the agent the template governs and refuse on that basis,
    // before the signature is even consulted. -01 could only catch it as a
    // signature failure, which named the wrong cause.
    expect(r.code).toBe('ERR_OWNER_MISMATCH');
  });

  it('refuses escalation planted in the unsigned chain copy', async () => {
    // The inverse: leave the signed template benign and correctly signed, and
    // put the escalation in the chain, which no signature covers at all.
    //
    // It fails because §8.3 validates the chain on its own terms rather than
    // trusting that a valid signature somewhere else vouched for it.
    const r = await attack((_, child) => {
      child.metadata.allowed_scopes = ['admin:all'];
      child.metadata.authorization_bounds.allowed_scopes = ['admin:all'];
      child.requested_scopes = ['admin:all'];
    });
    expect(r.verdict).toBe('DENY');
    expect(r.code).toBe('ERR_SCOPE_ESCALATION');
  });

  it('refuses a widened ceiling in the signed template', async () => {
    const r = await attack((d) => { d.existing_cert.allowed_scopes = ['admin:all']; });
    expect(r.verdict).toBe('DENY');
  });

  it('refuses when the duplicated bounds disagree', async () => {
    // Duplicate keys are the other classic wrapping primitive: parsers disagree
    // on first-vs-last, so a signer and a verifier can legitimately read
    // different values from identical bytes.
    //
    // The bounds are carried twice here (once flat, once nested) because the
    // reference implementation reads the nested copy and the certificate profile
    // carries the flat one. Cross-checking them turns a parser disagreement into
    // a refusal instead of a silent choice between two answers.
    const r = await attack((_, child) => {
      child.metadata.authorization_bounds.allowed_scopes = ['admin:all'];
    });
    expect(r.verdict).toBe('DENY');
    expect(r.code).toBe('ERR_BOUNDS_UNPARSEABLE');
  });

  it('refuses a policy_doc whose signed projection is intact but padded', async () => {
    // pa_sig covers a filtered subset, so fields outside it are unsigned by
    // construction. The field guard is what stops that from being a gap: an
    // unknown key is refused rather than carried along unsigned.
    const r = await attack((d) => { d.policy_doc.shadow_scopes = ['admin:all']; });
    expect(r.verdict).toBe('DENY');
  });
});

/**
 * ── Path traversal ─────────────────────────────────────────────────────────
 *
 * `cert_path` and `key_path` are strings this page never dereferences, which is
 * precisely why they went unvalidated — and why the gap was invisible from
 * inside the browser.
 *
 * The document is designed to be RECONSTITUTED. The round-trip harness writes a
 * directory from an exported document, and so would any other consumer. A field
 * that survives validation reads as validated to whoever handles it next, so
 * "we never open it" is not a property the export can promise on their behalf.
 */
describe('path traversal in file-path metadata', () => {
  const VALID = 'certs/8f14e45f-ceea-467a-9c0f-7ad0f1b0d5aa.crt';

  for (const [label, value] of Object.entries({
    'relative traversal': '../../../../etc/passwd',
    'absolute path': '/etc/shadow',
    'traversal after a valid prefix': 'certs/../../../etc/passwd.crt',
    'double slash': 'certs//x.crt',
    'non-uuid filename': 'certs/not-a-uuid.crt',
    'wrong directory': 'keys/8f14e45f-ceea-467a-9c0f-7ad0f1b0d5aa.crt',
    'case-varied prefix': 'CERTS/8f14e45f-ceea-467a-9c0f-7ad0f1b0d5aa.crt',
    'trailing newline': `${VALID}\n`,
    'leading whitespace': `  ${VALID}`,
    'space-padded suffix': `${VALID} .txt`,
    'wrong extension': VALID.replace('.crt', '.sh'),
    'non-string': 42,
    'array': [VALID],
  })) {
    it(`refuses cert_path: ${label}`, () => {
      expect(() => assertSafePaths({ cert_path: value })).toThrow(DenyError);
    });
  }

  it('refuses a key_path carrying a certificate extension', () => {
    expect(() => assertSafePaths({ key_path: VALID })).toThrow(DenyError);
  });

  it('accepts exactly the shape setup_keys.py emits', () => {
    expect(() => assertSafePaths({
      cert_path: VALID,
      key_path: VALID.replace('.crt', '.key'),
    })).not.toThrow();
  });

  it('accepts a document that omits them entirely', () => {
    expect(() => assertSafePaths({})).not.toThrow();
  });
});

/**
 * ── One hardened entrance ──────────────────────────────────────────────────
 *
 * Everything this page acts on arrives through a single textarea. That is what
 * makes the input surface tractable to harden — and it is also why a SECOND,
 * unguarded read of that same textarea is the entire risk. One existed: the
 * export button called a bare `JSON.parse` on it, skipping the byte cap, the
 * forbidden-key guard and the depth limit.
 *
 * These pin the property rather than any single call site, because the next such
 * read will be added by someone who does not know this paragraph exists.
 */
describe('the editor is the only input, and it has one door', () => {
  it('no module reads the editor with a bare JSON.parse', async () => {
    const src = await readFile(new URL('../src/app.js', import.meta.url), 'utf8');
    expect(src).not.toMatch(/JSON\.parse\s*\(\s*docBox\.value/);
  });

  it('the highlighter survives malformed input rather than throwing', () => {
    // It runs on raw editor text BEFORE the document is known to be valid, so a
    // throw here takes out the render for input the validator would otherwise
    // have refused with a clean, readable error. Highlighting is best-effort by
    // nature — a key it cannot decode costs a highlight, never a verdict.
    for (const text of [
      '{\n  "\\q": 1\n}',              // invalid JSON escape — this one threw
      '{\n  "\\": 1\n}',               // trailing backslash
      '{\n  "a": "\\u00"\n}',          // truncated unicode escape
      `{"a":${'['.repeat(500)}`,       // unbalanced open
      ']'.repeat(500),                 // unbalanced close
      '{"__proto__": {"a": 1}}',
      '\u0000\u0001\u0002',
      '',
      '   ',
    ]) {
      expect(() => locateFailure(text, { path: ['a', 'b'], values: ['x'] })).not.toThrow();
    }
  });

  it('exports a structured error rather than throwing on unparseable input', async () => {
    const src = await readFile(new URL('../src/app.js', import.meta.url), 'utf8');
    expect(src).toMatch(/parseDocument\(docBox\.value/);
    expect(src).toMatch(/ERR_UNPARSEABLE/);
  });
});
