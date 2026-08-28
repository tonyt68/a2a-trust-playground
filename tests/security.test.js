/**
 * Adversarial corpus — the security properties, as regression tests.
 *
 * Every case here was found by attacking the running code, not by reading it.
 * Several passed the first time and several did not; the ones that did not are
 * marked with what they caught. They live here so a later refactor cannot
 * quietly undo them — which is the whole point, because a fail-open bug does not
 * announce itself in a green unit suite.
 *
 * ── Reusing this in another tool ────────────────────────────────────────────
 *
 * The structure is deliberately portable. `ATTACKS` is a flat list of
 * {name, mutate, expect} — a mutation applied to a known-good document, and the
 * refusal it must produce. To adapt this to a different validator, replace
 * `buildDefaultDocument`/`runPipeline` with that system's equivalent and keep
 * the corpus. The categories generalise to anything that validates a signed,
 * structured document:
 *
 *   identity spoofing · type confusion · numeric bounds · prototype pollution
 *   signature malleability · structural ambiguity · resource exhaustion
 *   unknown-field acceptance · injection into rendered fields
 *
 * The single most valuable habit encoded here: assert the SPECIFIC refusal, not
 * merely that something was refused. A test that accepts any DENY passes when a
 * document is rejected for an unrelated reason, which is how a real gap hides
 * behind a green check. Two findings in this file were originally masked exactly
 * that way.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { runPipeline } from '../src/pipeline.js';
import { parseDocument } from '../src/validate-input.js';
import { buildDefaultDocument } from '../src/defaults.js';
import { DenyError } from '../src/errors.js';

let base;
beforeAll(async () => { base = await buildDefaultDocument(); }, 60_000);

const clone = () => JSON.parse(JSON.stringify(base));
const child = (d) => d.chain.find((n) => n.role === 'agent' && n.metadata?.parent_agent_id);
const parent = (d) => d.chain.find((n) => n.role === 'agent' && !n.metadata?.parent_agent_id);

/** Apply a mutation, run it through the real entry point, return the refusal. */
async function attack(mutate) {
  const doc = clone();
  mutate(doc);
  try {
    const parsed = parseDocument(JSON.stringify(doc));
    const r = await runPipeline({ document: parsed });
    return { verdict: r.verdict, code: r.error_code };
  } catch (e) {
    if (e instanceof DenyError) return { verdict: 'DENY', code: e.code };
    return { verdict: 'THREW', code: `${e.constructor.name}: ${e.message}` };
  }
}

/**
 * The corpus. `expect` is the exact error code required — see the note above on
 * why "any DENY" is not good enough.
 */
const ATTACKS = [
  // ── Injection and pollution ───────────────────────────────────────────────
  // `d.__proto__ = {...}` sets the PROTOTYPE — it does not create an own key, so
  // JSON.stringify drops it and the attack silently becomes a no-op. Creating a
  // real own "__proto__" key needs defineProperty (or JSON.parse, which is how a
  // pasted document would carry one). Worth knowing: the naive version of this
  // test passes while testing nothing.
  { name: '__proto__ key', expect: 'ERR_PROTOTYPE_POLLUTION',
    mutate: (d) => Object.defineProperty(d, '__proto__',
      { value: { polluted: true }, enumerable: true, configurable: true, writable: true }) },
  { name: 'constructor key', expect: 'ERR_PROTOTYPE_POLLUTION',
    mutate: (d) => { d.constructor = { x: 1 }; } },
  { name: 'prototype key nested in metadata', expect: 'ERR_PROTOTYPE_POLLUTION',
    mutate: (d) => { child(d).metadata.prototype = { x: 1 }; } },
  // FOUND A BUG: unknown metadata fields were accepted. They are inert, which is
  // exactly why silently keeping them is wrong — a key that survives validation
  // reads as meaningful.
  { name: 'injected authorization fields (admin, rebac_override)', expect: 'ERR_SCHEMA_VIOLATION',
    mutate: (d) => { child(d).metadata.admin = true; child(d).metadata.rebac_override = true; } },

  // ── Identity spoofing ─────────────────────────────────────────────────────
  { name: 'uppercase UUID', expect: 'ERR_AGENT_ID_FORMAT',
    mutate: (d) => { const c = child(d); const u = c.metadata.agent_id.toUpperCase();
      c.metadata.agent_id = u; c.metadata.agent_uuid = u; } },
  { name: 'agent_id as an array', expect: 'ERR_AGENT_ID_FORMAT',
    mutate: (d) => { child(d).metadata.agent_id = ['x']; } },
  { name: 'agent_id and agent_uuid disagree', expect: 'ERR_SCHEMA_VIOLATION',
    mutate: (d) => { child(d).metadata.agent_uuid = parent(d).metadata.agent_id; } },
  { name: 'homoglyph scope (Cyrillic e)', expect: 'ERR_FIELD_CHARSET',
    mutate: (d) => { const c = child(d); const s = ['rеad:events'];
      c.metadata.allowed_scopes = s; c.metadata.authorization_bounds.allowed_scopes = s;
      c.requested_scopes = s; } },
  { name: 'state with a trailing space', expect: 'ERR_AGENT_DISABLED',
    mutate: (d) => { child(d).metadata.state = 'ACTIVE '; } },
  { name: 'state in lowercase', expect: 'ERR_AGENT_DISABLED',
    mutate: (d) => { child(d).metadata.state = 'active'; } },

  // ── Certificate substitution ──────────────────────────────────────────────
  { name: 'parent and child certificates swapped', expect: 'ERR_SUBJECT_MISMATCH',
    mutate: (d) => { const p = parent(d); const c = child(d);
      [p.cert_pem, c.cert_pem] = [c.cert_pem, p.cert_pem]; } },
  { name: "child's certificate used for the parent", expect: 'ERR_SUBJECT_MISMATCH',
    mutate: (d) => { parent(d).cert_pem = child(d).cert_pem; } },
  { name: 'certificate body corrupted', expect: 'ERR_CHAIN_INVALID',
    mutate: (d) => { const c = child(d); const L = c.cert_pem.split('\n');
      const m = Math.floor(L.length / 2);
      L[m] = (L[m].startsWith('A') ? 'B' : 'A') + L[m].slice(1); c.cert_pem = L.join('\n'); } },

  // ── Signature attacks ─────────────────────────────────────────────────────
  { name: 'signature bit-flip (malleability)', expect: 'ERR_PA_SIG_INVALID',
    mutate: (d) => { const b = Buffer.from(d.pa_sig, 'base64');
      b[b.length - 1] ^= 1; d.pa_sig = b.toString('base64'); } },
  { name: 'owner_sig replayed as pa_sig', expect: 'ERR_PA_SIG_INVALID',
    mutate: (d) => { d.pa_sig = d.owner_sig; } },
  { name: 'signature dropped entirely', expect: 'ERR_PA_SIG_MISSING',
    mutate: (d) => { d.pa_sig = null; } },
  { name: 'signature is not base64', expect: 'ERR_PA_SIG_INVALID',
    mutate: (d) => { d.pa_sig = 'not base64!!'; } },

  // ── Structural ambiguity ──────────────────────────────────────────────────
  // FOUND A BUG: a second trust anchor was silently ignored, so the result
  // depended on which one happened to be first.
  { name: 'two trust anchors', expect: 'ERR_CHAIN_INVALID',
    mutate: (d) => { d.chain.push({ role: 'ca', cert_pem: d.chain[0].cert_pem,
      metadata: { subject: 'second-anchor' } }); } },
  // FOUND A BUG: the same identity twice was counted twice against max_children.
  { name: 'the same agent appears twice', expect: 'ERR_SCHEMA_VIOLATION',
    mutate: (d) => { d.chain.push(JSON.parse(JSON.stringify(child(d)))); } },
  { name: 'a chain node with an unrecognised role', expect: 'ERR_SCHEMA_VIOLATION',
    mutate: (d) => { d.chain.push({ role: 'sidecar', cert_pem: 'x', metadata: {} }); } },
  { name: 'child names itself as its parent', expect: 'ERR_CHILD_NOT_WHITELISTED',
    mutate: (d) => { child(d).metadata.parent_agent_id = child(d).metadata.agent_id; } },
  { name: 'chain is a string', expect: 'ERR_SCHEMA_VIOLATION',
    mutate: (d) => { d.chain = 'everything'; } },

  // ── Numeric and type confusion ────────────────────────────────────────────
  { name: 'max_children as a string', expect: 'ERR_FIELD_RANGE',
    mutate: (d) => { const p = parent(d); p.metadata.max_children = '2';
      p.metadata.authorization_bounds.max_children = '2'; } },
  { name: 'negative max_children', expect: 'ERR_FIELD_RANGE',
    mutate: (d) => { const p = parent(d); p.metadata.max_children = -1;
      p.metadata.authorization_bounds.max_children = -1; } },
  { name: 'max_children beyond the cap', expect: 'ERR_FIELD_RANGE',
    mutate: (d) => { const p = parent(d); p.metadata.max_children = 999999999;
      p.metadata.authorization_bounds.max_children = 999999999; } },
  // FOUND A BUG: ttl_seconds is §7.1 REQUIRED and nothing validated it, so
  // `1e999` (which serialises to null) passed.
  { name: 'ttl_seconds as Infinity', expect: 'ERR_FIELD_RANGE',
    mutate: (d) => { child(d).metadata.ttl_seconds = 1e999; } },
  { name: 'allowed_scopes null', expect: 'ERR_SCHEMA_VIOLATION',
    mutate: (d) => { const c = child(d); c.metadata.allowed_scopes = null;
      c.metadata.authorization_bounds.allowed_scopes = null; } },
  { name: 'duplicate scope entries', expect: 'ERR_SCHEMA_VIOLATION',
    mutate: (d) => { const c = child(d); const s = ['read:events', 'read:events'];
      c.metadata.allowed_scopes = s; c.metadata.authorization_bounds.allowed_scopes = s; } },
  { name: 'bounds copies disagree', expect: 'ERR_BOUNDS_UNPARSEABLE',
    mutate: (d) => { child(d).metadata.authorization_bounds.max_children = 99; } },

  // ── Resource exhaustion ───────────────────────────────────────────────────
  { name: 'a 100,000-character scope', expect: 'ERR_FIELD_CHARSET',
    mutate: (d) => { const c = child(d); const s = ['a'.repeat(100000)];
      c.metadata.allowed_scopes = s; c.metadata.authorization_bounds.allowed_scopes = s; } },

  // ── Audit forgery ─────────────────────────────────────────────────────────
  { name: 'forged audit entry with a made-up hash', expect: 'ERR_AUDIT_CHAIN_BROKEN',
    mutate: (d) => { d.audit = { chain: [{ index: 0, timestamp: 't',
      previous_hash: 'genesis', event: { decision: 'ALLOWED' }, hash: '0'.repeat(64) }] }; } },

  // ── Authority substitution ────────────────────────────────────────────────
  { name: 'policy submitted by the wrong owner', expect: 'ERR_OWNER_MISMATCH',
    mutate: (d) => { d.policy_doc.owner = 'attacker@example.com'; } },
  { name: 'authority certificate off a different CA', expect: 'ERR_AUTHORITY_CHAIN',
    mutate: (d) => { d.authorities.pa.cert_pem = d.chain[0].cert_pem; } },
];

describe('adversarial corpus — each attack must produce its SPECIFIC refusal', () => {
  for (const a of ATTACKS) {
    it(a.name, async () => {
      const r = await attack(a.mutate);
      expect(r.verdict, `expected DENY, got ${r.verdict} (${r.code})`).toBe('DENY');
      expect(r.code).toBe(a.expect);
    });
  }

  it('nothing in the corpus crashes the validator', async () => {
    for (const a of ATTACKS) {
      const r = await attack(a.mutate);
      expect(r.verdict, `${a.name} threw: ${r.code}`).not.toBe('THREW');
    }
  }, 60_000);

  it('Object.prototype is never polluted, even while refusing', async () => {
    for (const a of ATTACKS) await attack(a.mutate);
    expect({}.polluted).toBeUndefined();
    expect(Object.prototype.polluted).toBeUndefined();
  }, 60_000);
});

describe('behaviour that is correct and must NOT become a refusal', () => {
  // These looked like findings during the red-team pass and are not. Pinned so a
  // later "hardening" change cannot turn a legitimate document into an error.
  it('removing the policy update is legitimate — nothing to check, nothing granted', async () => {
    const r = await attack((d) => { delete d.policy_update; });
    expect(r.verdict).toBe('PASS');
  });

  it('an audit entry count claimed in the document is ignored, not trusted', async () => {
    const doc = clone();
    doc.audit = { chain: [], entries: 999 };
    const result = await runPipeline({ document: parseDocument(JSON.stringify(doc)) });
    // The count reported comes from the real chain, not the claim.
    expect(result.audit.entries).toBeLessThan(999);
  });
});

describe('the input contract holds at the boundary', () => {
  const OVERSIZED = JSON.stringify({ pad: 'x'.repeat(300_000) });
  it('rejects an oversized document before parsing it', () => {
    expect(() => parseDocument(OVERSIZED)).toThrow(DenyError);
  });

  it('rejects a nesting bomb rather than overflowing the stack', () => {
    let s = '1';
    for (let i = 0; i < 400; i++) s = `{"n":${s}}`;
    expect(() => parseDocument(s)).toThrow(DenyError);
  });

  for (const [name, text] of Object.entries({
    'an array at the root': '[1,2,3]',
    'a bare scalar': '"hello"',
    'null': 'null',
    'truncated JSON': '{"chain":',
  })) {
    it(`rejects ${name}`, () => expect(() => parseDocument(text)).toThrow(DenyError));
  }

  it('never leaks the parser message, which can echo input', () => {
    try { parseDocument('{"a":'); } catch (e) {
      expect(e.message).not.toMatch(/position|token|Unexpected/i);
    }
  });
});
