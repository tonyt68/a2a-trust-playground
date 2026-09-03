/**
 * Adversarial corpus — the security properties, as regression tests.
 *
 * Every case here was found by attacking the running code, not by reading it.
 * They live here so a later refactor cannot quietly undo them — a fail-open bug
 * does not announce itself in a green unit suite.
 *
 * The single most valuable habit encoded here: assert the SPECIFIC refusal, not
 * merely that something was refused. A test that accepts any DENY passes when a
 * document is rejected for an unrelated reason, which is how a real gap hides
 * behind a green check.
 *
 * Under -03 the attack surface moved. Authority lives in CA-signed certificate
 * extensions, so "edit the bound in the document" is no longer an attack the
 * document can carry — it is refused as an unknown field before any bound is
 * read. The attacks that remain are on the things the document still asserts:
 * identifiers, requests, envelopes, revocation state and the audit chain — and
 * on certificates a rogue CA could issue.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { runPipeline } from '../src/pipeline.js';
import { parseDocument } from '../src/validate-input.js';
import { buildDefaultDocument } from '../src/defaults.js';
import { childOf, parentOf, issueRaw } from '../src/scenarios.js';
import { DenyError } from '../src/errors.js';

let base, now;
beforeAll(async () => { now = new Date(); base = await buildDefaultDocument({ now }); }, 30_000);

const clone = () => JSON.parse(JSON.stringify(base));

/** Apply a mutation, run it through the real entry point, return the refusal. */
async function attack(mutate) {
  const doc = clone();
  await mutate(doc);
  try {
    const parsed = parseDocument(JSON.stringify(doc));
    const r = await runPipeline({ document: parsed, now: new Date() });
    return { verdict: r.verdict, code: r.error_code };
  } catch (e) {
    if (e instanceof DenyError) return { verdict: 'DENY', code: e.code };
    return { verdict: 'THREW', code: `${e.constructor.name}: ${e.message}` };
  }
}

const ATTACKS = [
  // ── Injection and pollution ───────────────────────────────────────────────
  { name: '__proto__ key', expect: 'ERR_PROTOTYPE_POLLUTION',
    mutate: (d) => Object.defineProperty(d, '__proto__',
      { value: { polluted: true }, enumerable: true, configurable: true, writable: true }) },
  { name: 'constructor key', expect: 'ERR_PROTOTYPE_POLLUTION',
    mutate: (d) => { d.constructor = { x: 1 }; } },
  { name: 'prototype key nested in metadata', expect: 'ERR_PROTOTYPE_POLLUTION',
    mutate: (d) => { childOf(d).metadata.prototype = { x: 1 }; } },
  { name: 'injected authorization fields in metadata (admin, rebac_override)', expect: 'ERR_SCHEMA_VIOLATION',
    mutate: (d) => { childOf(d).metadata.admin = true; childOf(d).metadata.rebac_override = true; } },
  { name: 'a -02 bound smuggled into metadata', expect: 'ERR_SCHEMA_VIOLATION',
    mutate: (d) => { childOf(d).metadata.allowed_scopes = ['admin:all']; } },
  { name: 'a -02 envelope key at the top level', expect: 'ERR_SCHEMA_VIOLATION',
    mutate: (d) => { d.policy_doc = d.policy.body; } },
  { name: 'a duplicate member, which JSON.parse would have collapsed', expect: 'ERR_DUPLICATE_MEMBER',
    mutate: (d) => { d.__dup__ = true; } },

  // ── Identity spoofing ─────────────────────────────────────────────────────
  { name: 'uppercase UUID', expect: 'ERR_AGENT_ID_FORMAT',
    mutate: (d) => { childOf(d).metadata.agent_id = childOf(d).metadata.agent_id.toUpperCase(); } },
  { name: 'agent_id as an array', expect: 'ERR_AGENT_ID_FORMAT',
    mutate: (d) => { childOf(d).metadata.agent_id = ['x']; } },
  { name: 'agent_id naming a different agent than the certificate', expect: 'ERR_SUBJECT_MISMATCH',
    mutate: (d) => { childOf(d).metadata.agent_id = '019b3c8e-2f10-7a4b-9c6d-3e5f7a9b1c2d'; } },
  { name: 'homoglyph scope in the request (Cyrillic e)', expect: 'ERR_SCOPE_SYNTAX',
    mutate: (d) => { childOf(d).requested_scopes = ['rеad:events']; } },
  { name: 'wildcard scope in the request', expect: 'ERR_SCOPE_SYNTAX',
    mutate: (d) => { childOf(d).requested_scopes = ['read:*']; } },

  // ── Certificate substitution ──────────────────────────────────────────────
  { name: 'parent and child certificates swapped', expect: 'ERR_SUBJECT_MISMATCH',
    mutate: (d) => { const p = parentOf(d); const c = childOf(d); [p.cert_pem, c.cert_pem] = [c.cert_pem, p.cert_pem]; } },
  { name: "child's certificate used for the parent", expect: 'ERR_SUBJECT_MISMATCH',
    mutate: (d) => { parentOf(d).cert_pem = childOf(d).cert_pem; } },
  { name: 'certificate body corrupted', expect: 'ERR_CHAIN_INVALID',
    mutate: (d) => { const c = childOf(d); const L = c.cert_pem.split('\n'); const m = Math.floor(L.length / 2);
      L[m] = (L[m].startsWith('A') ? 'B' : 'A') + L[m].slice(1); c.cert_pem = L.join('\n'); } },
  { name: 'an authority certificate presented as the child', expect: 'ERR_AGENT_ID_FORMAT',
    mutate: (d) => { childOf(d).cert_pem = d.authorities.owner.cert_pem; childOf(d).metadata.agent_id = 'owner-authority'; } },

  // ── What a rogue CA could issue ───────────────────────────────────────────
  { name: 'a child certificate claiming a different parent than the chain', expect: 'ERR_PARENT_MISMATCH',
    mutate: async (d) => { await issueRaw(d, childOf(d), { spawn: { parent_agent_id: '019b3c8e-2f10-7a4b-9c6d-3e5f7a9b1c2d',
      spawned_at: now.toISOString(), spawn_nonce: Buffer.alloc(16, 2).toString('base64') } }); } },
  { name: 'a child whose template subject is the parent', expect: 'ERR_SUBJECT_MISMATCH',
    mutate: async (d) => { await issueRaw(d, childOf(d), { template: { subject: parentOf(d).metadata.agent_id } }); } },
  { name: 'a template with a 65-character scope', expect: 'ERR_SCOPE_SYNTAX',
    mutate: async (d) => { await issueRaw(d, childOf(d), { template: { allowed_scopes: ['a'.repeat(65)] } }); } },
  { name: 'a template extension over the size limit is refused before it is parsed (§8.2)', expect: 'ERR_TEMPLATE_EXT_INVALID',
    mutate: async (d) => { await issueRaw(d, childOf(d), { template: { can_spawn: Array.from({ length: 120 }, (_, i) =>
      `019b3c8e-2f10-7a4b-9c6d-3e5f7a9b${String(i).padStart(4, '0')}`) } }); } },
  { name: 'a certificate over the PEM cap is refused before any parser sees it', expect: 'ERR_MALFORMED_PEM',
    mutate: async (d) => { await issueRaw(d, childOf(d), { template: { allowed_scopes: ['a'.repeat(100000)] } }); } },
  { name: 'a template with a nested member', expect: 'ERR_OBJECT_NOT_FLAT',
    mutate: async (d) => { await issueRaw(d, childOf(d), { template: { policy_ref: { a: 1 } } }); } },
  { name: 'a template with an unknown member', expect: 'ERR_TEMPLATE_EXT_INVALID',
    mutate: async (d) => { await issueRaw(d, childOf(d), { template: { issuer: 'x' } }); } },
  { name: 'a child template holding a scope the parent never had', expect: 'ERR_SCOPE_ESCALATION',
    mutate: async (d) => { await issueRaw(d, childOf(d), { template: { allowed_scopes: ['read:events', 'admin:all'] } }); delete d.policy; } },
  { name: 'a spawn nonce of 8 bits', expect: 'ERR_SPAWN_EXT_INVALID',
    mutate: async (d) => { await issueRaw(d, childOf(d), { spawn: { parent_agent_id: parentOf(d).metadata.agent_id,
      spawned_at: now.toISOString(), spawn_nonce: 'AA==' } }); } },
  { name: 'a spawned_at with an offset', expect: 'ERR_TIMESTAMP_FORMAT',
    mutate: async (d) => { await issueRaw(d, childOf(d), { spawn: { parent_agent_id: parentOf(d).metadata.agent_id,
      spawned_at: '2026-09-03T00:00:00+00:00', spawn_nonce: Buffer.alloc(16, 3).toString('base64') } }); } },

  // ── Signature attacks ─────────────────────────────────────────────────────
  { name: 'signature bit-flip (malleability)', expect: 'ERR_PA_SIG_INVALID',
    mutate: (d) => { const b = Buffer.from(d.policy.pa_sig, 'base64'); b[b.length - 1] ^= 1; d.policy.pa_sig = b.toString('base64'); } },
  { name: 'owner_sig replayed as pa_sig', expect: 'ERR_PA_SIG_INVALID',
    mutate: (d) => { d.policy.pa_sig = d.policy.owner_sig; } },
  { name: 'signature dropped entirely', expect: 'ERR_PA_SIG_MISSING',
    mutate: (d) => { d.policy.pa_sig = null; } },
  { name: 'signature is not base64', expect: 'ERR_PA_SIG_INVALID',
    mutate: (d) => { d.policy.pa_sig = 'not base64!!'; } },
  { name: 'signature in DER instead of r‖s', expect: 'ERR_SIGNATURE_ALGORITHM',
    mutate: (d) => { d.policy.pa_sig = Buffer.alloc(70, 4).toString('base64'); } },
  { name: 'an extra envelope member carrying a third signature', expect: 'ERR_ENVELOPE_MEMBER',
    mutate: (d) => { d.policy.admin_sig = d.policy.pa_sig; } },

  // ── Structural ambiguity ──────────────────────────────────────────────────
  { name: 'two trust anchors', expect: 'ERR_CHAIN_INVALID',
    mutate: (d) => { d.chain.push({ role: 'ca', cert_pem: d.chain[0].cert_pem, metadata: { subject: 'second-anchor' } }); } },
  { name: 'the same agent appears twice', expect: 'ERR_DUPLICATE_SUBJECT',
    mutate: (d) => { d.chain.push(JSON.parse(JSON.stringify(childOf(d)))); } },
  { name: 'a chain node with an unrecognised role', expect: 'ERR_SCHEMA_VIOLATION',
    mutate: (d) => { d.chain.push({ role: 'sidecar', cert_pem: 'x', metadata: {} }); } },
  { name: 'child names itself as its parent', expect: 'ERR_PARENT_MISMATCH',
    mutate: (d) => { childOf(d).metadata.parent_agent_id = childOf(d).metadata.agent_id; } },
  { name: 'chain is a string', expect: 'ERR_SCHEMA_VIOLATION',
    mutate: (d) => { d.chain = 'everything'; } },
  { name: 'the parent removed from the chain', expect: 'ERR_PARENT_MISMATCH',
    mutate: (d) => { d.chain = d.chain.filter((n) => n !== parentOf(d)); } },

  // ── Numeric and type confusion in the things the document still carries ──
  { name: 'requested_scopes null', expect: 'ERR_SCHEMA_VIOLATION',
    mutate: (d) => { childOf(d).requested_scopes = null; } },
  { name: 'duplicate requested scopes', expect: 'ERR_SCHEMA_VIOLATION',
    mutate: (d) => { childOf(d).requested_scopes = ['read:events', 'read:events']; } },
  { name: 'policy version as a string — refused before any signature is checked', expect: 'ERR_POLICY_VERSION',
    mutate: (d) => { d.policy.body.version = '2'; } },
  { name: 'policy version as Infinity (serialises to null)', expect: 'ERR_OBJECT_NOT_FLAT',
    mutate: (d) => { d.policy.body.version = 1e999; } },
  { name: 'current_policy_version claimed higher than the policy', expect: 'ERR_POLICY_VERSION',
    mutate: (d) => { d.current_policy_version = 99; } },

  // ── Audit forgery ─────────────────────────────────────────────────────────
  { name: 'forged audit entry with a made-up hash', expect: 'ERR_AUDIT_CHAIN_BROKEN',
    mutate: (d) => { d.audit = { chain: [{ index: 0, timestamp: 't', previous_hash: 'genesis', event: { decision: 'ALLOWED' }, hash: '0'.repeat(64) }] }; } },
  { name: 'an audit entry removed from the middle', expect: 'ERR_AUDIT_CHAIN_BROKEN',
    mutate: (d) => { d.audit.chain.splice(1, 1); } },

  // ── Authority substitution ────────────────────────────────────────────────
  { name: 'policy submitted by the wrong owner', expect: 'ERR_OWNER_MISMATCH',
    mutate: (d) => { d.policy.body.owner = 'attacker@example.com'; } },
  { name: 'authority certificate off a different CA', expect: 'ERR_AUTHORITY_CHAIN',
    mutate: (d) => { d.authorities.pa.cert_pem = d.chain[0].cert_pem; } },
  { name: 'the Owner certificate swapped for the Policy Authority’s', expect: 'ERR_AUTHORITY_CHAIN',
    mutate: (d) => { d.authorities.owner.cert_pem = d.authorities.pa.cert_pem; } },
];

/** The duplicate-member case cannot be expressed as an object mutation; it is inserted into the text. */
async function attackText(edit) {
  const text = edit(JSON.stringify(clone()));
  try {
    const r = await runPipeline({ document: parseDocument(text), now: new Date() });
    return { verdict: r.verdict, code: r.error_code };
  } catch (e) {
    if (e instanceof DenyError) return { verdict: 'DENY', code: e.code };
    return { verdict: 'THREW', code: `${e.constructor.name}: ${e.message}` };
  }
}

describe('adversarial corpus — each attack must produce its SPECIFIC refusal', () => {
  for (const a of ATTACKS) {
    it(a.name, async () => {
      const r = a.name.startsWith('a duplicate member')
        ? await attackText((t) => t.replace('"crl":', '"crl":{"revoked":[]},"crl":'))
        : await attack(a.mutate);
      expect(r.verdict, `expected DENY, got ${r.verdict} (${r.code})`).toBe('DENY');
      expect(r.code).toBe(a.expect);
    });
  }

  it('Object.prototype is never polluted, even while refusing', async () => {
    for (const a of ATTACKS.slice(0, 4)) await attack(a.mutate);
    expect({}.polluted).toBeUndefined();
    expect(Object.prototype.polluted).toBeUndefined();
  });
});

describe('behaviour that is correct and must NOT become a refusal', () => {
  it('removing the policy is legitimate — nothing to check, nothing granted', async () => {
    const r = await attack((d) => { delete d.policy; });
    expect(r.verdict).toBe('PASS');
  });
  it('an audit entry count claimed in the document is ignored, not trusted', async () => {
    const doc = clone();
    doc.audit = { chain: [], entries: 999 };
    const result = await runPipeline({ document: parseDocument(JSON.stringify(doc)), now });
    expect(result.audit.entries).toBeLessThan(999);
  });
  it('a v4 identifier is as valid as the v7 the page mints', async () => {
    // Re-issuing under a v4 subject takes a CA; the identifier format check is
    // the point here, and validateUuid accepts both.
    const { validateUuid } = await import('../src/validate-input.js');
    expect(validateUuid('8f14e45f-ceea-467a-9c0f-7ad0f1b0d5aa')).toBeTruthy();
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
    'an array at the root': '[1,2,3]', 'a bare scalar': '"hello"', 'null': 'null', 'truncated JSON': '{"chain":',
  })) {
    it(`rejects ${name}`, () => expect(() => parseDocument(text)).toThrow(DenyError));
  }
  it('never leaks the parser message, which can echo input', () => {
    try { parseDocument('{"a":'); } catch (e) {
      expect(e.message).not.toMatch(/position|token|Unexpected/i);
    }
  });
});
