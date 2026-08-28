/**
 * Canonicalization — RFC 8785 (JCS), per `-02` §9.5.
 *
 * ── What the oracle is, and why it changed ─────────────────────────────────
 *
 * These tests used to assert byte-equality with `ietf-a2a-trust-poc`'s Python.
 * That was the best available oracle while `-01` specified no canonicalization
 * at all, and it was also circular: it proved the browser agreed with one
 * particular program, not that either agreed with a specification. A second
 * implementer could not have used it, which was the whole problem.
 *
 * `-02` §9.5 cites RFC 8785, so the oracle is now the RFC. The fixture carries
 * two kinds of vector and the distinction is load-bearing:
 *
 *   RFC 8785            — transcribed from the specification. Authoritative.
 *   python-differential — computed by Python's serializer configured to match
 *                         JCS. Independent implementation, another language,
 *                         valid only where the two schemes agree.
 *
 * They disagree in exactly one place: JCS sorts keys by UTF-16 code unit
 * (§3.2.3) and Python's `sort_keys` sorts by Unicode code point. Identical
 * across the BMP, different above it. Astral key ordering is therefore asserted
 * against the RFC only, and the generator refuses to emit a Python answer for
 * it — see scripts/gen_canonical_vectors.py.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  canonicalize,
  extractIdentityFields,
  extractPolicyFields,
  IDENTITY_FIELDS,
  POLICY_FIELDS,
  CanonicalError,
} from '../src/canonical.js';

const vectors = JSON.parse(
  readFileSync(fileURLToPath(new URL('./fixtures/canonical_vectors.json', import.meta.url)), 'utf8'),
);

describe('RFC 8785 conformance', () => {
  const normative = vectors.filter((v) => v.source === 'RFC 8785');

  it('the fixture actually carries normative vectors', () => {
    expect(normative.length).toBeGreaterThanOrEqual(15);
  });

  for (const { name, value, expected } of normative) {
    it(`[RFC 8785] ${name}`, () => {
      expect(canonicalize(value)).toBe(expected);
    });
  }
});

describe('differential against an independent implementation', () => {
  for (const { name, value, expected } of vectors.filter((v) => v.source !== 'RFC 8785')) {
    it(`[python] ${name}`, () => {
      expect(canonicalize(value)).toBe(expected);
    });
  }
});

describe('the two properties JCS exists to provide', () => {
  it('is stable under key reordering', () => {
    // The point of a canonical form: two documents that differ only in property
    // order must produce identical bytes, because JSON object order is not
    // semantic and a signature over bytes would otherwise be order-dependent.
    const a = { z: 1, m: { d: 4, c: 3 }, a: [1, 2] };
    const b = { a: [1, 2], z: 1, m: { c: 3, d: 4 } };
    expect(canonicalize(a)).toBe(canonicalize(b));
  });

  it('is not stable under array reordering', () => {
    // The complement, and equally important: array order IS semantic. A scope
    // list is ordered data, and a canonicalizer that sorted it would silently
    // make ["read","write"] and ["write","read"] the same document.
    expect(canonicalize({ s: ['read', 'write'] })).not.toBe(canonicalize({ s: ['write', 'read'] }));
  });

  it('round-trips through JSON.parse unchanged', () => {
    const doc = { z: 1, a: { 'ὑ0': 'x', b: [1, 2] }, 'é': 'café' };
    expect(canonicalize(JSON.parse(canonicalize(doc)))).toBe(canonicalize(doc));
  });
});

describe('divergence from the superseded Python-parity scheme', () => {
  // These assertions exist to make the -02 change visible and deliberate rather
  // than incidental. Each is a case where the old serializer produced different
  // bytes, which is why every signature made under -01 stops verifying.
  it('non-ASCII is raw UTF-8, not \\uXXXX', () => {
    expect(canonicalize({ k: 'café' })).toBe('{"k":"café"}');
    expect(canonicalize({ k: 'café' })).not.toContain('\\u00e9');
  });

  it('astral keys sort by UTF-16 code unit, the opposite of Python', () => {
    // U+1F510 is a surrogate pair beginning 0xD83D, which is below 0xFFFD in
    // UTF-16 order and above it in code-point order.
    const out = canonicalize({ '\u{1F510}': 1, '�': 2 });
    expect(out.indexOf('\u{1F510}')).toBeLessThan(out.indexOf('�'));
  });

  it('there is exactly one canonical form, not a compact and a spaced one', async () => {
    // -01's implementation carried two serializations because the reference
    // implementation called json.dumps two different ways in two different
    // files. §9.5 specifies a single form for signatures and hashes alike.
    const mod = await import('../src/canonical.js');
    expect(mod.canonicalCompact).toBeUndefined();
    expect(mod.canonicalSpaced).toBeUndefined();
    expect(typeof mod.canonicalize).toBe('function');
  });
});

describe('the -02 field sets', () => {
  it('the policy field set is exactly §9.4', () => {
    expect([...POLICY_FIELDS].sort()).toEqual([
      'issued_at', 'not_after', 'org_id', 'scopes',
      'spawn_targets', 'subject', 'version',
    ].concat(['owner']).sort());
  });

  it('version is inside the signed policy set', () => {
    // The single most important assertion in this file. Its absence was an
    // exploitable replay: an attacker holding no key could take a superseded
    // but validly signed policy, increment the version, and have it accepted.
    expect(POLICY_FIELDS.has('version')).toBe(true);
  });

  it('subject is inside the signed policy set', () => {
    // Binds the policy to the agent it governs, so a policy signed for one
    // agent cannot be presented for another.
    expect(POLICY_FIELDS.has('subject')).toBe(true);
  });

  it('the content hash is never part of its own preimage', () => {
    expect(POLICY_FIELDS.has('content_hash')).toBe(false);
    expect(POLICY_FIELDS.has('policy_content_hash')).toBe(false);
  });

  it('signatures are never part of the signed set', () => {
    for (const f of ['owner_sig', 'pa_sig']) {
      expect(POLICY_FIELDS.has(f)).toBe(false);
      expect(IDENTITY_FIELDS.has(f)).toBe(false);
    }
  });

  it('extraction drops everything outside the set', () => {
    const doc = { subject: 'x', scopes: ['a'], version: 1, injected: true, __proto__: {} };
    expect(Object.keys(extractPolicyFields(doc)).sort()).toEqual(['scopes', 'subject', 'version']);
  });

  it('identity extraction covers all three identity fields', () => {
    // §7.1 carries the identity three times; a signature binding only one of
    // them leaves the others free to disagree.
    for (const f of ['subject', 'agent_id', 'agent_uuid']) {
      expect(IDENTITY_FIELDS.has(f)).toBe(true);
    }
    const out = extractIdentityFields({ subject: 'a', agent_id: 'a', agent_uuid: 'a', junk: 1 });
    expect(Object.keys(out).sort()).toEqual(['agent_id', 'agent_uuid', 'subject']);
  });
});

describe('fails closed on values it cannot canonicalize', () => {
  it('refuses non-finite numbers', () => {
    for (const n of [NaN, Infinity, -Infinity]) {
      expect(() => canonicalize({ ttl_seconds: n })).toThrow(CanonicalError);
    }
  });

  it('refuses non-integers', () => {
    expect(() => canonicalize({ ttl_seconds: 1.5 })).toThrow(CanonicalError);
  });

  it('refuses values with no JSON representation', () => {
    // JSON.stringify would silently DROP these from an object, producing a
    // shorter document that signs cleanly and means something else.
    for (const v of [undefined, () => {}, Symbol('s'), 1n]) {
      expect(() => canonicalize({ x: v })).toThrow(CanonicalError);
    }
  });

  it('refuses circular references', () => {
    const o = { a: 1 };
    o.self = o;
    expect(() => canonicalize(o)).toThrow(/circular/);
  });

  it('refuses nesting past the depth cap', () => {
    let root = {};
    let cur = root;
    for (let i = 0; i < 80; i++) { cur.n = {}; cur = cur.n; }
    expect(() => canonicalize(root)).toThrow(/nesting/);
  });

  it('serializes a JSON-parsed __proto__ as the own property it is', () => {
    // Refusing such a key is the validator's job; the serializer must round-trip
    // it faithfully or the bytes signed differ from the bytes checked.
    const parsed = JSON.parse('{"a":1,"__proto__":{"polluted":true}}');
    expect(canonicalize(parsed)).toBe('{"__proto__":{"polluted":true},"a":1}');
  });
});
