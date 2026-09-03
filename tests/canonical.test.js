/**
 * RFC 8785 — proven against the RFC, differentially against Python, and then
 * the properties that make it the right choice for §3 and §11.5.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import {
  canonicalize, CanonicalError, TEMPLATE_FIELDS, SPAWN_FIELDS, POLICY_FIELDS,
  REQUIRED_POLICY_FIELDS, GRANT_FIELDS, ENVELOPE_FIELDS,
} from '../src/canonical.js';
import * as canonical from '../src/canonical.js';

const vectors = JSON.parse(readFileSync(new URL('./fixtures/canonical_vectors.json', import.meta.url), 'utf8'));
const normative = vectors.filter((v) => v.source === 'RFC 8785');
const differential = vectors.filter((v) => v.source !== 'RFC 8785');

describe('RFC 8785 conformance', () => {
  it('the fixture actually carries normative vectors', () => {
    expect(normative.length).toBeGreaterThanOrEqual(15);
  });
  for (const { name, value, expected } of normative) {
    it(`[RFC 8785] ${name}`, () => expect(canonicalize(value)).toBe(expected));
  }
});

describe('differential against an independent implementation', () => {
  for (const { name, value, expected } of differential) {
    it(`[python] ${name}`, () => expect(canonicalize(value)).toBe(expected));
  }
  it('covers all four -03 documents and the audit entry', () => {
    const names = differential.map((d) => d.name).join(' ');
    for (const s of ['policy', 'Agent Template', 'Agent Spawn', 'grant', 'audit']) expect(names).toContain(s);
  });
});

describe('the two properties JCS exists to provide', () => {
  it('is stable under key reordering', () => {
    expect(canonicalize({ b: 1, a: 2 })).toBe(canonicalize({ a: 2, b: 1 }));
  });
  it('is not stable under array reordering — §10.3: order is significant to serialization', () => {
    expect(canonicalize({ scopes: ['a', 'b'] })).not.toBe(canonicalize({ scopes: ['b', 'a'] }));
  });
  it('round-trips through JSON.parse unchanged', () => {
    const o = { z: [1, { y: 'ü', x: null }], a: 'x' };
    expect(canonicalize(JSON.parse(canonicalize(o)))).toBe(canonicalize(o));
  });
  it('is its own fixed point — what §8.2 "valid JCS" means', () => {
    const c = canonicalize({ b: 'x', a: ['y'] });
    expect(canonicalize(JSON.parse(c))).toBe(c);
  });
});

describe('divergence from a language default serializer', () => {
  it('non-ASCII is raw UTF-8, not \\uXXXX', () => {
    expect(canonicalize({ k: 'café' })).toBe('{"k":"café"}');
  });
  it('astral keys sort by UTF-16 code unit, the opposite of a code-point sort', () => {
    expect(canonicalize({ '\u{1F510}': 1, '�': 2 })).toBe('{"\u{1F510}":1,"�":2}');
  });
  it('there is exactly one canonical form, not a compact and a spaced one', () => {
    expect(canonical.canonicalCompact).toBeUndefined();
    expect(canonical.canonicalSpaced).toBeUndefined();
  });
});

describe('the -03 field sets', () => {
  it('the Agent Template extension has exactly the nine members of Table 5', () => {
    expect([...TEMPLATE_FIELDS].sort()).toEqual(['allowed_scopes', 'can_spawn', 'max_children', 'org_id',
      'owner', 'permitted_operations', 'policy_ref', 'subject', 'ttl_seconds']);
  });
  it('the Agent Spawn extension has exactly the three members of Table 6', () => {
    expect([...SPAWN_FIELDS].sort()).toEqual(['parent_agent_id', 'spawn_nonce', 'spawned_at']);
  });
  it('the policy document is exactly §11.4 Table 7', () => {
    expect([...POLICY_FIELDS].sort()).toEqual(['issued_at', 'not_after', 'org_id', 'owner', 'scopes',
      'spawn_targets', 'subject', 'version']);
    expect([...REQUIRED_POLICY_FIELDS].sort()).toEqual(['issued_at', 'org_id', 'owner', 'scopes', 'subject', 'version']);
  });
  it('version and subject are inside the signed set (§11.6)', () => {
    expect(POLICY_FIELDS).toContain('version');
    expect(POLICY_FIELDS).toContain('subject');
  });
  it('the grant is exactly §13.2 Table 10, with no signature row', () => {
    expect([...GRANT_FIELDS].sort()).toEqual(['allowed_scopes', 'grantee', 'grantor', 'issued_at',
      'max_spawns', 'template', 'ttl_seconds']);
    expect(GRANT_FIELDS).not.toContain('signature');
  });
  it('the envelope is exactly §3.1 Table 1', () => {
    expect([...ENVELOPE_FIELDS].sort()).toEqual(['body', 'content_hash', 'owner_sig', 'pa_sig']);
  });
  it('no envelope member is a field of any body it attests to', () => {
    for (const f of ENVELOPE_FIELDS) {
      expect(POLICY_FIELDS).not.toContain(f);
      expect(GRANT_FIELDS).not.toContain(f);
      expect(TEMPLATE_FIELDS).not.toContain(f);
    }
  });
  it('the -02 filter-then-sign extractors are gone — bodies are signed whole', () => {
    expect(canonical.extractIdentityFields).toBeUndefined();
    expect(canonical.extractPolicyFields).toBeUndefined();
    expect(canonical.IDENTITY_FIELDS).toBeUndefined();
  });
});

describe('fails closed on values it cannot canonicalize', () => {
  it('refuses non-finite numbers', () => {
    expect(() => canonicalize({ a: NaN })).toThrow(CanonicalError);
    expect(() => canonicalize({ a: Infinity })).toThrow(CanonicalError);
  });
  it('refuses non-integers — §3 declares every number in this profile an integer', () => {
    expect(() => canonicalize({ a: 1.5 })).toThrow(CanonicalError);
  });
  it('refuses values with no JSON representation', () => {
    expect(() => canonicalize({ a: undefined })).toThrow(CanonicalError);
    expect(() => canonicalize({ a: () => 1 })).toThrow(CanonicalError);
    expect(() => canonicalize({ a: 1n })).toThrow(CanonicalError);
  });
  it('refuses circular references', () => {
    const o = {}; o.self = o;
    expect(() => canonicalize(o)).toThrow(CanonicalError);
  });
  it('refuses nesting past the depth cap', () => {
    let o = 1; for (let i = 0; i < 70; i++) o = { o };
    expect(() => canonicalize(o)).toThrow(CanonicalError);
  });
  it('serializes a JSON-parsed __proto__ as the own property it is', () => {
    expect(canonicalize(JSON.parse('{"__proto__":{"a":1}}'))).toBe('{"__proto__":{"a":1}}');
  });
});

describe('numbers at the edge', () => {
  it('serialises negative zero as 0 (RFC 8785 §3.2.2.3)', () => {
    expect(canonicalize({ a: -0 })).toBe('{"a":0}');
    expect(canonicalize([-0, 0])).toBe('[0,0]');
  });
});
