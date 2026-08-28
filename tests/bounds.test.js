/**
 * Stages 3, 7 and 8 — revocation (§12), authorization bounds (§7, §8.1),
 * scope containment (§8.3).
 *
 * Acceptance criterion 5: over-scoped delegation is refused AT ISSUANCE, and no
 * certificate is minted.
 */
import { describe, it, expect } from 'vitest';
import { DenyError } from '../src/errors.js';
import {
  assertNotRevoked, assertActive, AGENT_STATES,
  parseAuthorizationBounds, assertMaySpawn,
  assertScopeSubset, assertDelegationPermitted,
} from '../src/bounds.js';

const A = '8f14e45f-ceea-467a-9c0f-7ad0f1b0d5aa';
const B = 'c669186f-a84b-4d7a-81f3-05880df87114';
const C = 'd9cdba8d-5ada-485a-bd09-7a392d1f9625';

const NOW = new Date('2026-08-28T12:00:00Z');
const META = Object.freeze({
  state: 'ACTIVE',
  expires_at: '2026-08-29T12:00:00Z',
  // §7.1 lists TTL as REQUIRED. The fixture omitted it, and nothing checked —
  // caught by the red-team pass, which slipped `ttl_seconds: Infinity` through.
  ttl_seconds: 86400,
  allowed_scopes: ['read:events'],
  can_spawn: [A],
  max_children: 2,
  authorization_bounds: { allowed_scopes: ['read:events'], can_spawn: [A], max_children: 2 },
});

function denies(code, fn) {
  let thrown;
  try { fn(); } catch (e) { thrown = e; }
  expect(thrown, 'expected a DenyError, nothing was thrown').toBeDefined();
  expect(thrown, `threw ${thrown?.constructor?.name}: ${thrown?.message}`).toBeInstanceOf(DenyError);
  expect(thrown.code).toBe(code);
}

describe('stage 3 — revocation and TTL (§12)', () => {
  const ok = { revoked: [], disabled: [] };

  it('passes a clean agent', () => {
    expect(() => assertNotRevoked({ agentId: B, crl: ok, metadata: META, now: NOW })).not.toThrow();
  });

  it('refuses a revoked agent', () =>
    denies('ERR_AGENT_REVOKED', () => assertNotRevoked({
      agentId: B, crl: { revoked: [B], disabled: [] }, metadata: META, now: NOW })));

  it('refuses a disabled agent', () =>
    denies('ERR_AGENT_REVOKED', () => assertNotRevoked({
      agentId: B, crl: { revoked: [], disabled: [B] }, metadata: META, now: NOW })));

  it('refuses once the TTL has elapsed, without anyone listing it (§12.3)', () =>
    denies('ERR_TTL_EXPIRED', () => assertNotRevoked({
      agentId: B, crl: ok, metadata: META, now: new Date('2026-08-30T00:00:00Z') })));

  it('fails closed on an unreadable CRL', () => {
    for (const crl of [null, 'nope', ['a'], undefined]) {
      denies('ERR_AGENT_REVOKED', () => assertNotRevoked({ agentId: B, crl, metadata: META, now: NOW }));
    }
  });

  it('fails closed on a malformed CRL list', () =>
    denies('ERR_AGENT_REVOKED', () => assertNotRevoked({
      agentId: B, crl: { revoked: 'B' }, metadata: META, now: NOW })));

  it('fails closed on an unparseable expires_at', () =>
    denies('ERR_TTL_EXPIRED', () => assertNotRevoked({
      agentId: B, crl: ok, metadata: { ...META, expires_at: 'soon' }, now: NOW })));

  it('revoking the parent does not implicitly revoke the child', () => {
    // Revocation is per-agent; the chain walk is what propagates the refusal.
    expect(() => assertNotRevoked({
      agentId: B, crl: { revoked: [A], disabled: [] }, metadata: META, now: NOW })).not.toThrow();
  });
});

describe('§10.4 — agent state machine', () => {
  it('permits only ACTIVE', () => {
    expect(() => assertActive({ state: 'ACTIVE' })).not.toThrow();
    denies('ERR_AGENT_DISABLED', () => assertActive({ state: 'DISABLED' }));
    denies('ERR_AGENT_DISABLED', () => assertActive({ state: 'DELETED' }));
  });

  it('refuses an absent state rather than defaulting to ACTIVE', () => {
    // The reference implementation defaults a missing state to ACTIVE. That is
    // a fail-open default; this refuses.
    denies('ERR_AGENT_DISABLED', () => assertActive({}));
    denies('ERR_AGENT_DISABLED', () => assertActive(null));
  });

  it('refuses an unknown state', () =>
    denies('ERR_AGENT_DISABLED', () => assertActive({ state: 'SUPERUSER' })));

  it('knows the lifecycle', () => expect(AGENT_STATES).toEqual(['ACTIVE', 'DISABLED', 'DELETED']));
});

describe('stage 7 — parsing authorization bounds (§7)', () => {
  it('reads the three bound fields', () => {
    expect(parseAuthorizationBounds(META))
      .toEqual({ allowed_scopes: ['read:events'], can_spawn: [A], max_children: 2 });
  });

  it('accepts a document with only the top-level copy', () => {
    const { authorization_bounds, ...flat } = META;
    expect(parseAuthorizationBounds(flat).max_children).toBe(2);
  });

  it('accepts a document with only the nested copy', () => {
    expect(parseAuthorizationBounds({
      state: 'ACTIVE', ttl_seconds: 86400,
      authorization_bounds: META.authorization_bounds,
    }).max_children).toBe(2);
  });

  it('refuses unknown metadata fields rather than ignoring them', () => {
    // Red-team finding: `admin: true` and `rebac_override: true` validated
    // cleanly. They are inert — nothing reads them — which is exactly why
    // accepting them silently is wrong: a key that survives validation reads
    // as meaningful.
    denies('ERR_SCHEMA_VIOLATION', () =>
      parseAuthorizationBounds({ ...META, admin: true, rebac_override: true }));
  });

  it('validates ttl_seconds, a §7.1 REQUIRED field', () => {
    denies('ERR_FIELD_RANGE', () => parseAuthorizationBounds({ ...META, ttl_seconds: null }));
    denies('ERR_FIELD_RANGE', () => parseAuthorizationBounds({ ...META, ttl_seconds: 0 }));
    denies('ERR_FIELD_RANGE', () => parseAuthorizationBounds({ ...META, ttl_seconds: -1 }));
    denies('ERR_FIELD_RANGE', () => parseAuthorizationBounds({ ...META, ttl_seconds: '86400' }));
  });

  it('REFUSES when the duplicate copies disagree', () => {
    // setup_keys.py emits both and service.py reads the nested one. A document
    // whose copies differ has no single answer; picking one silently is how a
    // bound gets bypassed.
    denies('ERR_BOUNDS_UNPARSEABLE', () => parseAuthorizationBounds({
      ...META, authorization_bounds: { ...META.authorization_bounds, max_children: 99 },
    }));
    denies('ERR_BOUNDS_UNPARSEABLE', () => parseAuthorizationBounds({
      ...META, authorization_bounds: { ...META.authorization_bounds, can_spawn: [B] },
    }));
  });

  it('fails closed when a bound is absent', () => {
    for (const f of ['allowed_scopes', 'can_spawn', 'max_children']) {
      const meta = { ...META }; delete meta[f];
      const { [f]: _drop, ...nested } = META.authorization_bounds;
      denies('ERR_BOUNDS_UNPARSEABLE', () => parseAuthorizationBounds({ ...meta, authorization_bounds: nested }));
    }
  });

  it('validates the shape of each bound', () => {
    denies('ERR_BOUNDS_UNPARSEABLE', () => parseAuthorizationBounds({ ...META, can_spawn: 'x', authorization_bounds: undefined }));
    denies('ERR_AGENT_ID_FORMAT', () => parseAuthorizationBounds({ ...META, can_spawn: ['agent-a'], authorization_bounds: undefined }));
    denies('ERR_BOUNDS_UNPARSEABLE', () => parseAuthorizationBounds({ ...META, can_spawn: [A, A], authorization_bounds: undefined }));
    denies('ERR_FIELD_RANGE', () => parseAuthorizationBounds({ ...META, max_children: -1, authorization_bounds: undefined }));
    denies('ERR_FIELD_RANGE', () => parseAuthorizationBounds({ ...META, max_children: 1.5, authorization_bounds: undefined }));
    denies('ERR_FIELD_CHARSET', () => parseAuthorizationBounds({ ...META, allowed_scopes: ['ADMIN'], authorization_bounds: undefined }));
  });

  it('refuses a non-object', () => {
    for (const bad of [null, 'x', 42, ['a']]) denies('ERR_BOUNDS_UNPARSEABLE', () => parseAuthorizationBounds(bad));
  });
});

describe('stage 7 — the spawn whitelist and max_children (§8.1, §7)', () => {
  const bounds = { allowed_scopes: ['read:events'], can_spawn: [A], max_children: 2 };

  it('permits a whitelisted child under the cap', () => {
    expect(() => assertMaySpawn({ parentBounds: bounds, childId: A, currentChildren: 0 })).not.toThrow();
  });

  it('refuses a child that is not whitelisted', () =>
    denies('ERR_CHILD_NOT_WHITELISTED', () => assertMaySpawn({
      parentBounds: bounds, childId: C, currentChildren: 0 })));

  it('refuses at the cap', () =>
    denies('ERR_MAX_CHILDREN', () => assertMaySpawn({
      parentBounds: bounds, childId: A, currentChildren: 2 })));

  it('treats max_children 0 as no children, not unlimited', () => {
    // cert_validator.validate_max_children only enforces when max_c > 0, which
    // reads a zero cap as unlimited. For a structural bound that is backwards.
    denies('ERR_MAX_CHILDREN', () => assertMaySpawn({
      parentBounds: { ...bounds, max_children: 0 }, childId: A, currentChildren: 0 }));
  });

  it('refuses a malformed child id before consulting the whitelist', () =>
    denies('ERR_AGENT_ID_FORMAT', () => assertMaySpawn({
      parentBounds: bounds, childId: 'agent-a', currentChildren: 0 })));
});

describe('stage 8 — scope containment (§8.3)', () => {
  it('permits an exact match and a proper subset', () => {
    expect(assertScopeSubset(['read:events'], ['read:events'])).toBe(true);
    expect(assertScopeSubset(['read:events'], ['read:events', 'write:events'])).toBe(true);
  });

  it('refuses escalation and names the excess scope', () => {
    let thrown;
    try { assertScopeSubset(['write:events'], ['read:events']); } catch (e) { thrown = e; }
    expect(thrown.code).toBe('ERR_SCOPE_ESCALATION');
    expect(thrown.detail).toContain('write:events');
    expect(thrown.detail).toContain('read:events');
  });

  it('refuses empty scopes — an agent must declare intent (§16.1)', () =>
    denies('ERR_EMPTY_SCOPES', () => assertScopeSubset([], ['read:events'])));

  it('has no wildcards, prefixes or hierarchy', () => {
    // Each of these is a plausible-looking escalation path if a validator gets
    // clever about scope semantics. A scope is an opaque token.
    denies('ERR_FIELD_CHARSET', () => assertScopeSubset(['*'], ['read:events']));
    denies('ERR_SCOPE_ESCALATION', () => assertScopeSubset(['read'], ['read:events']));
    denies('ERR_SCOPE_ESCALATION', () => assertScopeSubset(['read:events:extra'], ['read:events']));
    denies('ERR_SCOPE_ESCALATION', () => assertScopeSubset(['admin:all'], ['read:events']));
    // write does not imply read, and read does not imply write
    denies('ERR_SCOPE_ESCALATION', () => assertScopeSubset(['read:events'], ['write:events']));
  });

  it('refuses a partial subset — one bad scope taints the request (A02)', () =>
    denies('ERR_SCOPE_ESCALATION', () =>
      assertScopeSubset(['read:events', 'admin:all'], ['read:events'])));

  it('fails closed on unparseable scope sets', () => {
    denies('ERR_SCHEMA_VIOLATION', () => assertScopeSubset(['read:events'], 'read:events'));
    denies('ERR_SCHEMA_VIOLATION', () => assertScopeSubset(['read:events'], null));
  });
});

describe('AC-5 — over-scoped delegation is refused at issuance', () => {
  it('permits a narrowing delegation', () => {
    expect(assertDelegationPermitted({
      parentScopes: ['read:events', 'write:events'], childScopes: ['read:events'],
    })).toBe(true);
  });

  it('refuses a widening delegation before any certificate exists', () => {
    // The headline act: the escalation is prevented, not caught afterwards.
    let thrown;
    try {
      assertDelegationPermitted({ parentScopes: ['read:events'], childScopes: ['write:events'] });
    } catch (e) { thrown = e; }
    expect(thrown.code).toBe('ERR_SCOPE_ESCALATION');
    expect(thrown.section).toBe('8.3');
    expect(thrown.banner).toBe('ERR_SCOPE_ESCALATION · §8.3');
  });

  it('refuses a child claiming scopes the parent never held', () =>
    denies('ERR_SCOPE_ESCALATION', () => assertDelegationPermitted({
      parentScopes: ['read:events'], childScopes: ['read:events', 'admin:all'] })));
});
