/**
 * Stages 3, 7 and 8 — revocation (§14), the two-check spawn rule (§10.1), the
 * MaxChildren consistency check (§10.2), scope containment (§10.3) and the
 * cross-organizational grant (§13.2).
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { assertNotRevoked, assertSpawnPermitted, assertScopeSubset, validateGrant } from '../src/bounds.js';
import { buildDefaultDocument } from '../src/defaults.js';
import { signEnvelope, privateKeyFromPem } from '../src/crypto-sign.js';
import { childOf, parentOf, templateOf, spawnAcrossOrganizations } from '../src/scenarios.js';
import { DenyError } from '../src/errors.js';

const refuses = async (code, promise) => {
  let caught = null;
  try { await promise; } catch (e) { caught = e; }
  expect(caught, 'expected a refusal').toBeInstanceOf(DenyError);
  expect(caught.code).toBe(code);
  return caught;
};
const throwsCode = (code, fn) => refuses(code, Promise.resolve().then(fn));

const A = '8f14e45f-ceea-467a-9c0f-7ad0f1b0d5aa', B = '019b3c8e-2f10-7a4b-9c6d-3e5f7a9b1c2d';

describe('stage 3 — revocation (§14) and DISABLED (§12.4)', () => {
  it('passes a clean agent', () => expect(() => assertNotRevoked({ agentId: A, crl: { revoked: [], disabled: [] } })).not.toThrow());
  it('refuses a revoked agent', () => throwsCode('ERR_AGENT_REVOKED', () => assertNotRevoked({ agentId: A, crl: { revoked: [A], disabled: [] } })));
  it('refuses a DISABLED template with its own code, and says it is not a revocation', async () => {
    const e = await throwsCode('ERR_AGENT_DISABLED', () => assertNotRevoked({ agentId: A, crl: { revoked: [], disabled: [A] } }));
    expect(e.detail).toMatch(/not a revocation/);
    expect(e.section).toBe('12.4');
  });
  it('fails closed on an unreadable or malformed CRL', async () => {
    await throwsCode('ERR_AGENT_REVOKED', () => assertNotRevoked({ agentId: A, crl: null }));
    await throwsCode('ERR_AGENT_REVOKED', () => assertNotRevoked({ agentId: A, crl: 'x' }));
    await throwsCode('ERR_AGENT_REVOKED', () => assertNotRevoked({ agentId: A, crl: { revoked: 'x' } }));
  });
  it('revoking the parent does not implicitly revoke the child', () =>
    expect(() => assertNotRevoked({ agentId: B, crl: { revoked: [A], disabled: [] } })).not.toThrow());
});

describe('stage 7 — Check 1 from the parent’s certificate (§10.1) and the MaxChildren consistency check (§10.2)', () => {
  const parent = { permitted_operations: ['spawn', 'read'], can_spawn: [B], max_children: 2, allowed_scopes: ['a:b'] };
  it('permits a whitelisted child under the cap, with spawn held', () =>
    expect(() => assertSpawnPermitted({ parentTemplate: parent, childId: B, siblings: 1 })).not.toThrow());
  it('refuses a parent without spawn — CanSpawn alone is "permitted to spawn specific children and not permitted to spawn"', () =>
    throwsCode('ERR_SPAWN_NOT_PERMITTED', () => assertSpawnPermitted({ parentTemplate: { ...parent, permitted_operations: ['read'] }, childId: B })));
  it('refuses a child not in CanSpawn', () =>
    throwsCode('ERR_CHILD_NOT_WHITELISTED', () => assertSpawnPermitted({ parentTemplate: { ...parent, can_spawn: [] }, childId: B })));
  it('refuses at the cap, and treats 0 as no children, not unlimited', async () => {
    await throwsCode('ERR_MAX_CHILDREN', () => assertSpawnPermitted({ parentTemplate: parent, childId: B, siblings: 2 }));
    await throwsCode('ERR_MAX_CHILDREN', () => assertSpawnPermitted({ parentTemplate: { ...parent, max_children: 0 }, childId: B, siblings: 0 }));
  });
  it('words the cap as a document-consistency check, not enforcement (§10.2)', async () => {
    const e = await throwsCode('ERR_MAX_CHILDREN', () => assertSpawnPermitted({ parentTemplate: { ...parent, max_children: 0 }, childId: B }));
    expect(e.detail).toMatch(/the document names/);
  });
  it('refuses a malformed child id before consulting the whitelist', () =>
    throwsCode('ERR_AGENT_ID_FORMAT', () => assertSpawnPermitted({ parentTemplate: parent, childId: 'not-a-uuid' })));
});

describe('stage 8 — scope containment (§10.3)', () => {
  it('permits an exact match and a proper subset', () => {
    expect(assertScopeSubset(['a:b'], ['a:b', 'c:d'])).toBe(true);
    expect(assertScopeSubset(['c:d', 'a:b'], ['a:b', 'c:d'])).toBe(true);   // order is not significant to comparison
  });
  it('refuses escalation and names the excess scope', async () => {
    const e = await throwsCode('ERR_SCOPE_ESCALATION', () => assertScopeSubset(['a:b', 'x:y'], ['a:b']));
    expect(e.detail).toMatch(/x:y/);
  });
  it('refuses empty scopes — the empty set satisfies containment vacuously', () =>
    throwsCode('ERR_EMPTY_SCOPES', () => assertScopeSubset([], ['a:b'])));
  it('has no wildcards, prefixes, hierarchy or case folding', async () => {
    await throwsCode('ERR_SCOPE_SYNTAX', () => assertScopeSubset(['admin:*'], ['admin:all']));
    await throwsCode('ERR_SCOPE_ESCALATION', () => assertScopeSubset(['read:events:extra'], ['read:events']));
    await throwsCode('ERR_SCOPE_ESCALATION', () => assertScopeSubset(['read:events'], ['write:events']));
    await throwsCode('ERR_SCOPE_SYNTAX', () => assertScopeSubset(['Read:Events'], ['read:events']));
  });
  it('fails closed on unparseable scope sets', async () => {
    await throwsCode('ERR_SCHEMA_VIOLATION', () => assertScopeSubset('a:b', ['a:b']));
    await throwsCode('ERR_SCHEMA_VIOLATION', () => assertScopeSubset(['a:b'], null));
  });
});

describe('cross-organizational grants (§13.2)', () => {
  let base, now;
  beforeAll(async () => {
    now = new Date();
    base = await buildDefaultDocument({ now });
    await spawnAcrossOrganizations(base, {}, { now });
  }, 30_000);
  const clone = () => JSON.parse(JSON.stringify(base));
  const run = (d, extra = {}) => validateGrant({
    grant: d.grant, childTemplate: templateOf(childOf(d)), parentTemplate: templateOf(parentOf(d)),
    ownerCertPem: d.authorities.owner.cert_pem, paCertPem: d.authorities.pa.cert_pem, now, ...extra,
  });
  const resign = async (d) => {
    d.grant = await signEnvelope(d.grant.body, await privateKeyFromPem(d.authorities.owner.key_pem),
      await privateKeyFromPem(d.authorities.pa.key_pem));
  };

  it('refuses a grant that is not an envelope, and an envelope with no body', async () => {
    for (const bad of ['grant', 7, [], null]) {
      const d = clone(); d.grant = bad;
      const e = await refuses('ERR_GRANT_INVALID', run(d));
      expect(e.detail).toMatch(/not an envelope/);
    }
    for (const bad of [null, 'body', []]) {
      const d = clone(); d.grant.body = bad;
      const e = await refuses('ERR_GRANT_INVALID', run(d));
      expect(e.detail).toMatch(/body is missing/);
    }
  });
  it('refuses a Policy Authority signature that does not verify — the Owner’s signature reused', async () => {
    const d = clone(); d.grant.pa_sig = d.grant.owner_sig;
    const e = await refuses('ERR_GRANT_INVALID', run(d));
    expect(e.detail).toMatch(/Policy Authority signature/);
  });
  it('accepts the grant the scenario issues', async () => {
    const body = await run(clone());
    expect(body.grantor).toBe('partner-org');
    expect(body.grantee).toBe('playground-org');
  });
  it('refuses an envelope member the draft does not define, and a content_hash on a grant', async () => {
    let d = clone(); d.grant.nonce = 'x'; await refuses('ERR_ENVELOPE_MEMBER', run(d));
    d = clone(); d.grant.content_hash = '00'; await refuses('ERR_ENVELOPE_MEMBER', run(d));
  });
  it('refuses a missing, extra, or mistyped field', async () => {
    let d = clone(); delete d.grant.body.issued_at; await refuses('ERR_GRANT_INVALID', run(d));
    d = clone(); d.grant.body.signature = 'x'; await refuses('ERR_GRANT_INVALID', run(d));
    d = clone(); d.grant.body.max_spawns = '3'; await refuses('ERR_GRANT_INVALID', run(d));
    d = clone(); d.grant.body.max_spawns = null; await refuses('ERR_OBJECT_NOT_FLAT', run(d));
    d = clone(); d.grant.body.ttl_seconds = 0; await resign(d); await refuses('ERR_GRANT_INVALID', run(d));
  });
  it('refuses a grant addressed to the wrong parties or template', async () => {
    let d = clone(); d.grant.body.grantor = 'someone-else'; await resign(d);
    expect((await refuses('ERR_GRANT_INVALID', run(d))).detail).toMatch(/grantor/);
    d = clone(); d.grant.body.grantee = 'someone-else'; await resign(d);
    expect((await refuses('ERR_GRANT_INVALID', run(d))).detail).toMatch(/grantee/);
    d = clone(); d.grant.body.template = A; await resign(d);
    expect((await refuses('ERR_GRANT_INVALID', run(d))).detail).toMatch(/template/);
  });
  it('refuses an expired grant, and one dated more than the window in the future; accepts one 59 s ahead', async () => {
    let d = clone(); d.grant.body.issued_at = new Date(now.getTime() - 7200_000).toISOString(); await resign(d);
    await refuses('ERR_GRANT_EXPIRED', run(d));
    d = clone(); d.grant.body.issued_at = new Date(now.getTime() + 61_000).toISOString(); await resign(d);
    await refuses('ERR_GRANT_EXPIRED', run(d));
    d = clone(); d.grant.body.issued_at = new Date(now.getTime() + 59_000).toISOString(); await resign(d);
    await run(d);
  });
  it('refuses a grant allowing scopes beyond the template it grants', async () => {
    const d = clone(); d.grant.body.allowed_scopes = ['read:events', 'admin:all']; await resign(d);
    await refuses('ERR_GRANT_EXCEEDS_TEMPLATE', run(d));
  });
  it('refuses a missing or invalid signature, each by name', async () => {
    let d = clone(); delete d.grant.pa_sig; await refuses('ERR_GRANT_INVALID', run(d));
    d = clone(); d.grant.body.max_spawns = 99; await refuses('ERR_GRANT_INVALID', run(d));   // body edited, not re-signed
  });
  it('refuses when the document names more agents under the grant than MaxSpawns', async () => {
    const d = clone(); d.grant.body.max_spawns = 0; await resign(d);
    await refuses('ERR_MAX_SPAWNS', run(d, { spawnsUnderGrant: 1 }));
  });
  it('refuses one key in both roles, and an Owner certificate that does not name the template owner', async () => {
    let d = clone(); d.authorities.pa = { ...d.authorities.owner };
    await refuses('ERR_SINGLE_SIGNATURE', run(d));
    d = clone(); await refuses('ERR_OWNER_CERT_MISMATCH', run(d, { ownerCertPem: d.authorities.pa.cert_pem }));
  });
});
