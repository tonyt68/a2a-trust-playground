/**
 * §11 — dual-signed policy updates in the §3.1 envelope, stages 4-6.
 *
 * The seed document is the fixture: a chain whose child has a dual-signed
 * policy. Each test bends one thing and asserts the SPECIFIC refusal.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { buildDefaultDocument } from '../src/defaults.js';
import {
  validatePolicyUpdate, assertFieldGuard, assertEnvelope, IMMUTABLE_CERT_FIELDS, isPolicyUpdate,
  assertRequiredFields, assertWithinTemplateBounds, assertOwnership, assertPolicyIntegrity,
} from '../src/policy.js';
import { signEnvelope, privateKeyFromPem, contentHash, signBody } from '../src/crypto-sign.js';
import { parseCertificate, parseTemplateExtension } from '../src/x509.js';
import { childOf, parentOf, templateOf, resignPolicy, issueRaw } from '../src/scenarios.js';
import { DenyError } from '../src/errors.js';

let base, now;
beforeAll(async () => { now = new Date(); base = await buildDefaultDocument({ now }); }, 30_000);
const clone = () => JSON.parse(JSON.stringify(base));

function templatesOf(d) {
  const m = new Map();
  for (const n of d.chain.filter((x) => x.role === 'agent')) {
    const c = parseCertificate(n.cert_pem);
    m.set(n.metadata.agent_id, { template: parseTemplateExtension(c), notAfter: c.notAfter.value });
  }
  return m;
}
const run = (d, extra = {}) => validatePolicyUpdate({
  document: d, templates: templatesOf(d), ownerCertPem: d.authorities.owner.cert_pem,
  paCertPem: d.authorities.pa.cert_pem, now, ...extra,
});
const refuses = async (code, promise) => {
  let caught = null;
  try { await promise; } catch (e) { caught = e; }
  expect(caught, 'expected a refusal').toBeInstanceOf(DenyError);
  expect(caught.code).toBe(code);
  return caught;
};

describe('the seed', () => {
  it('is a policy update and passes', async () => {
    const d = clone();
    expect(isPolicyUpdate(d)).toBe(true);
    const r = await run(d);
    expect(r.applicable).toBe(true);
    expect(r.subject).toBe(childOf(d).metadata.agent_id);
  });
  it('a chain without a policy is not applicable — a PASS, not a refusal', async () => {
    const d = clone(); delete d.policy;
    expect((await run(d)).applicable).toBe(false);
  });
  it('reports the stages in the reference order: 5, 6, then 4', async () => {
    const seen = [];
    await run(clone(), { onStage: (n) => seen.push(n) });
    expect(seen).toEqual([5, 6, 4]);
  });
});

describe('§3.1 — the envelope', () => {
  it('refuses a member the draft does not define', async () => {
    const d = clone(); d.policy.signature = 'x';
    await refuses('ERR_ENVELOPE_MEMBER', run(d));
  });
  it('refuses a policy envelope with no content_hash — §11.7 stores one', async () => {
    const d = clone(); delete d.policy.content_hash;
    await refuses('ERR_CONTENT_HASH', run(d));
  });
  it('refuses an envelope that is not an object', () => {
    expect(() => assertEnvelope('x', { requireHash: true })).toThrow(DenyError);
    expect(() => assertEnvelope({ owner_sig: 'a', pa_sig: 'b', content_hash: 'c' }, { requireHash: true })).toThrow(DenyError);
  });
});

describe('§11.3 — one signature is never enough', () => {
  it('refuses when both signatures are absent', async () => {
    const d = clone(); d.policy.owner_sig = null; d.policy.pa_sig = null;
    await refuses('ERR_SINGLE_SIGNATURE', run(d));
  });
  it('refuses with owner_sig only', async () => {
    const d = clone(); d.policy.pa_sig = null;
    await refuses('ERR_PA_SIG_MISSING', run(d));
  });
  it('refuses with pa_sig only', async () => {
    const d = clone(); d.policy.owner_sig = '';
    await refuses('ERR_OWNER_SIG_MISSING', run(d));
  });
  it('refuses a tampered Owner signature and a tampered PA signature, each by name', async () => {
    let d = clone(); const o = Buffer.from(d.policy.owner_sig, 'base64'); o[3] ^= 1; d.policy.owner_sig = o.toString('base64');
    await refuses('ERR_OWNER_SIG_INVALID', run(d));
    d = clone(); const p = Buffer.from(d.policy.pa_sig, 'base64'); p[3] ^= 1; d.policy.pa_sig = p.toString('base64');
    await refuses('ERR_PA_SIG_INVALID', run(d));
  });
  it('refuses a signature that is not base64', async () => {
    const d = clone(); d.policy.pa_sig = 'not base64!!';
    await refuses('ERR_PA_SIG_INVALID', run(d));
  });
  it('refuses a DER-encoded signature as an encoding error (§3.1)', async () => {
    const d = clone(); d.policy.owner_sig = Buffer.alloc(70, 1).toString('base64');
    await refuses('ERR_SIGNATURE_ALGORITHM', run(d));
  });
  it('refuses when the body is altered after signing', async () => {
    const d = clone(); d.policy.body.scopes = [];
    d.policy.content_hash = await contentHash(d.policy.body);
    await refuses('ERR_OWNER_SIG_INVALID', run(d));
  });
  it('the -02 replay is closed: an Owner signature from another policy on the same agent does not verify (§11.8)', async () => {
    // Under -02 owner_sig covered the certificate's identity fields, so one
    // valid owner_sig served every later policy on that agent. Under -03 it
    // covers the body, so a stale one is specific to the body it signed.
    const d = clone();
    const ownerKey = await privateKeyFromPem(d.authorities.owner.key_pem);
    const stale = await signBody({ ...d.policy.body, version: 1, scopes: [] }, ownerKey);
    d.policy.owner_sig = stale;
    await refuses('ERR_OWNER_SIG_INVALID', run(d));
  });
  it('refuses when one key holds both roles, comparing KEYS not signature octets (§3.1)', async () => {
    const d = clone();
    d.authorities.pa = { ...d.authorities.owner };
    const key = await privateKeyFromPem(d.authorities.owner.key_pem);
    d.policy = await signEnvelope(d.policy.body, key, key, { withHash: true });
    expect(d.policy.owner_sig).not.toBe(d.policy.pa_sig);   // ECDSA is randomized: octets differ
    await refuses('ERR_SINGLE_SIGNATURE', run(d));
  });
});

describe('§11.4 — the field guard makes the split real', () => {
  it('knows which template members are immutable', () => {
    expect([...IMMUTABLE_CERT_FIELDS].sort()).toEqual(['allowed_scopes', 'can_spawn', 'max_children',
      'permitted_operations', 'policy_ref', 'ttl_seconds']);
  });
  for (const field of ['can_spawn', 'max_children', 'allowed_scopes', 'permitted_operations', 'ttl_seconds', 'policy_ref']) {
    it(`refuses a policy touching ${field}`, async () => {
      const d = clone(); d.policy.body[field] = field === 'max_children' || field === 'ttl_seconds' ? 1 : [];
      await refuses('ERR_IMMUTABLE_FIELD', run(d));
    });
  }
  it('refuses an envelope member inside the body — it would be inside its own preimage (§11.6)', async () => {
    const d = clone(); d.policy.body.content_hash = 'x';
    const e = await refuses('ERR_UNKNOWN_POLICY_FIELD', run(d));
    expect(e.detail).toMatch(/preimage/);
  });
  it('refuses unknown fields rather than ignoring them', async () => {
    const d = clone(); d.policy.body.description = 'x';
    await refuses('ERR_UNKNOWN_POLICY_FIELD', run(d));
  });
  it('names every offending field, sorted', () => {
    let e; try { assertFieldGuard({ max_children: 1, can_spawn: [] }); } catch (x) { e = x; }
    expect(e.detail).toMatch(/can_spawn, max_children/);
  });
  it('runs the field guard BEFORE signature verification', async () => {
    const d = clone(); d.policy.body.can_spawn = []; d.policy.pa_sig = 'junk';
    await refuses('ERR_IMMUTABLE_FIELD', run(d));
  });
  it('refuses a nested value — bodies are flat (§3)', async () => {
    const d = clone(); d.policy.body.scopes = [{ read: true }];
    await refuses('ERR_OBJECT_NOT_FLAT', run(d));
  });
});

describe('§11.4 — required fields and their types', () => {
  for (const field of ['subject', 'owner', 'org_id', 'scopes', 'version', 'issued_at']) {
    it(`refuses a policy missing ${field}`, async () => {
      const d = clone(); delete d.policy.body[field];
      await refuses('ERR_REQUIRED_FIELD', run(d));
    });
  }
  it('refuses an issued_at with an offset (§3)', async () => {
    const d = clone(); d.policy.body.issued_at = '2026-09-03T00:00:00+00:00';
    await refuses('ERR_TIMESTAMP_FORMAT', run(d));
  });
  it('refuses a scope outside the §10.3 syntax', async () => {
    const d = clone(); d.policy.body.scopes = ['Read:Events'];
    await refuses('ERR_SCOPE_SYNTAX', run(d));
  });
});

describe('§11.2 — only the template owner, in the template organization, for the template subject', () => {
  it('refuses a different owner, even correctly signed', async () => {
    const d = clone(); d.policy.body.owner = 'attacker@example.com'; await resignPolicy(d);
    await refuses('ERR_OWNER_MISMATCH', run(d));
  });
  it('refuses a different organization', async () => {
    const d = clone(); d.policy.body.org_id = 'other-org'; await resignPolicy(d);
    await refuses('ERR_ORG_MISMATCH', run(d));
  });
  it('refuses a subject that is not in the chain', async () => {
    const d = clone(); d.policy.body.subject = '019b3c8e-2f10-7a4b-9c6d-3e5f7a9b1c2d'; await resignPolicy(d);
    await refuses('ERR_SUBJECT_UNKNOWN', run(d));
  });
  it('accepts a policy for the PARENT — bounds are then the parent’s', async () => {
    const d = clone(); d.policy.body.subject = parentOf(d).metadata.agent_id; d.policy.body.scopes = ['write:events'];
    await resignPolicy(d);
    expect((await run(d)).subject).toBe(parentOf(d).metadata.agent_id);
  });
  it('refuses when the Owner certificate does not name the template owner (§9.2)', async () => {
    const d = clone();
    await issueRaw(d, childOf(d), { template: { owner: 'another-owner' } });
    d.policy.body.owner = 'another-owner'; await resignPolicy(d);
    await refuses('ERR_OWNER_CERT_MISMATCH', run(d));
  });
});

describe('§11.4 / §11.6 — version, hash, lifetime', () => {
  it('accepts a correct content hash and refuses a wrong one', async () => {
    const d = clone(); d.policy.content_hash = '0'.repeat(64);
    await refuses('ERR_CONTENT_HASH', run(d));
  });
  it('refuses replaying an older version over the version in force', async () => {
    const d = clone(); d.current_policy_version = 2;
    await refuses('ERR_POLICY_VERSION', run(d));
  });
  it('rewriting the version breaks BOTH signatures (§11.6)', async () => {
    const d = clone(); d.policy.body.version = 99; d.policy.content_hash = await contentHash(d.policy.body);
    await refuses('ERR_OWNER_SIG_INVALID', run(d));
  });
  it('refuses a non-positive, non-integer or string version — before any signature is checked', async () => {
    for (const v of [0, -1, '2']) {
      const d = clone(); d.policy.body.version = v;
      await refuses('ERR_POLICY_VERSION', run(d));
    }
    const d = clone(); d.policy.body.version = 1.5;
    await refuses('ERR_OBJECT_NOT_FLAT', run(d));
  });
  it('refuses a NotAfter later than the certificate’s notAfter', async () => {
    const d = clone(); d.policy.body.not_after = '2099-01-01T00:00:00Z'; await resignPolicy(d);
    await refuses('ERR_POLICY_EXPIRED', run(d));
  });
  it('refuses a policy presented after its NotAfter', async () => {
    const d = clone(); d.policy.body.not_after = new Date(now.getTime() + 60_000).toISOString(); await resignPolicy(d);
    await refuses('ERR_POLICY_EXPIRED', run(d, { now: new Date(now.getTime() + 120_000) }));
  });
  it('refuses a policy presented after the certificate it governs has expired', async () => {
    await refuses('ERR_POLICY_EXPIRED', run(clone(), { now: new Date(now.getTime() + 2 * 86400_000) }));
  });
});

describe('§8.3 — dynamic policy is bounded by the static template, after the signatures', () => {
  it('permits narrowing, exactly the ceiling, and an empty grant', async () => {
    for (const scopes of [['read:events'], [], ]) {
      const d = clone(); d.policy.body.scopes = scopes; await resignPolicy(d);
      expect((await run(d)).applicable).toBe(true);
    }
  });
  it('REFUSES a grant beyond AllowedScopes, despite two valid signatures and a matching hash', async () => {
    const d = clone(); d.policy.body.scopes = ['read:events', 'admin:all']; await resignPolicy(d);
    await refuses('ERR_POLICY_EXCEEDS_TEMPLATE', run(d));
  });
  it('refuses spawn targets beyond CanSpawn', async () => {
    const d = clone(); d.policy.body.spawn_targets = ['019b3c8e-2f10-7a4b-9c6d-3e5f7a9b1c2d']; await resignPolicy(d);
    await refuses('ERR_SPAWN_EXCEEDS_TEMPLATE', run(d));
  });
  it('checks the ceiling AFTER the signatures: a widened AND badly signed policy reports the signature', async () => {
    const d = clone(); d.policy.body.scopes = ['admin:all']; d.policy.content_hash = await contentHash(d.policy.body);
    await refuses('ERR_OWNER_SIG_INVALID', run(d));
  });
  it('the ceiling is read from the certificate, not from anything in the document', async () => {
    const d = clone();
    expect(templateOf(childOf(d)).allowed_scopes).toEqual(['read:events']);
    expect(childOf(d).metadata.allowed_scopes).toBeUndefined();
  });
});

// ── The stage functions on their own — shapes the seed document cannot take ──
describe('the stage functions refuse malformed input on their own', () => {
  const sync = (code, fn) => refuses(code, Promise.resolve().then(fn));
  it('stage 5 — the field guard refuses a body that is not an object', async () => {
    for (const bad of [null, [], 'policy', 7]) {
      const e = await sync('ERR_SCHEMA_VIOLATION', () => assertFieldGuard(bad));
      expect(e.detail).toMatch(/must be an object/);
    }
  });
  it('stage 6 — spawn_targets must be an array; version a positive integer', async () => {
    const body = clone().policy.body;
    const e = await sync('ERR_SCHEMA_VIOLATION', () => assertRequiredFields({ ...body, spawn_targets: 'all' }));
    expect(e.detail).toMatch(/spawn_targets/);
    for (const v of ['2', 0, -1, 1.5, null]) {
      await sync('ERR_POLICY_VERSION', () => assertRequiredFields({ ...body, version: v }));
    }
  });
  it('stage 4 — the integrity check refuses a non-positive-integer version on its own', async () => {
    const body = clone().policy.body;
    const c = parseCertificate(childOf(base).cert_pem);
    for (const v of [0, '1', 2.5]) {
      await refuses('ERR_POLICY_VERSION', assertPolicyIntegrity({ ...body, version: v }, { certNotAfter: c.notAfter.value, now }));
    }
  });
  it('§8.3 — a dynamic policy cannot be bounded without a template', async () => {
    const e = await sync('ERR_POLICY_EXCEEDS_TEMPLATE', () => assertWithinTemplateBounds(clone().policy.body, null));
    expect(e.detail).toMatch(/template certificate is required/);
  });
  it('§11.2 / §11.4 — the policy must name the agent whose template bounds it', async () => {
    const d = clone();
    const t = templateOf(childOf(d));
    const other = parentOf(d).metadata.agent_id;
    expect(other).not.toBe(t.subject);
    const e = await sync('ERR_SUBJECT_UNKNOWN', () =>
      assertOwnership({ ...d.policy.body, subject: other, owner: t.owner, org_id: t.org_id }, t));
    expect(e.detail).toMatch(/subject/);
  });
});
