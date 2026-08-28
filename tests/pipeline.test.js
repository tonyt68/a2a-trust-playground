/**
 * The nine-stage pipeline, end to end.
 *
 * Acceptance criteria exercised here:
 *   AC-4   every sabotage yields its documented ERR_* code and draft section
 *   AC-5   over-scoped delegation is refused at issuance
 *   AC-8   a tampered audit entry flips the chain status and names the entry
 *   AC-13  the default chain passes every stage with no minting step
 *
 * The document under test is assembled from the OpenSSL fixtures, so a passing
 * run means real certificates verified against a real CA with real signatures —
 * not a mock that agrees with the code by construction.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { runPipeline, NOT_APPLICABLE, DRAFT } from '../src/pipeline.js';
import { extractIdentityFields, extractPolicyFields, canonicalize } from '../src/canonical.js';
import { privateKeyFromPem, signCanonical } from '../src/crypto-sign.js';
import { ERRORS } from '../src/errors.js';

const dir = fileURLToPath(new URL('./fixtures/certs/', import.meta.url));
const read = (f) => readFileSync(dir + f, 'utf8');

const AGENT_A = '8f14e45f-ceea-467a-9c0f-7ad0f1b0d5aa';
const AGENT_B = 'c669186f-a84b-4d7a-81f3-05880df87114';
const NOW = new Date();

let ownerKey, paKey;
beforeAll(async () => {
  if (!existsSync(dir + 'ca-root.crt')) throw new Error('run `pnpm fixtures`');
  ownerKey = await privateKeyFromPem(read('owner.key'));
  paKey = await privateKeyFromPem(read('pa.key'));
});

/** Metadata in the shape setup_keys.py emits, with UUID4 identities (§6). */
function metadata(id, { scopes, canSpawn = [], maxChildren = 0, parent = null, state = 'ACTIVE' }) {
  const expires = new Date(NOW.getTime() + 12 * 3600 * 1000).toISOString();
  return {
    subject: id, agent_id: id, agent_uuid: id,
    issuer: 'A2A-Trust-Playground-CA',
    owner: 'owner@example.com', org_id: 'tonyai-org',
    permitted_operations: ['read'], allowed_scopes: scopes,
    can_spawn: canSpawn, max_children: maxChildren, policy_ref: 'policy-store/current',
    ttl_seconds: 86400, template_version: '1.0', state,
    created_at: NOW.toISOString(), expires_at: expires,
    ...(parent ? { parent_agent_id: parent } : {}),
    authorization_bounds: { allowed_scopes: scopes, can_spawn: canSpawn, max_children: maxChildren },
  };
}

/** A known-good chain: CA -> Agent A (read+write, may spawn B) -> Agent B (read). */
function defaultDocument() {
  return {
    chain: [
      { role: 'ca', cert_pem: read('ca-root.crt'),
        metadata: { subject: 'A2A-Trust-Playground-CA' } },
      { role: 'agent', cert_pem: read('agent-a.crt'),
        metadata: metadata(AGENT_A, {
          scopes: ['read:events', 'write:events'], canSpawn: [AGENT_B], maxChildren: 2 }) },
      { role: 'agent', cert_pem: read('agent-b.crt'),
        metadata: metadata(AGENT_B, { scopes: ['read:events'], parent: AGENT_A }),
        requested_scopes: ['read:events'] },
    ],
    authorities: {
      owner: { cert_pem: read('owner.crt'), common_name: 'owner-authority' },
      pa: { cert_pem: read('pa.crt'), common_name: 'policy-authority' },
    },
    crl: { revoked: [], disabled: [] },
    audit: { chain: [] },
  };
}

const agent = (doc, id) => doc.chain.find((n) => n.metadata.agent_id === id);
const run = (doc) => runPipeline({ document: doc, now: NOW });

/** Assert the run denied with a specific code, and that the stage log says so. */
async function deniesWith(doc, code) {
  const r = await run(doc);
  expect(r.verdict, `expected DENY, got ${r.verdict} (${r.error_code})`).toBe('DENY');
  expect(r.error_code).toBe(code);
  expect(r.draft_section).toBe(ERRORS[code].section);
  const failed = r.stages.filter((s) => s.result === 'DENY');
  expect(failed).toHaveLength(1);
  expect(r.banner).toContain(code);
  return r;
}

describe('AC-13 — the default chain passes every stage', () => {
  it('returns PASS', async () => {
    const r = await run(defaultDocument());
    expect(r.verdict, `denied with ${r.error_code}: ${JSON.stringify(r.stages.at(-1))}`).toBe('PASS');
    expect(r.error_code).toBeNull();
    expect(r.draft_section).toBeNull();
  });

  it('records all nine stages, in order, all PASS', async () => {
    const r = await run(defaultDocument());
    expect(r.stages.map((s) => s.n)).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9]);
    expect(r.stages.every((s) => s.result === 'PASS')).toBe(true);
    expect(r.stages.every((s) => typeof s.detail === 'string' && s.detail.length > 0)).toBe(true);
  });

  it('appends exactly one audit entry for the run', async () => {
    const r = await run(defaultDocument());
    expect(r.audit.entries).toBe(1);
    expect(r.audit.chain_valid).toBe(true);
    expect(r.audit.head_hash).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe('the output contract', () => {
  it('has stable key order and no undefined values', async () => {
    const r = await run(defaultDocument());
    expect(Object.keys(r)).toEqual([
      'playground_version', 'draft', 'generated_at', 'demo_only', 'verdict', 'walk',
      'error_code', 'draft_section', 'banner', 'stages', 'not_applicable',
      'chain', 'authorities', 'crl', 'audit',
    ]);
    expect(JSON.stringify(r)).not.toContain('undefined');
  });

  it('always carries a verdict, a draft revision and demo_only', async () => {
    for (const doc of [defaultDocument(), {}, { chain: [] }]) {
      const r = await runPipeline({ document: doc, now: NOW });
      expect(['PASS', 'DENY']).toContain(r.verdict);
      expect(r.draft).toBe(DRAFT);
      expect(r.demo_only).toBe(true);
      expect(r.generated_at).toMatch(/^\d{4}-\d{2}-\d{2}T.*Z$/);
    }
  });

  it('names the stages it does NOT implement, rather than omitting them (AC-3)', async () => {
    const r = await run(defaultDocument());
    expect(r.not_applicable.map((s) => s.section).sort()).toEqual(['16.2', '9']);
    expect(r.not_applicable.every((s) => s.result === 'NOT-APPLICABLE' && s.reason)).toBe(true);
    expect(NOT_APPLICABLE).toHaveLength(2);
  });

  it('never throws, whatever it is handed', async () => {
    for (const doc of [null, undefined, {}, [], 'x', 42, { chain: 'nope' }, { chain: [{}] }]) {
      const r = await runPipeline({ document: doc, now: NOW });
      expect(r.verdict).toBe('DENY');
      expect(r.error_code).toBeTruthy();
    }
  });
});

describe('AC-4 — every sabotage yields its documented code and section', () => {
  it('revoke the parent -> ERR_AGENT_REVOKED §12', async () => {
    const doc = defaultDocument();
    doc.crl.revoked.push(AGENT_A);
    await deniesWith(doc, 'ERR_AGENT_REVOKED');
  });

  it('disable the agent -> ERR_AGENT_DISABLED §10.4', async () => {
    const doc = defaultDocument();
    agent(doc, AGENT_B).metadata.state = 'DISABLED';
    await deniesWith(doc, 'ERR_AGENT_DISABLED');
  });

  it('expire the cert -> ERR_TTL_EXPIRED §12.3', async () => {
    const doc = defaultDocument();
    agent(doc, AGENT_B).metadata.expires_at = '2020-01-01T00:00:00Z';
    await deniesWith(doc, 'ERR_TTL_EXPIRED');
  });

  it('escalate the scope -> ERR_SCOPE_ESCALATION §8.3', async () => {
    const doc = defaultDocument();
    const b = agent(doc, AGENT_B);
    b.metadata.allowed_scopes = ['admin:all'];
    b.metadata.authorization_bounds.allowed_scopes = ['admin:all'];
    b.requested_scopes = ['admin:all'];
    const r = await deniesWith(doc, 'ERR_SCOPE_ESCALATION');
    expect(r.banner).toBe('ERR_SCOPE_ESCALATION · §8.3');
  });

  it('exceed max_children -> ERR_MAX_CHILDREN §7', async () => {
    const doc = defaultDocument();
    const a = agent(doc, AGENT_A);
    a.metadata.max_children = 0;
    a.metadata.authorization_bounds.max_children = 0;
    await deniesWith(doc, 'ERR_MAX_CHILDREN');
  });

  it('spawn a non-whitelisted child -> ERR_CHILD_NOT_WHITELISTED §8.1', async () => {
    const doc = defaultDocument();
    const a = agent(doc, AGENT_A);
    a.metadata.can_spawn = [];
    a.metadata.authorization_bounds.can_spawn = [];
    await deniesWith(doc, 'ERR_CHILD_NOT_WHITELISTED');
  });

  it('forge the issuer -> ERR_FORGED_ISSUER §6', async () => {
    const doc = defaultDocument();
    agent(doc, AGENT_A).cert_pem = read('forged.crt');
    await deniesWith(doc, 'ERR_FORGED_ISSUER');
  });

  it('alter an audit entry -> ERR_AUDIT_CHAIN_BROKEN §16.6, naming the entry (AC-8)', async () => {
    const seeded = await run(defaultDocument());
    const doc = defaultDocument();
    doc.audit = { chain: seeded.audit.chain };
    doc.audit.chain[0].event.decision = 'DENIED';   // was ALLOWED
    const r = await deniesWith(doc, 'ERR_AUDIT_CHAIN_BROKEN');
    expect(r.stages.at(-1).detail).toContain('entry 0');
  });
});

describe('AC-4 — policy update sabotage (§9.3)', () => {
  async function policyDocument(overrides = {}) {
    const doc = defaultDocument();
    const existing = agent(doc, AGENT_B).metadata;
    // §9.4's complete field set. `scopes` is the policy's grant; the template
    // keeps `allowed_scopes` as the ceiling that bounds it.
    const policyDoc = {
      subject: existing.agent_id,
      owner: 'owner@example.com',
      org_id: existing.org_id,
      scopes: ['read:events'],
      version: 2,
      issued_at: NOW.toISOString(),
      ...(overrides.policyDoc ?? {}),
    };
    return {
      ...doc,
      policy_update: true,
      policy_doc: policyDoc,
      existing_cert: existing,
      owner_sig: await signCanonical(canonicalize(extractIdentityFields(existing)), ownerKey),
      pa_sig: await signCanonical(canonicalize(extractPolicyFields(policyDoc)), paKey),
      ...(overrides.doc ?? {}),
    };
  }

  it('a correctly dual-signed update passes all nine stages', async () => {
    const r = await run(await policyDocument());
    expect(r.verdict, `denied with ${r.error_code}`).toBe('PASS');
    expect(r.stages[3].detail).toContain('Phase 1');
  });

  it('sign with one key only -> ERR_PA_SIG_MISSING §9.3', async () => {
    await deniesWith(await policyDocument({ doc: { pa_sig: null } }), 'ERR_PA_SIG_MISSING');
  });

  it('tamper with the policy doc -> ERR_PA_SIG_INVALID §9.3', async () => {
    // Tamper with a field that stays INSIDE the §7.2 ceiling, so the signature
    // check is what fires. Widening scopes would be refused by §7.2 first —
    // correct, but it would stop this test proving anything about signatures.
    const doc = await policyDocument();
    doc.policy_doc.issued_at = '2030-01-01T00:00:00.000Z';  // altered after the PA signed
    await deniesWith(doc, 'ERR_PA_SIG_INVALID');
  });

  it('widen scopes past the template ceiling -> ERR_POLICY_EXCEEDS_TEMPLATE §7.2', async () => {
    // Two VALID signatures are still not enough to grant beyond the template.
    const doc = await policyDocument({ policyDoc: { scopes: ['admin:all'] } });
    await deniesWith(doc, 'ERR_POLICY_EXCEEDS_TEMPLATE');
  });

  it('edit can_spawn via policy update -> ERR_IMMUTABLE_FIELD §9.3 (AC-6)', async () => {
    await deniesWith(await policyDocument({ policyDoc: { can_spawn: [AGENT_A] } }), 'ERR_IMMUTABLE_FIELD');
  });

  it('edit max_children via policy update -> ERR_IMMUTABLE_FIELD §9.3', async () => {
    await deniesWith(await policyDocument({ policyDoc: { max_children: 99 } }), 'ERR_IMMUTABLE_FIELD');
  });

  it('drop a required field -> ERR_REQUIRED_FIELD §9.3', async () => {
    const doc = await policyDocument();
    delete doc.policy_doc.issued_at;
    await deniesWith(doc, 'ERR_REQUIRED_FIELD');
  });

  it('a policy update with no authorities -> ERR_AUTHORITY_CHAIN §9.3', async () => {
    const doc = await policyDocument();
    doc.authorities = {};
    await deniesWith(doc, 'ERR_AUTHORITY_CHAIN');
  });

  it('an authority certificate that does not chain to the CA -> ERR_AUTHORITY_CHAIN', async () => {
    const doc = await policyDocument();
    doc.authorities.pa = { cert_pem: read('forged.crt'), common_name: AGENT_A };
    await deniesWith(doc, 'ERR_AUTHORITY_CHAIN');
  });
});

describe('AC-5 — refusal happens at issuance, before a certificate exists', () => {
  it('refuses a delegation wider than the parent', async () => {
    const doc = defaultDocument();
    const b = agent(doc, AGENT_B);
    // Agent A holds read+write. Ask for a child with a scope A never held.
    b.metadata.allowed_scopes = ['admin:all'];
    b.metadata.authorization_bounds.allowed_scopes = ['admin:all'];
    b.requested_scopes = ['admin:all'];
    const r = await deniesWith(doc, 'ERR_SCOPE_ESCALATION');
    expect(r.stages.at(-1).section).toBe('8.3');
  });

  it('permits a narrowing delegation', async () => {
    const doc = defaultDocument();
    const b = agent(doc, AGENT_B);
    b.metadata.allowed_scopes = ['read:events'];
    b.metadata.authorization_bounds.allowed_scopes = ['read:events'];
    expect((await run(doc)).verdict).toBe('PASS');
  });
});

describe('the stage log stops at the first failure', () => {
  it('records the failing stage and nothing after it', async () => {
    const doc = defaultDocument();
    doc.crl.revoked.push(AGENT_A);           // stage 3
    const r = await run(doc);
    expect(r.stages.map((s) => s.n)).toEqual([1, 2, 3]);
    expect(r.stages.at(-1).result).toBe('DENY');
  });

  it('still appends the refusal to the audit chain', async () => {
    const doc = defaultDocument();
    doc.crl.revoked.push(AGENT_A);
    const r = await run(doc);
    expect(r.audit.entries).toBe(1);
    expect(r.audit.chain[0].event.decision).toBe('DENIED');
    expect(r.audit.chain[0].event.reason).toBe('ERR_AGENT_REVOKED');
  });
});
