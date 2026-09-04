/**
 * The nine-stage pipeline over the seed document, then every sabotage the page
 * offers, each asserting its SPECIFIC code and clause. The scenarios are the
 * same functions the buttons call (src/scenarios.js), so a green test here is
 * a claim about the page, not about a parallel copy of its logic.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { runPipeline, NOT_APPLICABLE, DRAFT } from '../src/pipeline.js';
import { buildDefaultDocument } from '../src/defaults.js';
import { newAgentId } from '../src/mint.js';
import { contentHash, signEnvelope, privateKeyFromPem } from '../src/crypto-sign.js';
import {
  childOf, parentOf, templateOf, spawnOf, reissueThroughRegistry, issueRaw, resignPolicy, spawnAcrossOrganizations,
  issueSecondChildWithNonce, setInForcePolicy, dropInForcePolicy,
} from '../src/scenarios.js';
import { Registry } from '../src/mint.js';

let base, now;
beforeAll(async () => { now = new Date(); base = await buildDefaultDocument({ now }); }, 30_000);
const clone = () => JSON.parse(JSON.stringify(base));
// Validated at the real clock: certificates re-issued by a scenario are valid
// from the moment they were minted, which is after `now`.
const run = (d, at = new Date()) => runPipeline({ document: d, now: at });

async function expectRefusal(d, code, section, { walk = null } = {}) {
  const r = await run(d);
  expect(r.verdict, `expected ${code}, got ${r.error_code}: ${r.stages.find((s) => s.result === 'DENY')?.detail}`).toBe('DENY');
  expect(r.error_code).toBe(code);
  expect(r.draft_section).toBe(section);
  expect(r.banner).toBe(section ? `${code} · §${section}` : code);
  expect(r.stages.filter((s) => s.result === 'DENY')).toHaveLength(1);
  if (walk) expect(r.walk.find((w) => w.result === 'DENY')?.subject).toBe(walk);
  return r;
}

describe('the default chain passes every stage', () => {
  it('returns PASS with nine PASS stages in order and seven walk steps', async () => {
    const r = await run(clone());
    expect(r.verdict).toBe('PASS');
    expect(r.stages.map((s) => [s.n, s.result])).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9].map((n) => [n, 'PASS']));
    expect(r.walk.map((w) => w.subject)).toEqual(['TRUST ANCHOR', 'PARENT AGENT', 'CHILD AGENT', 'CROSS-ORG GRANT',
      'POLICY UPDATE', 'DELEGATION', 'AUDIT CHAIN']);
    expect(r.walk.every((w) => w.result === 'PASS')).toBe(true);
    expect(r.advisories).toEqual([]);
  });
  it('cites -03 clauses on every stage', async () => {
    const r = await run(clone());
    expect(r.stages.map((s) => s.section)).toEqual(['7.2', '7', '14', '11.3', '11.4', '11.4', '10.1', '10.3', '19.7']);
  });
  it('appends exactly one audit entry for the run', async () => {
    const r = await run(clone());
    expect(r.audit.entries).toBe(base.audit.chain.length + 1);
    expect(r.audit.chain.at(-1)).toMatchObject({ action: 'verify_chain', outcome: 'ALLOWED' });
  });
});

describe('§10.2 step 3 — the policy in force, and §10.5 grant_id', () => {
  it('a policy in force that omits the child → ERR_SPAWN_NOT_IN_POLICY §10.2 at DELEGATION', async () => {
    const d = clone(); await setInForcePolicy(d, parentOf(d).metadata.agent_id, { spawn_targets: [] });
    await expectRefusal(d, 'ERR_SPAWN_NOT_IN_POLICY', '10.2', { walk: 'DELEGATION' });
  });
  it('no policy in force for the parent → ERR_SPAWN_NOT_IN_POLICY — absent grants nothing (§11.4, §15.1)', async () => {
    const d = clone(); dropInForcePolicy(d, parentOf(d).metadata.agent_id);
    const r = await expectRefusal(d, 'ERR_SPAWN_NOT_IN_POLICY', '10.2');
    expect(r.stages.find((s) => s.result === 'DENY').detail).toMatch(/no policy is in force/);
  });
  it('a policy in force is verified like any envelope: a tampered one is refused before it is consulted', async () => {
    const d = clone(); d.policies[0].body.spawn_targets = [...d.policies[0].body.spawn_targets, newAgentId()];
    await expectRefusal(d, 'ERR_OWNER_SIG_INVALID', '11.3', { walk: 'DELEGATION' });
  });
  it('a policy in force beyond its template’s ceiling → ERR_POLICY_EXCEEDS_TEMPLATE §8.3', async () => {
    const d = clone(); await setInForcePolicy(d, childOf(d).metadata.agent_id, { scopes: ['admin:all'] });
    await expectRefusal(d, 'ERR_POLICY_EXCEEDS_TEMPLATE', '8.3');
  });
  it('a same-organization child whose certificate names a grant → ERR_GRANT_ID_MISMATCH §10.5', async () => {
    const d = clone(); const c = childOf(d);
    await issueRaw(d, c, { spawn: { ...spawnOf(c), grant_id: newAgentId() } });
    await expectRefusal(d, 'ERR_GRANT_ID_MISMATCH', '10.5', { walk: 'DELEGATION' });
  });
  it('a cross-organization child whose certificate names no grant → ERR_GRANT_ID_MISMATCH §10.5', async () => {
    const d = clone(); await spawnAcrossOrganizations(d, {}, { now });
    const c = childOf(d); const { grant_id: _dropped, ...spawn } = spawnOf(c);
    await issueRaw(d, c, { spawn });
    await expectRefusal(d, 'ERR_GRANT_ID_MISMATCH', '10.5', { walk: 'CROSS-ORG GRANT' });
  });
  it('a cross-organization child issued under a DIFFERENT grant than the one presented → ERR_GRANT_INVALID', async () => {
    const d = clone(); await spawnAcrossOrganizations(d, {}, { now });
    d.grant = await signEnvelope({ ...d.grant.body, grant_id: newAgentId() },
      await privateKeyFromPem(d.authorities.owner.key_pem), await privateKeyFromPem(d.authorities.pa.key_pem));
    const r = await expectRefusal(d, 'ERR_GRANT_INVALID', '13.2', { walk: 'CROSS-ORG GRANT' });
    expect(r.stages.find((s) => s.result === 'DENY').detail).toMatch(/not this one/);
  });
  it('revoking the grant revokes the certificates issued under it (§13.4)', async () => {
    const d = clone(); await spawnAcrossOrganizations(d, {}, { now });
    const revoked = d.grant.body.grant_id;
    for (const n of d.chain) if (n.role === 'agent' && spawnOf(n)?.grant_id === revoked) d.crl.revoked.push(n.metadata.agent_id);
    await expectRefusal(d, 'ERR_AGENT_REVOKED', '14', { walk: 'CHILD AGENT' });
  });
  it('an audit entry outside Table 6 → ERR_AUDIT_ENTRY_INVALID §10.4 at AUDIT CHAIN', async () => {
    const d = clone();
    const spawn = d.audit.chain.find((e) => 'spawning_agent_id' in e);
    spawn.outcome = 'MAYBE';
    await expectRefusal(d, 'ERR_AUDIT_ENTRY_INVALID', '10.4', { walk: 'AUDIT CHAIN' });
  });
  it('a certificate whose MaxChildren exceeds CanSpawn → ERR_MAX_CHILDREN_EXCEEDS_CAN_SPAWN §8.1 at the parent', async () => {
    const d = clone(); await issueRaw(d, parentOf(d), { template: { max_children: 5 } });
    await expectRefusal(d, 'ERR_MAX_CHILDREN_EXCEEDS_CAN_SPAWN', '8.1', { walk: 'PARENT AGENT' });
  });
  it('a non-minimal serial → ERR_SERIAL_ENCODING §7.1; an oversized template extension → ERR_EXTENSION_TOO_LARGE §8.2', async () => {
    let d = clone();
    const octets = new Uint8Array(20); crypto.getRandomValues(octets); octets[0] = 0x00; octets[1] &= 0x7f;
    await issueRaw(d, childOf(d), { serialOctets: octets });
    await expectRefusal(d, 'ERR_SERIAL_ENCODING', '7.1', { walk: 'CHILD AGENT' });
    d = clone();
    await issueRaw(d, childOf(d), { template: { policy_ref: `policy-store/${'x'.repeat(17000)}/current` } });
    await expectRefusal(d, 'ERR_EXTENSION_TOO_LARGE', '8.2', { walk: 'CHILD AGENT' });
  });
});

describe('the output contract', () => {
  it('has stable key order and no undefined values', async () => {
    const r = await run(clone());
    expect(Object.keys(r)).toEqual(['playground_version', 'draft', 'generated_at', 'demo_only', 'verdict', 'walk',
      'advisories', 'error_code', 'draft_section', 'banner', 'stages', 'not_applicable', 'chain', 'authorities', 'crl', 'audit']);
    expect(JSON.stringify(r)).not.toContain('undefined');
  });
  it('claims -03', async () => {
    expect(DRAFT).toBe('draft-tonyai-a2a-trust-03');
    expect((await run(clone())).draft).toBe('draft-tonyai-a2a-trust-03');
  });
  it('names the two things it does NOT do, and nothing else', () => {
    expect(NOT_APPLICABLE.map((n) => n.check)).toEqual(['max_children_enforcement', 'policy_engine_gate']);
    expect(NOT_APPLICABLE.map((n) => n.section)).toEqual(['10.2', '11.7']);
  });
  it('never throws, whatever it is handed', async () => {
    for (const doc of [null, undefined, {}, { chain: 'x' }, { chain: [] }, { chain: [{ role: 'ca' }] }, { chain: [{}] }]) {
      const r = await runPipeline({ document: doc, now });
      expect(r.verdict).toBe('DENY');
      expect(typeof r.error_code).toBe('string');
    }
  });
});

describe('every sabotage yields its documented code and clause', () => {
  it('revoke the parent → ERR_AGENT_REVOKED §14', async () => {
    const d = clone(); d.crl.revoked.push(parentOf(d).metadata.agent_id);
    await expectRefusal(d, 'ERR_AGENT_REVOKED', '14', { walk: 'PARENT AGENT' });
  });
  it('disable the template → ERR_AGENT_DISABLED §12.4, catalogued at stage 3 so the stage-2 X.509 PASS survives', async () => {
    const d = clone(); d.crl.disabled.push(childOf(d).metadata.agent_id);
    const r = await expectRefusal(d, 'ERR_AGENT_DISABLED', '12.4', { walk: 'CHILD AGENT' });
    expect(r.stages.find((s) => s.n === 2)).toMatchObject({ result: 'PASS' });
    expect(r.stages.find((s) => s.n === 3)).toMatchObject({ result: 'DENY', check: 'revocation' });
  });
  it('expire the certificate → ERR_CERT_EXPIRED §7', async () => {
    const d = clone(); const at = new Date('2020-01-01T00:00:00Z');
    await issueRaw(d, childOf(d), { notBefore: at, notAfter: new Date(at.getTime() + 3600_000) });
    await expectRefusal(d, 'ERR_CERT_EXPIRED', '7', { walk: 'CHILD AGENT' });
  });
  it('escalate the scope in the certificate → ERR_SCOPE_ESCALATION §10.3 at DELEGATION', async () => {
    const d = clone(); const c = childOf(d);
    await issueRaw(d, c, { template: { allowed_scopes: ['admin:all'] } }); c.requested_scopes = ['admin:all']; delete d.policy;
    dropInForcePolicy(d, c.metadata.agent_id);   // the child's policy in force would trip §8.3 first
    await expectRefusal(d, 'ERR_SCOPE_ESCALATION', '10.3', { walk: 'DELEGATION' });
  });
  it('request beyond the certificate → ERR_SCOPE_ESCALATION', async () => {
    const d = clone(); childOf(d).requested_scopes = ['write:events'];
    await expectRefusal(d, 'ERR_SCOPE_ESCALATION', '10.3');
  });
  it('request nothing → ERR_EMPTY_SCOPES §10.3', async () => {
    const d = clone(); childOf(d).requested_scopes = [];
    await expectRefusal(d, 'ERR_EMPTY_SCOPES', '10.3');
  });
  it('exceed max_children → ERR_MAX_CHILDREN §10.2', async () => {
    const d = clone(); await issueRaw(d, parentOf(d), { template: { max_children: 0 } });
    await expectRefusal(d, 'ERR_MAX_CHILDREN', '10.2', { walk: 'DELEGATION' });
  });
  it('spawn a non-whitelisted child → ERR_CHILD_NOT_WHITELISTED §10.1', async () => {
    const d = clone(); const p = parentOf(d);
    await issueRaw(d, p, { template: { can_spawn: [], max_children: 0 } });
    await setInForcePolicy(d, p.metadata.agent_id, { spawn_targets: [] });   // else §8.3 refuses the policy first
    await expectRefusal(d, 'ERR_CHILD_NOT_WHITELISTED', '10.1');
  });
  it('parent without spawn → ERR_SPAWN_NOT_PERMITTED §10.1', async () => {
    const d = clone(); await issueRaw(d, parentOf(d), { template: { permitted_operations: ['read'] } });
    await expectRefusal(d, 'ERR_SPAWN_NOT_PERMITTED', '10.1');
  });
  it('forge the issuer → ERR_FORGED_ISSUER §7', async () => {
    const d = clone(); const rogue = await Registry.create({ caCommonName: 'Rogue-CA', now });
    const c = childOf(d); const parent = templateOf(parentOf(d));
    await rogue.adoptPolicyFor(parent, { spawnTargets: [c.metadata.agent_id], now });
    const issued = await rogue.spawn({ attested: await rogue.attest(templateOf(c)), parent, now });
    c.cert_pem = issued.cert_pem; c.key_pem = issued.key_pem;
    await expectRefusal(d, 'ERR_FORGED_ISSUER', '7', { walk: 'CHILD AGENT' });
  });
  it('forge the parent link → ERR_PARENT_MISMATCH §10.5', async () => {
    const d = clone(); childOf(d).metadata.parent_agent_id = newAgentId();
    await expectRefusal(d, 'ERR_PARENT_MISMATCH', '10.5', { walk: 'CHILD AGENT' });
  });
  it('a root carrying an Agent Spawn extension → ERR_PARENT_MISMATCH §10.5', async () => {
    const d = clone(); const p = parentOf(d);
    await issueRaw(d, p, { spawn: { parent_agent_id: childOf(d).metadata.agent_id, spawned_at: now.toISOString(), spawn_nonce: Buffer.alloc(16, 1).toString('base64') } });
    await expectRefusal(d, 'ERR_PARENT_MISMATCH', '10.5', { walk: 'PARENT AGENT' });
  });
  it('a child whose certificate carries no Agent Spawn extension → ERR_SPAWN_EXT_INVALID §10.5', async () => {
    const d = clone(); await issueRaw(d, childOf(d), { spawn: null });
    await expectRefusal(d, 'ERR_SPAWN_EXT_INVALID', '10.5');
  });
  it('a parent the certificate names that is not in the chain → ERR_PARENT_MISMATCH', async () => {
    const d = clone(); d.chain = d.chain.filter((n) => n !== parentOf(d));
    await expectRefusal(d, 'ERR_PARENT_MISMATCH', '10.5');
  });
  it('one identity, two certificates → ERR_DUPLICATE_SUBJECT §12.1', async () => {
    const d = clone(); d.chain.push(JSON.parse(JSON.stringify(childOf(d))));
    await expectRefusal(d, 'ERR_DUPLICATE_SUBJECT', '12.1');
  });
  it('two certificates with one spawn nonce → ERR_NONCE_REUSED §19.2', async () => {
    const d = clone(); await issueSecondChildWithNonce(d);
    await expectRefusal(d, 'ERR_NONCE_REUSED', '19.2');
  });
  it('an agent certificate asserting keyCertSign → ERR_KEY_USAGE §7.1', async () => {
    const d = clone(); await issueRaw(d, childOf(d), { keyUsageBits: [0, 5] });
    await expectRefusal(d, 'ERR_KEY_USAGE', '7.1');
  });
  it('a certificate outliving its ttl_seconds → ERR_VALIDITY_EXCEEDS_TTL §9.3', async () => {
    const d = clone(); const c = childOf(d); const ttl = templateOf(c).ttl_seconds;
    await issueRaw(d, c, { notBefore: now, notAfter: new Date(now.getTime() + (ttl + 1) * 1000) });
    await expectRefusal(d, 'ERR_VALIDITY_EXCEEDS_TTL', '9.3');
  });
  it('a leaf with no revocation source → ERR_NO_REVOCATION_SOURCE §14.4', async () => {
    const d = clone(); await issueRaw(d, childOf(d), { revocationSource: false });
    await expectRefusal(d, 'ERR_NO_REVOCATION_SOURCE', '14.4');
  });
  it('a non-critical profile extension → ERR_TEMPLATE_EXT_INVALID §8.2', async () => {
    const d = clone(); await issueRaw(d, childOf(d), { criticalExtensions: false });
    await expectRefusal(d, 'ERR_TEMPLATE_EXT_INVALID', '8.2');
  });
  it('alter an audit entry → ERR_AUDIT_CHAIN_BROKEN §19.7, naming the entry', async () => {
    const d = clone(); d.audit.chain[1].detail = 'altered';
    const r = await expectRefusal(d, 'ERR_AUDIT_CHAIN_BROKEN', '19.7', { walk: 'AUDIT CHAIN' });
    expect(r.stages.find((s) => s.result === 'DENY').detail).toMatch(/entry 1/);
  });
});

describe('cross-organizational grants (§13)', () => {
  it('a cross-org spawn with no grant → ERR_GRANT_MISSING §13.1 at CROSS-ORG GRANT', async () => {
    const d = clone(); await spawnAcrossOrganizations(d, {}, { now }); delete d.grant;
    await expectRefusal(d, 'ERR_GRANT_MISSING', '13.1', { walk: 'CROSS-ORG GRANT' });
  });
  it('a cross-org spawn with a valid grant PASSES, and the walk says so', async () => {
    const d = clone(); await spawnAcrossOrganizations(d, {}, { now });
    const r = await run(d);
    expect(r.verdict).toBe('PASS');
    expect(r.walk.find((w) => w.subject === 'CROSS-ORG GRANT').detail).toMatch(/partner-org → playground-org/);
  });
  it('an expired grant → ERR_GRANT_EXPIRED §13.2', async () => {
    const d = clone(); await spawnAcrossOrganizations(d, { issued_at: new Date(now.getTime() - 7200_000).toISOString(), ttl_seconds: 3600 }, { now });
    await expectRefusal(d, 'ERR_GRANT_EXPIRED', '13.2');
  });
  it('a grant beyond the template → ERR_GRANT_EXCEEDS_TEMPLATE §13.2', async () => {
    const d = clone(); await spawnAcrossOrganizations(d, { allowed_scopes: ['read:events', 'admin:all'] }, { now });
    await expectRefusal(d, 'ERR_GRANT_EXCEEDS_TEMPLATE', '13.2');
  });
  it('a grant missing a signature or a field → ERR_GRANT_INVALID §13.2', async () => {
    let d = clone(); await spawnAcrossOrganizations(d, {}, { now }); delete d.grant.pa_sig;
    await expectRefusal(d, 'ERR_GRANT_INVALID', '13.2');
    d = clone(); await spawnAcrossOrganizations(d, {}, { now }); delete d.grant.body.issued_at;
    await expectRefusal(d, 'ERR_GRANT_INVALID', '13.2');
  });
  it('a grant permitting no spawns → ERR_MAX_SPAWNS §13.2', async () => {
    const d = clone(); await spawnAcrossOrganizations(d, { max_spawns: 0 }, { now });
    await expectRefusal(d, 'ERR_MAX_SPAWNS', '13.2');
  });
  it('the request is bounded by the grant too', async () => {
    const d = clone(); await spawnAcrossOrganizations(d, {}, { now });
    d.grant.body.allowed_scopes = []; d.grant = await signEnvelope(d.grant.body,
      await privateKeyFromPem(d.authorities.owner.key_pem), await privateKeyFromPem(d.authorities.pa.key_pem));
    await expectRefusal(d, 'ERR_SCOPE_ESCALATION', '10.3');
  });
  // A single-organization chain carrying a grant it does not need. The grant
  // is re-signed for the organization the child ends up in, so the only thing
  // wrong with it is whatever the test then does to it.
  async function withUnusedGrant() {
    const d = clone(); await spawnAcrossOrganizations(d, {}, { now });
    const childId = childOf(d).metadata.agent_id;
    // Back into the parent's organization: the policy in force follows the template (§11.2).
    await setInForcePolicy(d, childId, { org_id: 'playground-org' });
    await reissueThroughRegistry(d, childOf(d), { org_id: 'playground-org' }, { now });
    d.policy.body.org_id = 'playground-org'; await resignPolicy(d);
    d.grant = await signEnvelope({ ...d.grant.body, grantor: 'playground-org', grantee: 'playground-org' },
      await privateKeyFromPem(d.authorities.owner.key_pem), await privateKeyFromPem(d.authorities.pa.key_pem));
    return d;
  }
  it('a grant nothing uses is verified, and the walk says it is unused', async () => {
    const r = await run(await withUnusedGrant());
    expect(r.verdict).toBe('PASS');
    expect(r.walk.find((w) => w.subject === 'CROSS-ORG GRANT').detail).toMatch(/unused/);
  });
  it('a grant nothing uses is still refused when it does not verify', async () => {
    const d = await withUnusedGrant();
    delete d.grant.owner_sig;
    const r = await expectRefusal(d, 'ERR_GRANT_INVALID', '13.2', { walk: 'CROSS-ORG GRANT' });
    expect(r.stages.find((s) => s.result === 'DENY').detail).toMatch(/no Owner signature/);
  });
  it('an unused grant is matched against the agent it NAMES, not against whichever agent is first in a multi-child chain', async () => {
    const d = clone();
    const parent = parentOf(d);
    const firstChildId = childOf(d).metadata.agent_id;
    const secondChildId = newAgentId();
    // Widen the parent so it can spawn a second child too — the certificate
    // (CanSpawn) and the policy in force (SpawnTargets) both — then mint one.
    await reissueThroughRegistry(d, parent,
      { can_spawn: [firstChildId, secondChildId], max_children: 2 }, { now });
    await setInForcePolicy(d, parent.metadata.agent_id, { spawn_targets: [firstChildId, secondChildId] });
    const registry = await Registry.fromDocument(d, { now });
    const secondTemplate = { ...templateOf(childOf(d)), subject: secondChildId };
    const issued = await registry.spawn({
      attested: await registry.attest(secondTemplate), parent: templateOf(parent), now,
    });
    d.chain.push({ role: 'agent', cert_pem: issued.cert_pem, key_pem: issued.key_pem,
      metadata: { agent_id: secondChildId, parent_agent_id: parent.metadata.agent_id } });
    // A leftover grant that names the SECOND child specifically. `children[0]`
    // in this chain is the FIRST child — an arbitrary pairing would try to
    // validate this grant against the first child's org and template, and
    // refuse a grant that is well-formed, validly signed, and correctly
    // addressed to the agent it actually names.
    d.grant = await signEnvelope({
      grant_id: newAgentId(), grantor: 'playground-org', grantee: 'playground-org', template: secondChildId,
      allowed_scopes: [...secondTemplate.allowed_scopes], issued_at: now.toISOString(),
      ttl_seconds: 3600, max_spawns: 1,
    }, await privateKeyFromPem(d.authorities.owner.key_pem), await privateKeyFromPem(d.authorities.pa.key_pem));
    const r = await run(d);
    expect(r.verdict, `expected PASS, got ${r.error_code}: ${r.stages.find((s) => s.result === 'DENY')?.detail}`).toBe('PASS');
    expect(r.walk.find((w) => w.subject === 'CROSS-ORG GRANT').detail).toMatch(/unused/);
  });
});

describe('advisories — SHOULD, not MUST', () => {
  it('a child that outlives its parent PASSES with an advisory at DELEGATION (§10.3)', async () => {
    const d = clone(); await reissueThroughRegistry(d, childOf(d), { ttl_seconds: 172800 }, { now });
    const r = await run(d);
    expect(r.verdict).toBe('PASS');
    expect(r.advisories).toHaveLength(1);
    expect(r.advisories[0].section).toBe('10.3');
    expect(r.walk.find((w) => w.subject === 'DELEGATION').result).toBe('ADVISORY');
    expect(r.stages.find((s) => s.n === 8).result).toBe('ADVISORY');
  });
});

describe('policy sabotage (§11)', () => {
  it('sign with one key only → ERR_PA_SIG_MISSING §11.3 at POLICY UPDATE', async () => {
    const d = clone(); d.policy.pa_sig = null;
    await expectRefusal(d, 'ERR_PA_SIG_MISSING', '11.3', { walk: 'POLICY UPDATE' });
  });
  it('tamper with the body → ERR_OWNER_SIG_INVALID §11.3', async () => {
    const d = clone(); d.policy.body.issued_at = '2027-01-01T00:00:00Z'; d.policy.content_hash = await contentHash(d.policy.body);
    await expectRefusal(d, 'ERR_OWNER_SIG_INVALID', '11.3');
  });
  it('widen past the ceiling, correctly signed → ERR_POLICY_EXCEEDS_TEMPLATE §8.3', async () => {
    const d = clone(); d.policy.body.scopes = ['admin:all']; await resignPolicy(d);
    await expectRefusal(d, 'ERR_POLICY_EXCEEDS_TEMPLATE', '8.3', { walk: 'POLICY UPDATE' });
  });
  it('edit can_spawn via policy → ERR_IMMUTABLE_FIELD §11.4', async () => {
    const d = clone(); d.policy.body.can_spawn = [];
    await expectRefusal(d, 'ERR_IMMUTABLE_FIELD', '11.4');
  });
  it('replay an old policy, bump version → a signature breaks (§11.6)', async () => {
    const d = clone(); d.current_policy_version = 5; d.policy.body.version = 6;
    await expectRefusal(d, 'ERR_OWNER_SIG_INVALID', '11.3');
  });
  it('alter the stored hash only → ERR_CONTENT_HASH §11.6', async () => {
    const d = clone(); d.policy.content_hash = '0'.repeat(64);
    await expectRefusal(d, 'ERR_CONTENT_HASH', '11.6');
  });
  it('submit as the wrong owner → ERR_OWNER_MISMATCH §11.2', async () => {
    const d = clone(); d.policy.body.owner = 'attacker@example.com';
    await expectRefusal(d, 'ERR_OWNER_MISMATCH', '11.2');
  });
  it('one key, both roles → ERR_SINGLE_SIGNATURE §3.1', async () => {
    const d = clone(); d.authorities.pa = { ...d.authorities.owner };
    const key = await privateKeyFromPem(d.authorities.owner.key_pem);
    d.policy = await signEnvelope(d.policy.body, key, key, { withHash: true });
    await expectRefusal(d, 'ERR_SINGLE_SIGNATURE', '3.1');
  });
  it('the Owner certificate does not name the template owner → ERR_OWNER_CERT_MISMATCH §9.2', async () => {
    const d = clone(); await issueRaw(d, childOf(d), { template: { owner: 'another-owner' } });
    d.policy.body.owner = 'another-owner'; await resignPolicy(d);
    await expectRefusal(d, 'ERR_OWNER_CERT_MISMATCH', '9.2');
  });
  it('a policy update with no authorities → ERR_AUTHORITY_CHAIN §9.2', async () => {
    const d = clone(); delete d.authorities;
    await expectRefusal(d, 'ERR_AUTHORITY_CHAIN', '9.2');
  });
  it('an authority that does not chain to the anchor → ERR_AUTHORITY_CHAIN', async () => {
    const d = clone(); d.authorities.pa.cert_pem = d.chain[0].cert_pem;
    await expectRefusal(d, 'ERR_AUTHORITY_CHAIN', '9.2');
  });
  it('a stale envelope member → ERR_ENVELOPE_MEMBER §3.1', async () => {
    const d = clone(); d.policy.policy_update = true;
    await expectRefusal(d, 'ERR_ENVELOPE_MEMBER', '3.1');
  });
});

describe('the chain document asserts no authority of its own', () => {
  it('refuses a -02-style template field in the metadata', async () => {
    const d = clone(); childOf(d).metadata.allowed_scopes = ['admin:all'];
    await expectRefusal(d, 'ERR_SCHEMA_VIOLATION', null);
  });
  it('refuses an unknown node field', async () => {
    const d = clone(); childOf(d).authorization_bounds = {};
    await expectRefusal(d, 'ERR_SCHEMA_VIOLATION', null);
  });
  it('a re-issued child through the Registry stays valid — identity is the UUID, not the key', async () => {
    const d = clone(); await reissueThroughRegistry(d, childOf(d), {}, { now });
    expect((await run(d)).verdict).toBe('PASS');
  });
  it('narrowing the parent stays valid; the child is still a subset, and the policy in force is re-stated within the new ceiling', async () => {
    const d = clone(); const p = parentOf(d);
    await reissueThroughRegistry(d, p, { allowed_scopes: ['read:events'] }, { now });
    await setInForcePolicy(d, p.metadata.agent_id, { scopes: ['read:events'] });
    expect((await run(d)).verdict).toBe('PASS');
  });
  it('narrowing the parent WITHOUT re-stating its policy is refused: a retired template’s policy is not inherited (§8.3, §12.3)', async () => {
    const d = clone(); await reissueThroughRegistry(d, parentOf(d), { allowed_scopes: ['read:events'] }, { now });
    await expectRefusal(d, 'ERR_POLICY_EXCEEDS_TEMPLATE', '8.3');
  });
});

describe('the stage log stops at the first failure and still records the refusal', () => {
  it('records the failing stage, nothing after it, and a DENIED audit entry', async () => {
    const d = clone(); d.crl.revoked.push(childOf(d).metadata.agent_id);
    const r = await run(d);
    expect(Math.max(...r.stages.map((s) => s.n))).toBe(3);
    expect(r.audit.chain.at(-1)).toMatchObject({ outcome: 'DENIED', reason: 'ERR_AGENT_REVOKED' });
    expect(r.audit.chain.at(-1).agents).toHaveLength(2);
  });
});

describe('document shape — chain nodes', () => {
  it('a chain node that is not an object → ERR_SCHEMA_VIOLATION', async () => {
    for (const bad of [null, 'agent', 7, []]) {
      const d = clone(); d.chain.push(bad);
      const r = await expectRefusal(d, 'ERR_SCHEMA_VIOLATION', null);
      expect(r.stages.find((s) => s.result === 'DENY').detail).toMatch(/must be an object/);
    }
  });
  it('a chain with a trust anchor and no agents → ERR_SCHEMA_VIOLATION', async () => {
    const d = clone(); d.chain = d.chain.filter((n) => n.role === 'ca');
    const r = await expectRefusal(d, 'ERR_SCHEMA_VIOLATION', null);
    expect(r.stages.find((s) => s.result === 'DENY').detail).toMatch(/no agent nodes/);
  });
});
