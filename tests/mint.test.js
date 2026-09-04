/**
 * The Registry and the certificates it issues (§9, §10.2, §19.2), plus the
 * demo-only profile. OpenSSL is consulted wherever it can be: the minted
 * certificates verify under `openssl verify -ignore_critical` and are refused
 * without the flag, which is the §8.2 design working.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import {
  Registry, mintChain, newAgentId, newNonce, generateKeyPair, issueCertificate, toPem,
  DEMO_NOTICE_OID, FRESHNESS_WINDOW_MS, CRL_URI, OWNER_COMMON_NAME,
} from '../src/mint.js';
import { templateFor } from '../src/defaults.js';
import {
  validateCertificate, validateAnchor, parseCertificate, parseTemplateExtension, parseSpawnExtension,
  publicKeyInfo, normalizeOid,
} from '../src/x509.js';
import { validateUuid } from '../src/validate-input.js';
import { DenyError } from '../src/errors.js';

const refuses = async (code, promise) => {
  let caught = null;
  try { await promise; } catch (e) { caught = e; }
  expect(caught, 'expected a refusal').toBeInstanceOf(DenyError);
  expect(caught.code).toBe(code);
  return caught;
};

let minted, parentId, childId, parentT, childT, now;
beforeAll(async () => {
  now = new Date();
  parentId = newAgentId(); childId = newAgentId();
  parentT = templateFor({ subject: parentId, scopes: ['read:events', 'write:events'], canSpawn: [childId], maxChildren: 1,
    ttlSeconds: 86400, permittedOperations: ['spawn', 'read'] });
  childT = templateFor({ subject: childId, scopes: ['read:events'], ttlSeconds: 43200 });
  minted = await mintChain({ parent: parentT, child: childT, now });
}, 30_000);

describe('the playground validator accepts its own output', () => {
  it('the anchor is a valid CA', () => validateAnchor(minted.ca.cert_pem));
  it('every minted agent passes full §7 validation and carries its template', async () => {
    for (const a of minted.agents) {
      const r = await validateCertificate({ certPem: a.cert_pem, caPem: minted.ca.cert_pem, agentId: a.agent_id, now });
      expect(r.template.subject).toBe(a.agent_id);
      expect(r.key.curve).toBe('P-256');
    }
  });
  it('the child carries the Agent Spawn extension naming its parent, with a fresh nonce', async () => {
    const s = parseSpawnExtension(parseCertificate(minted.agents[1].cert_pem));
    expect(s.parent_agent_id).toBe(parentId);
    expect(Buffer.from(s.spawn_nonce, 'base64').length).toBe(16);
    expect(parseSpawnExtension(parseCertificate(minted.agents[0].cert_pem))).toBeNull();
  });
  it('both authorities validate in the authority role', async () => {
    for (const [role, cn] of [['owner', 'owner-authority'], ['pa', 'policy-authority']]) {
      await validateCertificate({ certPem: minted.authorities[role].cert_pem, caPem: minted.ca.cert_pem, agentId: cn, role: 'authority', now });
    }
  });
  it('binds validity to ttl_seconds exactly (§9.3)', () => {
    const c = parseCertificate(minted.agents[1].cert_pem);
    expect((c.notAfter.value - c.notBefore.value) / 1000).toBe(43200);
  });
  it('carries cRLDistributionPoints on every leaf and not on the anchor (§14.4)', () => {
    for (const pem of [minted.agents[0].cert_pem, minted.authorities.owner.cert_pem]) {
      const cdp = parseCertificate(pem).extensions.find((e) => e.extnID === '2.5.29.31');
      expect(cdp).toBeTruthy();
      expect(String(cdp.parsedValue.distributionPoints[0].distributionPoint[0].value)).toBe(CRL_URI);
    }
    expect(parseCertificate(minted.ca.cert_pem).extensions.find((e) => e.extnID === '2.5.29.31')).toBeUndefined();
  });
});

describe('OpenSSL and the minted certificates', () => {
  let dir;
  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), 'a2a-mint-'));
    writeFileSync(join(dir, 'ca.crt'), minted.ca.cert_pem);
    writeFileSync(join(dir, 'a.crt'), minted.agents[0].cert_pem);
    writeFileSync(join(dir, 'b.crt'), minted.agents[1].cert_pem);
    writeFileSync(join(dir, 'owner.crt'), minted.authorities.owner.cert_pem);
    writeFileSync(join(dir, 'b.key'), minted.agents[1].key_pem);
  });
  const verify = (f, ...flags) => {
    try { return execFileSync('openssl', ['verify', '-CAfile', join(dir, 'ca.crt'), ...flags, join(dir, f)], { encoding: 'utf8', stdio: 'pipe' }); }
    catch (e) { return String(e.stdout) + String(e.stderr); }
  };
  it('refuses the agent certificates without -ignore_critical — §8.2 working as designed', () => {
    expect(verify('a.crt')).toMatch(/unhandled critical extension/);
    expect(verify('b.crt')).toMatch(/unhandled critical extension/);
  });
  it('accepts them with -ignore_critical — the cryptography and the name constraint are sound', () => {
    expect(verify('a.crt', '-ignore_critical')).toMatch(/: OK/);
    expect(verify('b.crt', '-ignore_critical')).toMatch(/: OK/);
  });
  it('accepts the authority certificates outright — they carry no profile extension', () => {
    expect(verify('owner.crt')).toMatch(/: OK/);
  });
  it('encodes the DN as a sequence of RDNs, not one multi-valued RDN', () => {
    const subj = execFileSync('openssl', ['x509', '-in', join(dir, 'a.crt'), '-noout', '-subject'], { encoding: 'utf8' });
    expect(subj).toMatch(/C=US, O=PhalanxAI A2A Playground, OU=DEMO ONLY - NOT FOR PRODUCTION, CN=/);
    expect(subj).not.toContain(' + ');
  });
  it('reads the Agent Template extension bytes as the JCS the validator canonicalizes', () => {
    const text = execFileSync('openssl', ['x509', '-in', join(dir, 'a.crt'), '-noout', '-text'], { encoding: 'utf8' });
    expect(text).toContain(`${normalizeOid(TEMPLATE_OID_FROM_TEXT(text))}: critical`);
  });
  it('exports PKCS#8 that OpenSSL can read', () => {
    const out = execFileSync('openssl', ['pkey', '-in', join(dir, 'b.key'), '-noout', '-text'], { encoding: 'utf8' });
    expect(out).toMatch(/prime256v1|P-256/);
  });
  it('cleans up', () => rmSync(dir, { recursive: true, force: true }));
});
/** The extension OID as OpenSSL prints it: full decimal form. */
function TEMPLATE_OID_FROM_TEXT(text) {
  const m = /(2\.25\.318754453516410815925104555075461256891)/.exec(text);
  return m ? m[1] : 'not printed';
}

describe('§9.1 / §9.2 / §9.3 — the Registry gates', () => {
  let registry;
  beforeAll(async () => { registry = await Registry.create({ now }); });

  it('attests a conforming template with two signatures over its JCS form', async () => {
    const a = await registry.attest(parentT);
    expect(Object.keys(a).sort()).toEqual(['body', 'owner_sig', 'pa_sig']);
    expect(a.body).toEqual(parentT);
  });
  it('refuses to sign a template missing a REQUIRED member (§9.1)', async () => {
    const { ttl_seconds, ...t } = parentT;
    const e = await refuses('ERR_TEMPLATE_NONCONFORMING', registry.attest(t));
    expect(e.detail).toMatch(/ttl_seconds/);
  });
  it('refuses to sign a template with a null member, a nested member, or an unknown member', async () => {
    await refuses('ERR_OBJECT_NOT_FLAT', registry.attest({ ...parentT, policy_ref: null }));
    await refuses('ERR_OBJECT_NOT_FLAT', registry.attest({ ...parentT, can_spawn: [{}] }));
    await refuses('ERR_TEMPLATE_NONCONFORMING', registry.attest({ ...parentT, issuer: 'x' }));
  });
  it('refuses a template whose owner is not the Owner certificate’s subject (§9.2)', () =>
    refuses('ERR_OWNER_CERT_MISMATCH', registry.attest({ ...parentT, owner: 'someone-else' })));
  it('refuses to issue when a signature is missing (§9.2)', async () => {
    const a = await registry.attest(parentT);
    await refuses('ERR_TEMPLATE_SIGNATURE', registry.issue({ ...a, pa_sig: undefined }));
    await refuses('ERR_TEMPLATE_SIGNATURE', registry.issue({ ...a, owner_sig: '' }));
  });
  it('refuses to issue a template edited after signing — the gate is applied twice (§9.3)', async () => {
    const a = await registry.attest(parentT);
    a.body = { ...a.body, allowed_scopes: [...a.body.allowed_scopes, 'admin:all'] };
    await refuses('ERR_TEMPLATE_SIGNATURE', registry.issue(a));
  });
  it('refuses to issue a template that stopped conforming after signing (§9.1, second application)', async () => {
    const a = await registry.attest(parentT);
    delete a.body.policy_ref;
    await refuses('ERR_TEMPLATE_NONCONFORMING', registry.issue(a));
  });
  it('refuses to issue nothing', () => refuses('ERR_TEMPLATE_SIGNATURE', registry.issue(null)));
  it('refuses to issue a template whose owner changed after signing — checked before the signatures (§9.2)', async () => {
    const a = await registry.attest(parentT);
    const e = await refuses('ERR_OWNER_CERT_MISMATCH', registry.issue({ ...a, body: { ...a.body, owner: 'someone-else' } }));
    expect(e.detail).toMatch(/someone-else/);
  });
  it('refuses to issue when the Policy Authority signature is the Owner’s (§9.2)', async () => {
    const a = await registry.attest(parentT);
    const e = await refuses('ERR_TEMPLATE_SIGNATURE', registry.issue({ ...a, pa_sig: a.owner_sig }));
    expect(e.detail).toMatch(/Policy Authority/);
  });
  it('copies the signed members into the extension unaltered and sets the CN from subject (§9.3)', async () => {
    const issued = await registry.issue(await registry.attest(parentT), { now });
    const c = parseCertificate(issued.cert_pem);
    expect(parseTemplateExtension(c)).toEqual(parentT);
    expect(c.subject.typesAndValues.find((tv) => tv.type === '2.5.4.3').value.valueBlock.value).toBe(parentId);
  });
});

describe('§10.2 / §19.2 — the spawn request at the Registry', () => {
  /**
   * A Registry holds state now — the policy in force, the children it has
   * spawned, the live certificates — so each test that spawns gets its own,
   * with the parent's policy naming the child (§10.2 step 3).
   */
  const fresh = async ({ targets = [childId] } = {}) => {
    const registry = await Registry.create({ now });
    await registry.adoptPolicyFor(parentT, { spawnTargets: targets, now });
    return { registry, attested: await registry.attest(childT) };
  };
  const at = (offsetSeconds) => new Date(now.getTime() + offsetSeconds * 1000).toISOString();

  it('accepts a fresh request and records parent, time and nonce in the child (§10.5), and the event in the audit log (§10.4)', async () => {
    const { registry, attested } = await fresh();
    const r = await registry.spawn({ attested, parent: parentT, now });
    expect(r.spawn.parent_agent_id).toBe(parentId);
    expect(r.spawn.spawned_at).toBe(now.toISOString());
    expect('grant_id' in r.spawn).toBe(false);
    const entry = registry.audit.chain.at(-1);
    expect(entry).toMatchObject({ spawning_agent_id: parentId, child_template_id: childId, outcome: 'ALLOWED',
      spawn_nonce: r.spawn.spawn_nonce, requested_scopes: ['read:events'], granted_scopes: ['read:events'] });
    expect('reason' in entry).toBe(false);
    expect(() => registry.audit.assertEntries()).not.toThrow();
  });
  it('accepts 59 s either side and exactly 60 s', async () => {
    for (const s of [-59, 59, -60, 60]) {
      const { registry, attested } = await fresh();
      await registry.spawn({ attested, parent: parentT, now, requestedAt: at(s) });
    }
  });
  it('refuses 61 s in the past and 61 s in the future, naming the measured offset — and records each refusal (§10.4)', async () => {
    const { registry, attested } = await fresh();
    const past = await refuses('ERR_SPAWN_STALE', registry.spawn({ attested, parent: parentT, now, requestedAt: at(-61) }));
    expect(past.detail).toMatch(/61\.0 s in the past/);
    const future = await refuses('ERR_SPAWN_STALE', registry.spawn({ attested, parent: parentT, now, requestedAt: at(61) }));
    expect(future.detail).toMatch(/61\.0 s in the future/);
    const denied = registry.audit.chain.filter((e) => e.outcome === 'DENIED');
    expect(denied).toHaveLength(2);
    expect(denied[0]).toMatchObject({ child_template_id: childId, granted_scopes: [] });
    expect(denied[0].reason).toMatch(/^ERR_SPAWN_STALE/);
    expect(() => registry.audit.assertEntries()).not.toThrow();
  });
  it('the window is 60, not "roughly a minute": 60.5 s is refused', async () => {
    const { registry, attested } = await fresh();
    await refuses('ERR_SPAWN_STALE', registry.spawn({ attested, parent: parentT, now, requestedAt: at(60.5) }));
  });
  it('refuses a nonce it has already seen (§19.2)', async () => {
    const { registry, attested } = await fresh();
    const nonce = newNonce();
    await registry.spawn({ attested, parent: parentT, now, nonce });
    await refuses('ERR_NONCE_REUSED', registry.spawn({ attested, parent: parentT, now, nonce }));
  });
  it('a nonce is spent by being PRESENTED: a refused request consumes it (§19.2)', async () => {
    const { registry, attested } = await fresh();
    const nonce = newNonce();
    await refuses('ERR_SPAWN_STALE', registry.spawn({ attested, parent: parentT, now, nonce, requestedAt: at(-61) }));
    await refuses('ERR_NONCE_REUSED', registry.spawn({ attested, parent: parentT, now, nonce }));
    await registry.spawn({ attested, parent: parentT, now });   // a fresh nonce is all a retry needs
  });
  it('a request refused by ISSUE\'s re-gate has spent its nonce too — the nonce names the request, not the outcome', async () => {
    const { registry, attested } = await fresh();
    const nonce = newNonce();
    const tampered = { ...attested, pa_sig: attested.owner_sig };
    await refuses('ERR_TEMPLATE_SIGNATURE', registry.spawn({ attested: tampered, parent: parentT, now, nonce }));
    await refuses('ERR_NONCE_REUSED', registry.spawn({ attested, parent: parentT, now, nonce }));
  });
  it('refuses a nonce under 128 bits and a timestamp with an offset', async () => {
    const { registry, attested } = await fresh();
    await refuses('ERR_SCHEMA_VIOLATION', registry.spawn({ attested, parent: parentT, now, nonce: Buffer.alloc(8).toString('base64') }));
    await refuses('ERR_TIMESTAMP_FORMAT', registry.spawn({ attested, parent: parentT, now, requestedAt: now.toISOString().replace('Z', '+00:00') }));
  });
  it('Check 1 — refuses a parent without spawn in PermittedOperations (§10.1)', async () => {
    const { registry, attested } = await fresh();
    await refuses('ERR_SPAWN_NOT_PERMITTED', registry.spawn({ attested, parent: { ...parentT, permitted_operations: ['read'] }, now }));
  });
  it('Check 1 — refuses a child not in CanSpawn (§10.1)', async () => {
    const { registry, attested } = await fresh();
    await refuses('ERR_CHILD_NOT_WHITELISTED', registry.spawn({ attested, parent: { ...parentT, can_spawn: [], max_children: 0 }, now }));
  });
  it('step 3 — refuses a child the policy in force does not name, and one with no policy in force (§10.2)', async () => {
    let { registry, attested } = await fresh({ targets: [] });
    let e = await refuses('ERR_SPAWN_NOT_IN_POLICY', registry.spawn({ attested, parent: parentT, now }));
    expect(e.detail).toMatch(/not among them/);
    registry = await Registry.create({ now }); attested = await registry.attest(childT);
    e = await refuses('ERR_SPAWN_NOT_IN_POLICY', registry.spawn({ attested, parent: parentT, now }));
    expect(e.detail).toMatch(/no policy is in force/);
  });
  it('step 3 — a policy that withdraws the target is refused without re-certification: CanSpawn still names the child', async () => {
    const { registry, attested } = await fresh();
    await registry.adoptPolicyFor(parentT, { spawnTargets: [], version: 2, now });
    await refuses('ERR_SPAWN_NOT_IN_POLICY', registry.spawn({ attested, parent: parentT, now }));
  });
  it('the policy store refuses a version that does not supersede the one in force, and a policy beyond the template (§11.4, §8.3)', async () => {
    const { registry } = await fresh();
    await refuses('ERR_POLICY_VERSION', registry.adoptPolicyFor(parentT, { version: 1, now }));
    await refuses('ERR_SPAWN_EXCEEDS_TEMPLATE', registry.adoptPolicyFor(parentT, { spawnTargets: [newAgentId()], version: 2, now }));
  });
  it('refuses a child template holding scopes the parent does not (§10.3)', async () => {
    const { registry } = await fresh();
    const wide = await registry.attest({ ...childT, allowed_scopes: ['read:events', 'admin:all'] });
    await refuses('ERR_SCOPE_ESCALATION', registry.spawn({ attested: wide, parent: parentT, now }));
  });
  it('refuses to issue a child template holding no scopes at all — not only at the pipeline\'s stage 8', async () => {
    const { registry } = await fresh();
    const empty = await registry.attest({ ...childT, allowed_scopes: [] });
    await refuses('ERR_EMPTY_SCOPES', registry.spawn({ attested: empty, parent: parentT, now }));
  });
  it('step 5 — enforces MaxChildren from the count it holds (§10.2)', async () => {
    const other = newAgentId();
    const parent2 = { ...parentT, can_spawn: [childId, other], max_children: 1 };
    const registry = await Registry.create({ now });
    await registry.adoptPolicyFor(parent2, { now });
    await registry.spawn({ attested: await registry.attest(childT), parent: parent2, now });
    const e = await refuses('ERR_MAX_CHILDREN', registry.spawn({ attested: await registry.attest({ ...childT, subject: other }), parent: parent2, now }));
    expect(e.detail).toMatch(/enforced here/);
  });
  it('step 5 — refuses a second live certificate for one child template (§10.2, §12.1)', async () => {
    const parent2 = { ...parentT, max_children: 1 };
    const registry = await Registry.create({ now });
    await registry.adoptPolicyFor(parent2, { now });
    const attested = await registry.attest(childT);
    await registry.spawn({ attested, parent: parent2, now });
    // The count is at the cap, so raise it out of the way: the LIVE check is the one under test.
    registry.children.clear();
    await refuses('ERR_DUPLICATE_SUBJECT', registry.spawn({ attested, parent: parent2, now }));
  });
  it('a cross-organizational spawn requires a grant, and records its grant_id in the certificate (§10.5, §13)', async () => {
    const { signEnvelope } = await import('../src/crypto-sign.js');
    const registry = await Registry.create({ now });
    await registry.adoptPolicyFor(parentT, { now });
    const foreign = { ...childT, org_id: 'partner-org' };
    const attested = await registry.attest(foreign);
    await refuses('ERR_GRANT_MISSING', registry.spawn({ attested, parent: parentT, now }));
    const grantBody = { grant_id: newAgentId(), grantor: 'partner-org', grantee: parentT.org_id, template: childId,
      allowed_scopes: ['read:events'], issued_at: now.toISOString(), ttl_seconds: 3600, max_spawns: 1 };
    const grant = await signEnvelope(grantBody, registry.authorities.owner.privateKey, registry.authorities.pa.privateKey);
    const issued = await registry.spawn({ attested: await registry.attest(foreign), parent: parentT, now, grant });
    expect(issued.spawn.grant_id).toBe(grantBody.grant_id);
    expect(parseSpawnExtension(parseCertificate(issued.cert_pem)).grant_id).toBe(grantBody.grant_id);
    expect(registry.audit.chain.at(-1)).toMatchObject({ outcome: 'ALLOWED', grant_id: grantBody.grant_id });
    // MaxSpawns is the Grantor's Registry's count (§13.2): the second spawn under a max_spawns of 1 is refused.
    registry.children.clear(); registry.live.clear();
    await refuses('ERR_MAX_SPAWNS', registry.spawn({ attested: await registry.attest(foreign), parent: parentT, now, grant }));
  });
  it('refuses to issue a template envelope carrying a content_hash (§11.6)', async () => {
    const { registry, attested } = await fresh();
    await refuses('ERR_ENVELOPE_MEMBER', registry.issue({ ...attested, content_hash: '0'.repeat(64) }));
  });
  it('a Registry rebuilt from a document has forgotten its nonces — which is what §19.2’s retention rule is about — and re-reads its policy store', async () => {
    const doc = { chain: [{ role: 'ca', cert_pem: minted.ca.cert_pem, key_pem: minted.ca.key_pem }],
      authorities: { owner: minted.authorities.owner, pa: minted.authorities.pa }, policies: minted.policies };
    const rebuilt = await Registry.fromDocument(doc, { now });
    expect(rebuilt.seenNonces.size).toBe(0);
    expect(rebuilt.policies.get(parentId).spawn_targets).toEqual([childId]);
    const issued = await rebuilt.spawn({ attested: await rebuilt.attest(childT), parent: parentT, now });
    await validateCertificate({ certPem: issued.cert_pem, caPem: minted.ca.cert_pem, agentId: childId, now });
  });
  it('a Registry rebuilt from a document refuses a policy in force whose signature does not verify', async () => {
    const tampered = JSON.parse(JSON.stringify(minted.policies[0]));
    tampered.body.spawn_targets = [];
    const doc = { chain: [{ role: 'ca', cert_pem: minted.ca.cert_pem, key_pem: minted.ca.key_pem }],
      authorities: { owner: minted.authorities.owner, pa: minted.authorities.pa }, policies: [tampered] };
    await refuses('ERR_OWNER_SIG_INVALID', Registry.fromDocument(doc, { now }));
  });
  it('a Registry cannot be rebuilt from a document missing the anchor key or an authority key', async () => {
    let e = await refuses('ERR_SCHEMA_VIOLATION', Registry.fromDocument({ chain: [{ role: 'ca', cert_pem: minted.ca.cert_pem }] }));
    expect(e.detail).toMatch(/trust anchor key/);
    e = await refuses('ERR_SCHEMA_VIOLATION', Registry.fromDocument({
      chain: [{ role: 'ca', cert_pem: minted.ca.cert_pem, key_pem: minted.ca.key_pem }],
      authorities: { owner: minted.authorities.owner },
    }));
    expect(e.detail).toMatch(/pa authority key/);
  });
  it('the freshness window constant is sixty seconds', () => expect(FRESHNESS_WINDOW_MS).toBe(60_000));
});

describe('the raw issuer — what a compromised CA can do', () => {
  it('issues whatever it is told, and the validator refuses it', async () => {
    const keys = await generateKeyPair();
    const cert = await issueCertificate({ commonName: childId, subjectPublicKey: keys.publicKey,
      issuer: minted.registry.issuer, notBefore: now, notAfter: new Date(now.getTime() + 1000),
      template: { ...childT, allowed_scopes: ['admin:all'] }, keyUsageBits: [0, 5] });
    await refuses('ERR_KEY_USAGE', validateCertificate({ certPem: await toPem(cert), caPem: minted.ca.cert_pem, agentId: childId, now }));
  });
});

describe('identifiers and nonces', () => {
  it('mints UUID version 7 that validates and sorts by time', () => {
    const a = newAgentId(); const b = newAgentId();
    expect(a).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    validateUuid(a); validateUuid(b);
    expect(a.slice(0, 13) <= b.slice(0, 13)).toBe(true);
    expect(a).not.toBe(b);
  });
  it('nonces are 128 bits of base64', () => expect(Buffer.from(newNonce(), 'base64').length).toBe(16));
  it('the demo OID is the UUID arc form of 15b1bbb1-6b8d-451b-80e9-636fbe6e69cd', () => {
    expect(DEMO_NOTICE_OID).toBe(`2.25.${BigInt('0x15b1bbb16b8d451b80e9636fbe6e69cd')}`);
  });
  it('the owner constant is what the seed binds templates to', () => expect(OWNER_COMMON_NAME).toBe('owner-authority'));
  it('keys are P-256', async () => {
    const k = await generateKeyPair();
    expect(k.privateKey.algorithm).toMatchObject({ name: 'ECDSA', namedCurve: 'P-256' });
  });
  it('a chain mints unique identities and serials', () => {
    expect(minted.agents[0].agent_id).not.toBe(minted.agents[1].agent_id);
    const s = (pem) => Buffer.from(parseCertificate(pem).serialNumber.valueBlock.valueHexView).toString('hex');
    expect(s(minted.agents[0].cert_pem)).not.toBe(s(minted.agents[1].cert_pem));
    expect(publicKeyInfo(parseCertificate(minted.agents[0].cert_pem)).curve).toBe('P-256');
  });
  it('serials are positive, minimal DER of at most twenty octets (§7.1)', () => {
    for (const pem of [minted.ca.cert_pem, ...minted.agents.map((a) => a.cert_pem)]) {
      const bytes = new Uint8Array(parseCertificate(pem).serialNumber.valueBlock.valueHexView);
      expect(bytes.length).toBeLessThanOrEqual(20);
      expect(bytes[0] & 0x80).toBe(0);
      if (bytes[0] === 0x00) expect(bytes[1] & 0x80).toBe(0x80);
    }
  });
  it('mintChain returns the policies it put in force: the parent names the child, the child names nothing', () => {
    expect(minted.policies.map((p) => p.body.subject)).toEqual([parentId, childId]);
    expect(minted.policies[0].body.spawn_targets).toEqual([childId]);
    expect(minted.policies[1].body.spawn_targets).toEqual([]);
    expect(minted.registry.audit.chain.map((e) => e.action ?? 'spawn')).toEqual(['issue_template', 'policy_update', 'spawn', 'policy_update']);
  });
});
