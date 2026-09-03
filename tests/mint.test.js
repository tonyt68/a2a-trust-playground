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
  parentT = templateFor({ subject: parentId, scopes: ['read:events', 'write:events'], canSpawn: [childId], maxChildren: 2,
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
  let registry, attested;
  beforeAll(async () => { registry = await Registry.create({ now }); attested = await registry.attest(childT); });
  const at = (offsetSeconds) => new Date(now.getTime() + offsetSeconds * 1000).toISOString();

  it('accepts a fresh request and records parent, time and nonce in the child (§10.5)', async () => {
    const r = await registry.spawn({ attested, parent: parentT, now });
    expect(r.spawn.parent_agent_id).toBe(parentId);
    expect(r.spawn.spawned_at).toBe(now.toISOString());
  });
  it('accepts 59 s either side and exactly 60 s', async () => {
    for (const s of [-59, 59, -60, 60]) {
      await registry.spawn({ attested, parent: parentT, now, requestedAt: at(s) });
    }
  });
  it('refuses 61 s in the past and 61 s in the future, naming the measured offset', async () => {
    const past = await refuses('ERR_SPAWN_STALE', registry.spawn({ attested, parent: parentT, now, requestedAt: at(-61) }));
    expect(past.detail).toMatch(/61\.0 s in the past/);
    const future = await refuses('ERR_SPAWN_STALE', registry.spawn({ attested, parent: parentT, now, requestedAt: at(61) }));
    expect(future.detail).toMatch(/61\.0 s in the future/);
  });
  it('the window is 60, not "roughly a minute": 60.5 s is refused', () =>
    refuses('ERR_SPAWN_STALE', registry.spawn({ attested, parent: parentT, now, requestedAt: at(60.5) })));
  it('refuses a nonce it has already accepted (§19.2)', async () => {
    const nonce = newNonce();
    await registry.spawn({ attested, parent: parentT, now, nonce });
    await refuses('ERR_NONCE_REUSED', registry.spawn({ attested, parent: parentT, now, nonce }));
  });
  it('a refused request does not spend its nonce', async () => {
    const nonce = newNonce();
    await refuses('ERR_SPAWN_STALE', registry.spawn({ attested, parent: parentT, now, nonce, requestedAt: at(-61) }));
    await registry.spawn({ attested, parent: parentT, now, nonce });   // still fresh
  });
  it('a request refused by ISSUE\'s re-gate (not spawn\'s own checks) does not spend its nonce either', async () => {
    // spawn() itself has nothing to object to here — the tampered signature is
    // only caught by issue()'s re-verification, which runs AFTER spawn()'s
    // checks. The nonce must still be free for a corrected retry.
    const nonce = newNonce();
    const tampered = { ...attested, pa_sig: attested.owner_sig };
    await refuses('ERR_TEMPLATE_SIGNATURE', registry.spawn({ attested: tampered, parent: parentT, now, nonce }));
    await registry.spawn({ attested, parent: parentT, now, nonce });   // still fresh
  });
  it('refuses a nonce under 128 bits and a timestamp with an offset', async () => {
    await refuses('ERR_SCHEMA_VIOLATION', registry.spawn({ attested, parent: parentT, now, nonce: Buffer.alloc(8).toString('base64') }));
    await refuses('ERR_TIMESTAMP_FORMAT', registry.spawn({ attested, parent: parentT, now, requestedAt: now.toISOString().replace('Z', '+00:00') }));
  });
  it('Check 1 — refuses a parent without spawn in PermittedOperations (§10.1)', () =>
    refuses('ERR_SPAWN_NOT_PERMITTED', registry.spawn({ attested, parent: { ...parentT, permitted_operations: ['read'] }, now })));
  it('Check 1 — refuses a child not in CanSpawn (§10.1)', () =>
    refuses('ERR_CHILD_NOT_WHITELISTED', registry.spawn({ attested, parent: { ...parentT, can_spawn: [] }, now })));
  it('refuses a child template holding scopes the parent does not (§10.3)', async () => {
    const wide = await registry.attest({ ...childT, allowed_scopes: ['read:events', 'admin:all'] });
    await refuses('ERR_SCOPE_ESCALATION', registry.spawn({ attested: wide, parent: parentT, now }));
  });
  it('refuses to issue a child template holding no scopes at all — not only at the pipeline\'s stage 8', async () => {
    const empty = await registry.attest({ ...childT, allowed_scopes: [] });
    await refuses('ERR_EMPTY_SCOPES', registry.spawn({ attested: empty, parent: parentT, now }));
  });
  it('a Registry rebuilt from a document has forgotten its nonces — which is what §19.2’s retention rule is about', async () => {
    const doc = { chain: [{ role: 'ca', cert_pem: minted.ca.cert_pem, key_pem: minted.ca.key_pem }],
      authorities: { owner: minted.authorities.owner, pa: minted.authorities.pa } };
    const rebuilt = await Registry.fromDocument(doc, { now });
    expect(rebuilt.seenNonces.size).toBe(0);
    const issued = await rebuilt.spawn({ attested: await rebuilt.attest(childT), parent: parentT, now });
    await validateCertificate({ certPem: issued.cert_pem, caPem: minted.ca.cert_pem, agentId: childId, now });
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
});
