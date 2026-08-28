/**
 * Stages 4-6 — dual signature (§9.3), field guard, required fields.
 *
 * Acceptance criteria 6 and 7:
 *   AC-6  can_spawn and max_children cannot be altered by a policy update
 *   AC-7  a single signature is always insufficient; both must verify
 *
 * Signatures here are made with the real fixture keys and verified through the
 * same path the page uses, so a canonicalisation drift would fail these rather
 * than surfacing later as a mysterious crypto error.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { DenyError } from '../src/errors.js';
import { extractIdentityFields, extractPolicyFields, canonicalize } from '../src/canonical.js';
import { privateKeyFromPem, signCanonical } from '../src/crypto-sign.js';
import {
  IMMUTABLE_CERT_FIELDS, MODIFIABLE_POLICY_FIELDS, REQUIRED_POLICY_FIELDS, assertFieldGuard, assertOwnership, assertPolicyIntegrity, assertRequiredFields, assertWithinTemplateBounds, isPolicyUpdate, policyContentHash, validatePolicyUpdate,
} from '../src/policy.js';

const dir = fileURLToPath(new URL('./fixtures/certs/', import.meta.url));
const read = (f) => readFileSync(dir + f, 'utf8');

const AGENT_B = 'c669186f-a84b-4d7a-81f3-05880df87114';
const AGENT_A = '8f14e45f-ceea-467a-9c0f-7ad0f1b0d5aa';

/** Mirrors the reference implementation's agent-b metadata shape. */
const EXISTING_CERT = Object.freeze({
  subject: AGENT_B, agent_id: AGENT_B, agent_uuid: AGENT_B,
  issuer: 'A2A-Trust-Playground-CA', owner: 'owner@example.com', org_id: 'tonyai-org',
  permitted_operations: ['write', 'spawn', 'delegate'], allowed_scopes: ['write:events'],
  can_spawn: [AGENT_A], max_children: 5,
  policy_ref: 'policy-store/agent-b/current', ttl_seconds: 86400,
  template_version: '1.0', state: 'ACTIVE',
});

/**
 * A complete dynamic policy document, per `-02` §9.4.
 *
 * Previously copied from the reference implementation's
 * tests/test_policy_signatures.py, which was the only available definition while
 * `-01` left the structure unspecified. §9.4 now defines it, so the fixture is
 * built from the draft's field table instead of from another codebase's tests.
 */
const VALID_POLICY_DOC = Object.freeze({
  subject: AGENT_B,
  owner: 'owner@example.com',
  org_id: 'tonyai-org',
  scopes: ['write:events'],
  version: 2,
  issued_at: '2026-06-06T20:00:00Z',
});

let ownerCert, paCert, ownerKey, paKey;
beforeAll(async () => {
  if (!existsSync(dir + 'owner.crt')) throw new Error('run `pnpm fixtures`');
  ownerCert = read('owner.crt');
  paCert = read('pa.crt');
  ownerKey = await privateKeyFromPem(read('owner.key'));
  paKey = await privateKeyFromPem(read('pa.key'));
});

/** Build a correctly dual-signed update. Overrides let each test break one thing. */
async function signedUpdate(overrides = {}) {
  const policyDoc = { ...VALID_POLICY_DOC, ...(overrides.policyDoc ?? {}) };
  const existing = { ...EXISTING_CERT, ...(overrides.existingCert ?? {}) };
  const doc = {
    policy_update: true,
    policy_doc: policyDoc,
    existing_cert: existing,
    owner_sig: await signCanonical(canonicalize(extractIdentityFields(existing)), ownerKey),
    pa_sig: await signCanonical(canonicalize(extractPolicyFields(policyDoc)), paKey),
  };
  return { ...doc, ...(overrides.doc ?? {}) };
}

const run = (document) => validatePolicyUpdate({ document, ownerCertPem: ownerCert, paCertPem: paCert });

async function denies(code, fn) {
  let thrown;
  try { await fn(); } catch (e) { thrown = e; }
  expect(thrown, 'expected a DenyError, nothing was thrown').toBeDefined();
  expect(thrown, `threw ${thrown?.constructor?.name}: ${thrown?.message}`).toBeInstanceOf(DenyError);
  expect(thrown.code).toBe(code);
}

describe('field sets match policy_field_guard.py', () => {
  it('can_spawn and max_children are immutable identity (AC-6)', () => {
    for (const f of ['can_spawn', 'max_children']) {
      expect(IMMUTABLE_CERT_FIELDS.has(f)).toBe(true);
      expect(MODIFIABLE_POLICY_FIELDS.has(f)).toBe(false);
    }
  });
  it('requires the §9.4 REQUIRED fields', () => {
    expect([...REQUIRED_POLICY_FIELDS].sort()).toEqual(
      ['issued_at', 'org_id', 'owner', 'scopes', 'subject', 'version']);
  });
});

describe('not a policy update — passes through', () => {
  it('a plain chain document is not applicable', async () => {
    const r = await run({ chain: [] });
    expect(r.applicable).toBe(false);
    expect(r.detail).toBe('not a policy update');
  });
  it('isPolicyUpdate keys off the policy_update field', () => {
    expect(isPolicyUpdate({ policy_update: true })).toBe(true);
    expect(isPolicyUpdate({ policy_update: false })).toBe(true); // presence, not truthiness
    expect(isPolicyUpdate({})).toBe(false);
    expect(isPolicyUpdate(null)).toBe(false);
  });
});

describe('the happy path — both phases verify', () => {
  it('accepts a correctly dual-signed update', async () => {
    const r = await run(await signedUpdate());
    expect(r.applicable).toBe(true);
    expect(r.detail).toContain('Phase 1');
    expect(r.detail).toContain('Phase 2');
  });

  it('reports exactly which fields each signature covered', async () => {
    const { signed } = await run(await signedUpdate());
    // Phase 1 covers identity; note can_spawn and max_children are in it.
    expect(signed.identity_fields).toContain('can_spawn');
    expect(signed.identity_fields).toContain('max_children');
    expect(signed.identity_fields).toContain('agent_uuid');
    // Phase 2 covers policy only — and must NOT contain the identity fields.
    expect(signed.policy_fields).toContain('scopes');
    expect(signed.policy_fields).not.toContain('can_spawn');
    expect(signed.policy_fields).not.toContain('agent_uuid');
    // `owner` is the one field in both sets, matching the reference.
    expect(signed.identity_fields).toContain('owner');
    expect(signed.policy_fields).toContain('owner');
  });

  it('signs the canonical form, not the raw document', async () => {
    const { signed } = await run(await signedUpdate());
    expect(signed.policy_canonical).not.toContain(', ');   // compact separators
    expect(signed.policy_canonical.startsWith('{"issued_at":')).toBe(true);
  });
});

describe('AC-7 — one signature is never enough', () => {
  it('refuses when both signatures are absent', async () => {
    const doc = await signedUpdate({ doc: { owner_sig: null, pa_sig: null } });
    await denies('ERR_SINGLE_SIGNATURE', () => run(doc));
  });

  it('refuses with owner_sig only', async () => {
    const doc = await signedUpdate({ doc: { pa_sig: null } });
    await denies('ERR_PA_SIG_MISSING', () => run(doc));
  });

  it('refuses with pa_sig only', async () => {
    const doc = await signedUpdate({ doc: { owner_sig: null } });
    await denies('ERR_OWNER_SIG_MISSING', () => run(doc));
  });

  it('refuses when one key signs both roles', async () => {
    // The A20 red-team case: same key used for owner and PA.
    const policyDoc = { ...VALID_POLICY_DOC };
    const sig = await signCanonical(canonicalize(extractPolicyFields(policyDoc)), paKey);
    await denies('ERR_OWNER_SIG_INVALID', () => run({
      policy_update: true, policy_doc: policyDoc, existing_cert: EXISTING_CERT,
      owner_sig: sig, pa_sig: sig,
    }));
  });

  it('refuses a tampered PA signature (A18)', async () => {
    const doc = await signedUpdate();
    const flipped = Buffer.from(doc.pa_sig, 'base64');
    flipped[0] ^= 0xff;
    doc.pa_sig = flipped.toString('base64');
    await denies('ERR_PA_SIG_INVALID', () => run(doc));
  });

  it('refuses a tampered owner signature', async () => {
    const doc = await signedUpdate();
    const flipped = Buffer.from(doc.owner_sig, 'base64');
    flipped[0] ^= 0xff;
    doc.owner_sig = flipped.toString('base64');
    await denies('ERR_OWNER_SIG_INVALID', () => run(doc));
  });

  it('refuses a signature that is not base64', async () => {
    const doc = await signedUpdate({ doc: { pa_sig: 'not base64!' } });
    await denies('ERR_PA_SIG_INVALID', () => run(doc));
  });

  it('refuses when the policy document is altered after signing', async () => {
    // Altered inside the §7.2 ceiling, so the signature is what refuses it.
    const doc = await signedUpdate();
    doc.policy_doc.issued_at = '2030-01-01T00:00:00Z';  // altered after the PA signed
    await denies('ERR_PA_SIG_INVALID', () => run(doc));
  });

  it('refuses when the existing certificate identity is altered after signing', async () => {
    const doc = await signedUpdate();
    doc.existing_cert.agent_uuid = AGENT_A;          // swap identity under the owner sig
    await denies('ERR_OWNER_SIG_INVALID', () => run(doc));
  });

  it('refuses when existing_cert is absent — Phase 1 has nothing to verify', async () => {
    const doc = await signedUpdate({ doc: { existing_cert: null } });
    await denies('ERR_OWNER_SIG_INVALID', () => run(doc));
  });
});

describe('AC-6 — the field guard makes the split real', () => {
  for (const field of ['can_spawn', 'max_children', 'agent_id', 'agent_uuid', 'allowed_scopes', 'cert_serial']) {
    it(`refuses a policy update touching ${field}`, async () => {
      const doc = await signedUpdate({ policyDoc: { [field]: field === 'max_children' ? 999 : ['x'] } });
      await denies('ERR_IMMUTABLE_FIELD', () => run(doc));
    });
  }

  it('names every offending field, sorted', async () => {
    let thrown;
    try {
      await run(await signedUpdate({ policyDoc: { max_children: 99, can_spawn: [] } }));
    } catch (e) { thrown = e; }
    expect(thrown.detail).toContain('can_spawn');
    expect(thrown.detail).toContain('max_children');
    expect(thrown.detail).toContain('new certificate');
  });

  it('refuses unknown fields rather than ignoring them', async () => {
    const doc = await signedUpdate({ policyDoc: { surprise: 'value' } });
    await denies('ERR_UNKNOWN_POLICY_FIELD', () => run(doc));
  });

  it('runs the field guard BEFORE signature verification, as the reference does', async () => {
    // Both broken: the field guard must be what is reported.
    const doc = await signedUpdate({ policyDoc: { can_spawn: ['x'] } });
    doc.pa_sig = 'AAAA';
    await denies('ERR_IMMUTABLE_FIELD', () => run(doc));
  });

  it('accepts every modifiable field on its own', () => {
    for (const f of MODIFIABLE_POLICY_FIELDS) {
      expect(() => assertFieldGuard({ [f]: 'x' }), f).not.toThrow();
    }
  });

  it('rejects a non-object policy_doc', () => {
    for (const bad of [null, 'x', 42, ['a']]) {
      expect(() => assertFieldGuard(bad)).toThrow(DenyError);
    }
  });
});

describe('stage 6 — required fields', () => {
  for (const field of REQUIRED_POLICY_FIELDS) {
    it(`refuses an update missing ${field}`, async () => {
      const policyDoc = { ...VALID_POLICY_DOC };
      delete policyDoc[field];
      const doc = {
        policy_update: true, policy_doc: policyDoc, existing_cert: EXISTING_CERT,
        owner_sig: await signCanonical(canonicalize(extractIdentityFields(EXISTING_CERT)), ownerKey),
        pa_sig: await signCanonical(canonicalize(extractPolicyFields(policyDoc)), paKey),
      };
      await denies('ERR_REQUIRED_FIELD', () => run(doc));
    });
  }

  it('names what is missing', () => {
    let thrown;
    try { assertRequiredFields({ owner: 'o' }); } catch (e) { thrown = e; }
    expect(thrown.detail).toContain('issued_at');
  });

  it('runs after the field guard', async () => {
    // Missing required field AND an illegal field: field guard wins.
    const doc = await signedUpdate({ policyDoc: { can_spawn: [] } });
    delete doc.policy_doc.owner;
    await denies('ERR_IMMUTABLE_FIELD', () => run(doc));
  });
});

/**
 * §7.2 Dynamic Policy Bounds, §9.2 Ownership, §9.4 Policy Change Sequence —
 * verified against the draft-tonyai-a2a-trust-01 text, not against the PoC.
 *
 * The two-lane model (§9.1): the template certificate is the guardrail and the
 * dynamic policy chooses how and which WITHIN it. A dual signature authorises a
 * change; it does not raise the ceiling. Raising the ceiling means a new
 * certificate — a different signer and a different audit trail.
 */
describe('§7.2 — dynamic policy is bounded by the static template', () => {
  const ceiling = ['read:events', 'write:events'];
  const template = { ...EXISTING_CERT, allowed_scopes: ceiling, can_spawn: [AGENT_A] };

  async function update(policyOverrides) {
    const policyDoc = {
      subject: AGENT_B, owner: 'owner@example.com', org_id: 'tonyai-org',
      version: 2, issued_at: '2026-06-06T20:00:00Z', ...policyOverrides,
    };
    return {
      policy_update: true, policy_doc: policyDoc, existing_cert: template,
      owner_sig: await signCanonical(canonicalize(extractIdentityFields(template)), ownerKey),
      pa_sig: await signCanonical(canonicalize(extractPolicyFields(policyDoc)), paKey),
    };
  }

  it('permits narrowing within the ceiling', async () => {
    const r = await run(await update({ scopes: ['read:events'] }));
    expect(r.applicable).toBe(true);
  });

  it('permits exactly the ceiling', async () => {
    expect((await run(await update({ scopes: ceiling }))).applicable).toBe(true);
  });

  it('permits an empty grant — a policy may remove authority', async () => {
    expect((await run(await update({ scopes: [] }))).applicable).toBe(true);
  });

  it('REFUSES a grant beyond AllowedScopes, despite two valid signatures', async () => {
    let thrown;
    try { await run(await update({ scopes: ['admin:all'] })); } catch (e) { thrown = e; }
    expect(thrown.code).toBe('ERR_POLICY_EXCEEDS_TEMPLATE');
    expect(thrown.section).toBe('7.2');
    expect(thrown.detail).toContain('admin:all');
    expect(thrown.detail).toContain('beyond template AllowedScopes');
  });

  it('REFUSES a partial overreach — one scope past the ceiling taints the update', async () => {
    await denies('ERR_POLICY_EXCEEDS_TEMPLATE', async () =>
      run(await update({ scopes: ['read:events', 'admin:all'] })));
  });

  it('refuses when the template declares no AllowedScopes to bound against', async () => {
    const bare = { ...template };
    delete bare.allowed_scopes;
    const policyDoc = { subject: AGENT_B, owner: 'owner@example.com', org_id: 'tonyai-org',
      scopes: ['read:events'], version: 2, issued_at: '2026-06-06T20:00:00Z' };
    // Real signatures, so the run reaches the bounds check rather than stopping
    // at stage 4.
    const doc = {
      policy_update: true, policy_doc: policyDoc, existing_cert: bare,
      owner_sig: await signCanonical(canonicalize(extractIdentityFields(bare)), ownerKey),
      pa_sig: await signCanonical(canonicalize(extractPolicyFields(policyDoc)), paKey),
    };
    await denies('ERR_POLICY_EXCEEDS_TEMPLATE', () => run(doc));
  });

  it('checks the ceiling AFTER the signatures, per §9.4 step 5', async () => {
    // §9.4 step 5 lists the runtime order: "both signatures, version currency,
    // hash integrity, and template bounds compliance". A document that is both
    // unsigned AND over-broad reports the signature failure, because
    // authenticity is established first.
    const doc = await update({ scopes: ['admin:all'] });
    doc.pa_sig = 'AAAA';
    await denies('ERR_PA_SIG_INVALID', () => run(doc));
  });

  it('refuses a CORRECTLY SIGNED update that exceeds the ceiling', async () => {
    // The §7.2 case that matters: every signature verifies, and it is still
    // refused. Two valid signatures do not raise the ceiling.
    const doc = await update({ scopes: ['admin:all'] });
    await denies('ERR_POLICY_EXCEEDS_TEMPLATE', () => run(doc));
  });

  it('assertWithinTemplateBounds refuses spawn targets beyond CanSpawn', () => {
    // Unreachable through the field guard, which refuses can_spawn outright.
    // Kept as defence in depth if that guard is ever relaxed to allow narrowing.
    let thrown;
    try {
      assertWithinTemplateBounds({ spawn_targets: [AGENT_B] }, { allowed_scopes: [], can_spawn: [AGENT_A] });
    } catch (e) { thrown = e; }
    expect(thrown.code).toBe('ERR_SPAWN_EXCEEDS_TEMPLATE');
    expect(thrown.section).toBe('7.2');
  });

  it('permits a policy naming a subset of CanSpawn', () => {
    expect(() => assertWithinTemplateBounds(
      { spawn_targets: [AGENT_A] }, { allowed_scopes: [], can_spawn: [AGENT_A, AGENT_B] })).not.toThrow();
  });
});

describe('§9.2 — only the template owner may submit a policy change', () => {
  async function update(policyOverrides, templateOverrides = {}) {
    const template = { ...EXISTING_CERT, ...templateOverrides };
    const policyDoc = {
      subject: AGENT_B, org_id: 'tonyai-org', scopes: ['write:events'],
      version: 2, owner: 'owner@example.com',
      issued_at: '2026-06-06T20:00:00Z', ...policyOverrides,
    };
    return {
      policy_update: true, policy_doc: policyDoc, existing_cert: template,
      owner_sig: await signCanonical(canonicalize(extractIdentityFields(template)), ownerKey),
      pa_sig: await signCanonical(canonicalize(extractPolicyFields(policyDoc)), paKey),
    };
  }

  it('accepts the template owner', async () => {
    expect((await run(await update({}))).applicable).toBe(true);
  });

  it('REFUSES a different owner, even with two valid signatures', async () => {
    // A valid Owner Authority signature proves a key was used. It does not prove
    // that key speaks for THIS template's owner.
    let thrown;
    try { await run(await update({ owner: 'attacker@example.com' })); } catch (e) { thrown = e; }
    expect(thrown.code).toBe('ERR_OWNER_MISMATCH');
    expect(thrown.section).toBe('9.2');
  });

  /**
   * The key must be DELETED, not set to undefined: canonicalize refuses to
   * serialise undefined (Python's json.dumps has no equivalent), so an override
   * of `{owner: undefined}` throws while building the fixture rather than
   * reaching the validator. That refusal is correct — it just is not this test.
   */
  async function updateWithout(field) {
    const template = { ...EXISTING_CERT };
    delete template[field];
    const policyDoc = {
      subject: AGENT_B, org_id: 'tonyai-org', scopes: ['write:events'],
      version: 2, owner: 'owner@example.com',
      issued_at: '2026-06-06T20:00:00Z',
    };
    return {
      policy_update: true, policy_doc: policyDoc, existing_cert: template,
      owner_sig: await signCanonical(canonicalize(extractIdentityFields(template)), ownerKey),
      pa_sig: await signCanonical(canonicalize(extractPolicyFields(policyDoc)), paKey),
    };
  }

  it('refuses when the template establishes no Owner', async () => {
    const doc = await updateWithout('owner');
    await denies('ERR_OWNER_MISMATCH', () => run(doc));
  });

  it('refuses when the template establishes no OrgID', async () => {
    const doc = await updateWithout('org_id');
    await denies('ERR_ORG_MISMATCH', () => run(doc));
  });
});

describe('§9.4 — version currency and content-hash integrity', () => {
  /**
   * The envelope travels on the DOCUMENT, not inside policy_doc. §9.4 describes
   * "storage with dual signature, version, timestamp, and content hash" — those
   * are properties of the stored record. Putting them in policy_doc made the
   * reference implementation reject the whole update as containing unknown
   * fields, which the round-trip harness caught.
   */
  async function update(policyOverrides, docOverrides = {}) {
    const policyDoc = {
      subject: AGENT_B, org_id: 'tonyai-org', scopes: ['write:events'],
      version: 2, owner: 'owner@example.com',
      issued_at: '2026-06-06T20:00:00Z', ...policyOverrides,
    };
    return {
      policy_update: true, policy_doc: policyDoc, existing_cert: EXISTING_CERT,
      owner_sig: await signCanonical(canonicalize(extractIdentityFields(EXISTING_CERT)), ownerKey),
      pa_sig: await signCanonical(canonicalize(extractPolicyFields(policyDoc)), paKey),
      ...docOverrides,
    };
  }

  it('accepts a correct content hash', async () => {
    const policyDoc = { subject: AGENT_B, org_id: 'tonyai-org', scopes: ['write:events'],
      version: 2, owner: 'owner@example.com', issued_at: '2026-06-06T20:00:00Z' };
    const hash = await policyContentHash(policyDoc);
    const doc = await update({}, { policy_content_hash: hash, policy_version: 2 });
    expect((await run(doc)).applicable).toBe(true);
  });

  it('REFUSES a content hash that does not match the document', async () => {
    const doc = await update({}, { policy_content_hash: 'a'.repeat(64) });
    await denies('ERR_CONTENT_HASH', () => run(doc));
  });

  it('REFUSES replaying an older version over a newer stored one', async () => {
    // Both signatures still verify on a replayed policy — the version is what
    // distinguishes "apply this change" from "roll authority backwards".
    const doc = await update({}, { policy_version: 2, current_policy_version: 5 });
    await denies('ERR_POLICY_VERSION', () => run(doc));
  });

  it('accepts a version that supersedes the stored one', async () => {
    const doc = await update({ version: 6 }, { current_policy_version: 5 });
    expect((await run(doc)).applicable).toBe(true);
  });

  it('refuses a non-positive or non-integer version', async () => {
    // Asserted directly against assertPolicyIntegrity rather than through a full
    // run, because a full run can no longer REACH this check with a bad version:
    // §9.4 step 5 verifies signatures first, and under -02 the version is inside
    // the signed preimage, so any tampered version fails as a signature error
    // before the format rule is consulted.
    //
    // That ordering is the security property working, so the test follows the
    // rule to where it still applies instead of asserting the old sequence.
    for (const v of [0, -1, 1.5, '2', null, [], undefined]) {
      await expect(assertPolicyIntegrity({ ...VALID_POLICY_DOC, version: v }))
        .rejects.toMatchObject({ code: 'ERR_POLICY_VERSION' });
    }
  });

  it('refuses a version that does not supersede the stored one', async () => {
    for (const [version, current] of [[1, 1], [1, 5], [5, 5]]) {
      await expect(assertPolicyIntegrity(
        { ...VALID_POLICY_DOC, version }, { currentVersion: current },
      )).rejects.toMatchObject({ code: 'ERR_POLICY_VERSION' });
    }
    await expect(assertPolicyIntegrity(
      { ...VALID_POLICY_DOC, version: 6 }, { currentVersion: 5 },
    )).resolves.toBeUndefined();
  });

  it('a non-integer version cannot be signed in the first place', async () => {
    const { CanonicalError } = await import('../src/canonical.js');
    await expect(update({ version: 1.5 })).rejects.toThrow(CanonicalError);
  });

  it('version lives INSIDE policy_doc, and is therefore signed (§9.6)', async () => {
    // The inverse of what this test asserted under -01, and the change is the
    // whole security fix. -01's field guard refused `version` inside the policy
    // document, which put it on the envelope, outside the signed preimage —
    // where an attacker holding no key could rewrite it.
    const doc = await update({ version: 4 }, { current_policy_version: 3 });
    expect(doc.policy_doc.version).toBe(4);
    expect(doc.policy_version).toBeUndefined();
    expect((await run(doc)).applicable).toBe(true);
  });

  it('rewriting the version breaks the signature (§9.6)', async () => {
    // The replay, demonstrated at the unit level. The attacker holds no key.
    const doc = await update({ version: 2 }, { current_policy_version: 5 });
    await denies('ERR_POLICY_VERSION', () => run(doc));   // stale, refused
    doc.policy_doc.version = 6;                            // one integer, no key
    await denies('ERR_PA_SIG_INVALID', () => run(doc));    // -01: this PASSED
  });

  it('the content hash is still refused inside its own preimage', async () => {
    await denies('ERR_UNKNOWN_POLICY_FIELD', async () => run(await update({ content_hash: 'x' })));
  });

  it('the content hash is SHA-256 over the canonical POLICY fields (TV-23/24)', async () => {
    const doc = { subject: AGENT_B, org_id: 'tonyai-org', scopes: ['read:events'],
      version: 2, owner: 'o@example.com', issued_at: '2026-06-06T20:00:00Z' };
    expect(await policyContentHash(doc)).toMatch(/^[0-9a-f]{64}$/);
    // Deterministic, and a changed policy changes the hash.
    expect(await policyContentHash(doc)).toBe(await policyContentHash({ ...doc }));
    expect(await policyContentHash(doc))
      .not.toBe(await policyContentHash({ ...doc, scopes: ['write:events'] }));
  });
});
