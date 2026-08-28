/**
 * AC-13 — `Load Defaults` yields a chain that passes every stage, with no
 * minting step required of the visitor.
 *
 * The stronger claim tested here is that every stage does REAL work. A default
 * that passes stages 4-6 by reporting "not a policy update" would satisfy AC-13
 * while hiding the dual-signature mechanism §9.3 calls the differentiator.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { buildDefaultDocument, PARENT_SCOPES, CHILD_SCOPES } from '../src/defaults.js';
import { runPipeline } from '../src/pipeline.js';
import { policyContentHash } from '../src/policy.js';

let doc;
const NOW = new Date();
beforeAll(async () => { doc = await buildDefaultDocument({ now: NOW }); }, 60_000);

const run = (d) => runPipeline({ document: d, now: NOW });
const clone = () => JSON.parse(JSON.stringify(doc));
const agentNodes = (d) => d.chain.filter((n) => n.role === 'agent');
const child = (d) => agentNodes(d).find((n) => n.metadata.parent_agent_id);
const parent = (d) => agentNodes(d).find((n) => !n.metadata.parent_agent_id);

describe('AC-13 — the default passes every stage', () => {
  it('verdict is PASS', async () => {
    const r = await run(doc);
    expect(r.verdict, `denied: ${r.error_code} — ${r.stages.at(-1)?.detail}`).toBe('PASS');
  });

  it('all nine stages run and pass', async () => {
    const r = await run(doc);
    expect(r.stages.map((s) => s.n)).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9]);
    expect(r.stages.every((s) => s.result === 'PASS')).toBe(true);
  });

  it('stages 4-6 do REAL work, not a pass-through', async () => {
    const r = await run(doc);
    for (const n of [4, 5, 6]) {
      expect(r.stages[n - 1].detail, `stage ${n} is vacuous`).not.toContain('not a policy update');
    }
    expect(r.stages[3].detail).toContain('Phase 1');
    expect(r.stages[3].detail).toContain('Phase 2');
  });
});

describe('the seeded chain is shaped for the demonstration', () => {
  it('is CA -> parent -> child, with UUID4 identities (§6)', () => {
    expect(doc.chain.filter((n) => n.role === 'ca')).toHaveLength(1);
    expect(agentNodes(doc)).toHaveLength(2);
    for (const n of agentNodes(doc)) {
      expect(n.metadata.agent_id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
      expect(n.metadata.agent_id).toBe(n.metadata.agent_uuid);
    }
  });

  it('the child holds a strict subset of the parent scopes (§8.3)', () => {
    expect(parent(doc).metadata.allowed_scopes).toEqual([...PARENT_SCOPES]);
    expect(child(doc).metadata.allowed_scopes).toEqual([...CHILD_SCOPES]);
    expect(CHILD_SCOPES.every((s) => PARENT_SCOPES.includes(s))).toBe(true);
    expect(CHILD_SCOPES.length).toBeLessThan(PARENT_SCOPES.length);
  });

  it('the parent may spawn exactly the child, under a real cap (§8.1, §7)', () => {
    expect(parent(doc).metadata.can_spawn).toEqual([child(doc).metadata.agent_id]);
    expect(parent(doc).metadata.max_children).toBeGreaterThan(0);
  });

  it('duplicates authorization_bounds, and the copies agree', () => {
    for (const n of agentNodes(doc)) {
      expect(n.metadata.authorization_bounds).toEqual({
        allowed_scopes: n.metadata.allowed_scopes,
        can_spawn: n.metadata.can_spawn,
        max_children: n.metadata.max_children,
      });
    }
  });

  it('hands over both authority private keys, so one-key signing can be tried', () => {
    expect(doc.authorities.owner.key_pem).toContain('BEGIN PRIVATE KEY');
    expect(doc.authorities.pa.key_pem).toContain('BEGIN PRIVATE KEY');
    expect(doc.authorities.owner.key_pem).not.toBe(doc.authorities.pa.key_pem);
  });

  it('carries a §9.4 envelope, with the version INSIDE the signed document', async () => {
    // -02 §9.6 moved the version into the policy document so the signature
    // covers it. What stays on the envelope is the store's current version
    // (context) and the content hash, which cannot be in its own preimage.
    expect(doc.policy_doc.version).toBeGreaterThan(doc.current_policy_version);
    expect(doc.policy_version).toBeUndefined();
    expect(doc.policy_content_hash).toBe(await policyContentHash(doc.policy_doc));
    expect(doc.policy_doc.content_hash).toBeUndefined();
  });

  it('issues certificates inside their validity window', async () => {
    const r = await run(doc);
    expect(r.stages[1].result).toBe('PASS');
  });
});

describe('the default is one edit away from each refusal', () => {
  it('widening the policy past the ceiling trips §7.2 — even correctly signed', async () => {
    // The distinction the two lanes exist to make: the POLICY exceeding the
    // template, not a child exceeding its parent. Re-signed and re-hashed, so
    // the run reaches §7.2 rather than stopping at the broken signature —
    // which is the whole point: authentic, and still refused.
    const { privateKeyFromPem, signCanonical } = await import('../src/crypto-sign.js');
    const { extractPolicyFields, canonicalize } = await import('../src/canonical.js');
    const d = clone();
    d.policy_doc.scopes = ['admin:all'];
    d.policy_content_hash = await policyContentHash(d.policy_doc);
    const paKey = await privateKeyFromPem(d.authorities.pa.key_pem);
    d.pa_sig = await signCanonical(canonicalize(extractPolicyFields(d.policy_doc)), paKey);
    const r = await run(d);
    expect(r.error_code).toBe('ERR_POLICY_EXCEEDS_TEMPLATE');
    expect(r.draft_section).toBe('7.2');
  });

  it('widening the CHILD past the parent trips §8.3', async () => {
    const d = clone();
    const c = child(d);
    c.metadata.allowed_scopes = ['admin:all'];
    c.metadata.authorization_bounds.allowed_scopes = ['admin:all'];
    c.requested_scopes = ['admin:all'];
    // The policy update names the old scopes, so clear it to isolate stage 8.
    delete d.policy_update;
    const r = await run(d);
    expect(r.error_code).toBe('ERR_SCOPE_ESCALATION');
    expect(r.draft_section).toBe('8.3');
  });

  it('dropping one signature trips §9.3', async () => {
    const d = clone();
    d.pa_sig = null;
    expect((await run(d)).error_code).toBe('ERR_PA_SIG_MISSING');
  });

  it('editing can_spawn through the policy trips the field guard', async () => {
    const d = clone();
    d.policy_doc.can_spawn = [];
    expect((await run(d)).error_code).toBe('ERR_IMMUTABLE_FIELD');
  });

  it('revoking the parent trips §12', async () => {
    const d = clone();
    d.crl.revoked.push(parent(d).metadata.agent_id);
    expect((await run(d)).error_code).toBe('ERR_AGENT_REVOKED');
  });

  it('disabling the child trips §10.4', async () => {
    const d = clone();
    child(d).metadata.state = 'DISABLED';
    expect((await run(d)).error_code).toBe('ERR_AGENT_DISABLED');
  });
});

describe('the document survives a JSON round trip', () => {
  it('is serialisable and reloads to the same verdict — the editor loop depends on it', async () => {
    const text = JSON.stringify(doc, null, 2);
    expect(text).not.toContain('undefined');
    const reloaded = JSON.parse(text);
    expect((await run(reloaded)).verdict).toBe('PASS');
  });

  it('is a workable size for a textarea', () => {
    const lines = JSON.stringify(doc, null, 2).split('\n').length;
    expect(lines).toBeGreaterThan(80);
    expect(lines).toBeLessThan(400);
  });

  it('every run is a fresh chain — refresh really is the reset', async () => {
    const other = await buildDefaultDocument({ now: NOW });
    expect(other.chain[1].metadata.agent_id).not.toBe(doc.chain[1].metadata.agent_id);
    expect(other.chain[1].cert_pem).not.toBe(doc.chain[1].cert_pem);
  }, 60_000);
});
