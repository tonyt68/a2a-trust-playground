/**
 * The seed document: what the page starts from, and why it is shaped that way.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { buildDefaultDocument, templateFor, PARENT_TTL_SECONDS, CHILD_TTL_SECONDS } from '../src/defaults.js';
import { runPipeline } from '../src/pipeline.js';
import { parseCertificate, subjectCN } from '../src/x509.js';
import { childOf, parentOf, templateOf, spawnOf } from '../src/scenarios.js';
import { validateUuid } from '../src/validate-input.js';

let doc, result;
beforeAll(async () => {
  doc = await buildDefaultDocument();
  result = await runPipeline({ document: JSON.parse(JSON.stringify(doc)) });
}, 30_000);

describe('the default passes every stage', () => {
  it('verdict is PASS', () => expect(result.verdict).toBe('PASS'));
  it('all nine stages run and pass', () => expect(result.stages.filter((s) => s.result === 'PASS')).toHaveLength(9));
  it('stages 4-6 do REAL work, not a pass-through', () => {
    expect(result.stages.find((s) => s.n === 4).detail).toMatch(/verify over the same body/);
  });
});

describe('the seeded chain is shaped for the demonstration', () => {
  it('is CA -> parent -> child, with RFC 9562 identities that are version 7', () => {
    expect(doc.chain.map((n) => n.role)).toEqual(['ca', 'agent', 'agent']);
    for (const n of doc.chain.slice(1)) {
      validateUuid(n.metadata.agent_id);
      expect(n.metadata.agent_id[14]).toBe('7');
    }
  });
  it('the metadata restates identifiers and nothing else (§7.2, §16.1)', () => {
    expect(Object.keys(parentOf(doc).metadata)).toEqual(['agent_id']);
    expect(Object.keys(childOf(doc).metadata).sort()).toEqual(['agent_id', 'parent_agent_id']);
  });
  it('every bound lives in the certificate', () => {
    const p = templateOf(parentOf(doc)); const c = templateOf(childOf(doc));
    expect(p.allowed_scopes).toEqual(['read:events', 'write:events']);
    expect(c.allowed_scopes).toEqual(['read:events']);
    expect(p.can_spawn).toEqual([c.subject]);
    expect(p.max_children).toBe(2);
    expect(p.permitted_operations).toContain('spawn');
    expect(c.permitted_operations).not.toContain('spawn');
  });
  it('the child carries CA-attested provenance (§10.5)', () => {
    const s = spawnOf(childOf(doc));
    expect(s.parent_agent_id).toBe(parentOf(doc).metadata.agent_id);
  });
  it('TTLs: one day for the parent, twelve hours for the child, and validity matches (§9.3, §10.3)', () => {
    expect(templateOf(parentOf(doc)).ttl_seconds).toBe(PARENT_TTL_SECONDS);
    expect(templateOf(childOf(doc)).ttl_seconds).toBe(CHILD_TTL_SECONDS);
    const c = parseCertificate(childOf(doc).cert_pem);
    expect((c.notAfter.value - c.notBefore.value) / 1000).toBe(CHILD_TTL_SECONDS);
  });
  it('the template owner IS the Owner certificate’s subject (§9.2)', () => {
    expect(templateOf(childOf(doc)).owner).toBe(subjectCN(parseCertificate(doc.authorities.owner.cert_pem)));
    expect(doc.authorities.owner.common_name).toBe('owner-authority');
  });
  it('hands over both authority private keys, so one-key signing can be tried', () => {
    expect(doc.authorities.owner.key_pem).toMatch(/BEGIN PRIVATE KEY/);
    expect(doc.authorities.pa.key_pem).toMatch(/BEGIN PRIVATE KEY/);
  });
  it('carries a §3.1 policy envelope with the version INSIDE the signed body', () => {
    expect(Object.keys(doc.policy).sort()).toEqual(['body', 'content_hash', 'owner_sig', 'pa_sig']);
    expect(doc.policy.body.version).toBe(2);
    expect(doc.current_policy_version).toBe(1);
    expect(doc.policy.body.subject).toBe(childOf(doc).metadata.agent_id);
  });
  it('carries no cross-org grant by default — the buttons introduce one', () => expect(doc.grant).toBeUndefined());
  it('templateFor produces exactly the nine members', () => {
    expect(Object.keys(templateFor({ subject: parentOf(doc).metadata.agent_id, scopes: ['a:b'] })).sort())
      .toEqual(['allowed_scopes', 'can_spawn', 'max_children', 'org_id', 'owner', 'permitted_operations', 'policy_ref', 'subject', 'ttl_seconds']);
  });
});

describe('the document survives a JSON round trip', () => {
  it('reloads to the same verdict — the editor loop depends on it', async () => {
    const r = await runPipeline({ document: JSON.parse(JSON.stringify(doc)) });
    expect(r.verdict).toBe('PASS');
  });
  it('is a workable size for a textarea', () => {
    expect(JSON.stringify(doc, null, 2).length).toBeLessThan(40_000);
  });
  it('every run is a fresh chain — refresh really is the reset', async () => {
    const other = await buildDefaultDocument();
    expect(other.chain[1].metadata.agent_id).not.toBe(doc.chain[1].metadata.agent_id);
    expect(other.chain[0].cert_pem).not.toBe(doc.chain[0].cert_pem);
  });
});
