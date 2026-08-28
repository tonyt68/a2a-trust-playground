/**
 * Fail-closed and identity-consistency properties.
 *
 * Every case here was a document that VALIDATED CLEANLY until it was attacked.
 * None was found by reading the code — each came out of a sweep that mutated a
 * known-good document one field at a time and asked what still passed.
 *
 * They share a shape worth naming, because it is the shape that survives review:
 * none of them is a broken check. Each is a check that was never reached, or a
 * default that answered a question nobody could answer. A missing CRL is the
 * clearest example — `document.crl ?? { revoked: [], disabled: [] }` reads as
 * defensive and means "nothing is revoked", which is an assertion, not a
 * fallback. Deleting one key from the document turned every revocation check in
 * the pipeline into a pass.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { runPipeline } from '../src/pipeline.js';
import { parseDocument } from '../src/validate-input.js';
import { buildDefaultDocument } from '../src/defaults.js';
import { DenyError } from '../src/errors.js';

let base;
beforeAll(async () => { base = await buildDefaultDocument(); }, 60_000);

const kid = (d) => d.chain.find((n) => n.role === 'agent' && n.metadata?.parent_agent_id);

async function attack(mutate) {
  const d = JSON.parse(JSON.stringify(base));
  mutate(d, kid(d));
  try {
    const r = await runPipeline({ document: parseDocument(JSON.stringify(d)) });
    return { verdict: r.verdict, code: r.error_code };
  } catch (e) {
    if (e instanceof DenyError) return { verdict: 'DENY', code: e.code };
    return { verdict: 'THREW', code: `${e.constructor.name}: ${e.message}` };
  }
}

describe('fail closed on absent evidence (§13.1)', () => {
  it('refuses a document with no CRL rather than assuming nothing is revoked', async () => {
    // An EMPTY crl is a valid answer: "nothing is revoked". A MISSING crl is
    // "unknown". Collapsing the two is what made this a one-key bypass.
    const r = await attack((d) => { delete d.crl; });
    expect(r.verdict).toBe('DENY');
    expect(r.code).toBe('ERR_SCHEMA_VIOLATION');
  });

  it('still accepts an explicitly empty CRL', async () => {
    const r = await attack((d) => { d.crl = { revoked: [], disabled: [] }; });
    expect(r.verdict).toBe('PASS');
  });

  it('refuses a document with no audit chain', async () => {
    const r = await attack((d) => { delete d.audit; });
    expect(r.verdict).toBe('DENY');
    expect(r.code).toBe('ERR_SCHEMA_VIOLATION');
  });

  it('never throws, even with both omitted', async () => {
    // The contract the UI depends on: a DENY is returned, not raised. A throw
    // here would take out the render for the exact documents most worth seeing
    // a verdict for.
    const r = await attack((d) => { delete d.crl; delete d.audit; });
    expect(r.verdict).toBe('DENY');
  });
});

describe('revocation reaches the trust anchor (§12)', () => {
  it('refuses when the CRL names the anchor', async () => {
    // Revocation was applied per-agent only, so the one revocation that voids
    // every certificate beneath it was the one revocation with no effect.
    const r = await attack((d) => { d.crl.revoked.push(d.chain[0].metadata.subject); });
    expect(r.verdict).toBe('DENY');
    expect(r.code).toBe('ERR_AGENT_REVOKED');
  });

  it('refuses when the anchor is merely disabled', async () => {
    const r = await attack((d) => { d.crl.disabled.push(d.chain[0].metadata.subject); });
    expect(r.verdict).toBe('DENY');
    expect(r.code).toBe('ERR_AGENT_REVOKED');
  });

  it('refuses before validating any agent beneath it', async () => {
    // Order matters: if the anchor is void, an agent's verification against it
    // means nothing, so no agent stage should report PASS first.
    const d = JSON.parse(JSON.stringify(base));
    d.crl.revoked.push(d.chain[0].metadata.subject);
    const r = await runPipeline({ document: d });
    expect(r.stages.filter((s) => s.subject === 'CHILD AGENT' && s.status === 'PASS')).toHaveLength(0);
  });
});

describe('an agent has exactly one identity (§7.1)', () => {
  // §7.1 carries the identity three times. All three are inside the owner_sig
  // projection, so a mismatch in `existing_cert` breaks the signature — but
  // nothing signs the chain copy, so a mismatch there was silent.
  for (const field of ['subject', 'agent_uuid']) {
    it(`refuses ${field} naming a different agent than agent_id`, async () => {
      const r = await attack((_, child) => {
        child.metadata[field] = '00000000-0000-4000-8000-000000000000';
      });
      expect(r.verdict).toBe('DENY');
      expect(r.code).toBe('ERR_SCHEMA_VIOLATION');
    });
  }

  for (const [field, value] of Object.entries({
    'owner as an array': ['owner@example.com'],
    'owner as a number': 42,
    'owner as an empty string': '',
    'owner as null': null,
  })) {
    it(`refuses ${field}`, async () => {
      const r = await attack((_, child) => { child.metadata.owner = value; });
      expect(r.verdict).toBe('DENY');
      expect(r.code).toBe('ERR_SCHEMA_VIOLATION');
    });
  }

  it('refuses a non-string org_id', async () => {
    const r = await attack((_, child) => { child.metadata.org_id = { id: 'x' }; });
    expect(r.verdict).toBe('DENY');
  });
});

describe('organisational containment (§9.2, §11)', () => {
  it('refuses a child declaring a different org than its parent', async () => {
    // §9.2 scopes authority to the organisation that signed the template, and
    // §11 puts cross-org trust behind federation this document cannot express.
    // org_id was compared only on the policy path, never between a parent and
    // the child it spawned.
    const r = await attack((_, child) => { child.metadata.org_id = 'other-org'; });
    expect(r.verdict).toBe('DENY');
    expect(r.code).toBe('ERR_ORG_MISMATCH');
  });

  it('permits a child in its parent’s organisation', async () => {
    const r = await attack(() => {});
    expect(r.verdict).toBe('PASS');
  });
});

describe('metadata timestamps must be coherent', () => {
  it('refuses created_at in the future', async () => {
    // X.509 notBefore covers the certificate. Nothing covered the metadata's
    // own claim, so the two could disagree unnoticed.
    const r = await attack((_, child) => { child.metadata.created_at = '2099-01-01T00:00:00.000Z'; });
    expect(r.verdict).toBe('DENY');
    expect(r.code).toBe('ERR_TIMESTAMP_FORMAT');
  });

  it('accepts created_at in the past', async () => {
    const r = await attack((_, child) => { child.metadata.created_at = '2020-01-01T00:00:00.000Z'; });
    expect(r.verdict).toBe('PASS');
  });
});

describe('chain order is not load-bearing', () => {
  it('reaches the same verdict however the chain is ordered', async () => {
    // This one is NOT a finding, recorded because a sweep flags it and a future
    // reader will wonder. The walk sorts parents before children explicitly, so
    // array position cannot change which checks run — the chain is a set with
    // parentage stated in the data, not a sequence.
    const forward = await runPipeline({ document: JSON.parse(JSON.stringify(base)) });
    const reversed = JSON.parse(JSON.stringify(base));
    reversed.chain.reverse();
    const back = await runPipeline({ document: reversed });

    const shape = (r) => r.stages.map((s) => `${s.stage}${s.status}${s.subject ?? ''}`).sort().join('|');
    expect(back.verdict).toBe(forward.verdict);
    expect(shape(back)).toBe(shape(forward));
  });
});
