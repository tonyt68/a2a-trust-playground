/**
 * §15.1 — a verification step that cannot be completed is a DENY. These pin
 * the places where a missing thing used to be read as an empty thing.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { runPipeline } from '../src/pipeline.js';
import { buildDefaultDocument } from '../src/defaults.js';
import { childOf, parentOf, reissueThroughRegistry } from '../src/scenarios.js';

let base, now;
beforeAll(async () => { now = new Date(); base = await buildDefaultDocument({ now }); }, 30_000);
const clone = () => JSON.parse(JSON.stringify(base));
const run = (d) => runPipeline({ document: d, now });

describe('fail closed on absent evidence (§15.1)', () => {
  it('refuses a document with no CRL rather than assuming nothing is revoked', async () => {
    const d = clone(); delete d.crl;
    const r = await run(d);
    expect(r.verdict).toBe('DENY');
    expect(r.stages.find((s) => s.result === 'DENY').detail).toMatch(/no crl/);
  });
  it('still accepts an explicitly empty CRL', async () => {
    const d = clone(); d.crl = { revoked: [], disabled: [] };
    expect((await run(d)).verdict).toBe('PASS');
  });
  it('refuses a document with no audit chain', async () => {
    const d = clone(); delete d.audit;
    const r = await run(d);
    expect(r.verdict).toBe('DENY');
    expect(r.stages.find((s) => s.result === 'DENY').detail).toMatch(/no audit chain/);
  });
  it('never throws, even with both omitted', async () => {
    const d = clone(); delete d.audit; delete d.crl;
    expect((await run(d)).verdict).toBe('DENY');
  });
});

describe('revocation reaches the trust anchor (§14)', () => {
  it('refuses when the CRL names the anchor, before any agent', async () => {
    const d = clone(); d.crl.revoked.push(d.chain[0].metadata.subject);
    const r = await run(d);
    expect(r.error_code).toBe('ERR_AGENT_REVOKED');
    expect(r.walk.map((w) => w.subject)).toEqual([]);
  });
  it('matches the CRL against the CERTIFICATE\'s own subject, not the document\'s unverified restatement of it', async () => {
    // If the check trusted `metadata.subject`, deleting or lying about it
    // would let a CRL entry naming the real anchor be silently skipped.
    let d = clone(); delete d.chain[0].metadata.subject;
    d.crl.revoked.push('A2A-Trust-Playground-CA');
    expect((await run(d)).error_code).toBe('ERR_AGENT_REVOKED');

    d = clone(); d.chain[0].metadata.subject = 'not-the-real-anchor';
    d.crl.revoked.push('A2A-Trust-Playground-CA');
    expect((await run(d)).error_code).toBe('ERR_AGENT_REVOKED');
  });
});

describe('the trust anchor\'s own validity window is checked (§15.1)', () => {
  it('refuses when the clock has moved past the anchor\'s notAfter, even though every leaf beneath it is freshly re-issued', async () => {
    const d = clone();
    // Re-issue both agents under the SAME (already-expired-relative-to-`now`)
    // CA key, so only the anchor's own window is what could refuse this.
    const far = new Date(now.getTime() + 30 * 24 * 3600 * 1000);
    await reissueThroughRegistry(d, parentOf(d), {}, { now: far });
    await reissueThroughRegistry(d, childOf(d), {}, { now: far });
    const r = await runPipeline({ document: d, now: far });
    expect(r.verdict).toBe('DENY');
    expect(r.error_code).toBe('ERR_CERT_EXPIRED');
  });
});

describe('every restatement of an identifier must agree with the certificate (§7.2, §10.5)', () => {
  it('refuses a chain agent_id that is not the certificate subject', async () => {
    const d = clone(); childOf(d).metadata.agent_id = parentOf(d).metadata.agent_id;
    expect((await run(d)).error_code).toBe('ERR_DUPLICATE_SUBJECT');
  });
  it('refuses a parent_agent_id the certificate did not attest', async () => {
    const d = clone(); childOf(d).metadata.parent_agent_id = '019b3c8e-2f10-7a4b-9c6d-3e5f7a9b1c2d';
    expect((await run(d)).error_code).toBe('ERR_PARENT_MISMATCH');
  });
  it('refuses a child presented as a root', async () => {
    const d = clone(); delete childOf(d).metadata.parent_agent_id;
    expect((await run(d)).error_code).toBe('ERR_PARENT_MISMATCH');
  });
});

describe('organisational containment (§10.1 Check 2, §13)', () => {
  it('a child in its parent’s organisation needs no grant', async () => {
    expect((await run(clone())).walk.find((w) => w.subject === 'CROSS-ORG GRANT').detail).toMatch(/not needed/);
  });
});

describe('chain order is not load-bearing', () => {
  it('reaches the same verdict however the chain is ordered', async () => {
    const d = clone(); d.chain.reverse();
    expect((await run(d)).verdict).toBe('PASS');
  });
});
