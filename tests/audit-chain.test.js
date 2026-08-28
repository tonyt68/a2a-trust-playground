/**
 * Acceptance criterion 8: tampering with an audit entry flips the chain status
 * and NAMES the broken entry.
 *
 * Under `-02` §9.5 there is ONE canonical form. `-01`'s implementation carried
 * two — compact for signatures, spaced for audit blocks — because the reference
 * implementation called json.dumps two different ways in two different files.
 * §9.5 specifies a single form for both, on the reasoning that an implementation
 * carrying two will eventually apply the wrong one, and that failure presents as
 * an integrity error with no indication that serialization was the cause.
 */
import { describe, it, expect } from 'vitest';
import { AuditChain, hashBlock, blockPreimage, GENESIS_PREVIOUS_HASH } from '../src/audit-chain.js';
import { DenyError } from '../src/errors.js';

const at = (n) => new Date(Date.UTC(2026, 7, 28, 12, 0, n));

async function chainOf(n) {
  const c = new AuditChain();
  for (let i = 0; i < n; i++) {
    await c.append({ agent: `agent-${i}`, decision: i % 2 ? 'DENIED' : 'ALLOWED' }, at(i));
  }
  return c;
}

describe('chain construction', () => {
  it('starts from the genesis sentinel', async () => {
    const c = await chainOf(1);
    expect(c.chain[0].previous_hash).toBe(GENESIS_PREVIOUS_HASH);
    expect(c.chain[0].index).toBe(0);
  });

  it('links each block to the one before it', async () => {
    const c = await chainOf(5);
    for (let i = 1; i < 5; i++) {
      expect(c.chain[i].previous_hash).toBe(c.chain[i - 1].hash);
    }
    expect(c.headHash).toBe(c.chain[4].hash);
  });

  it('verifies clean', async () => {
    expect(await (await chainOf(5)).verify())
      .toEqual({ valid: true, brokenAt: null, reason: null });
  });

  it('verifies an empty chain', async () => {
    expect(await new AuditChain().verify()).toEqual({ valid: true, brokenAt: null, reason: null });
  });

  it('produces hex SHA-256', async () => {
    const c = await chainOf(1);
    expect(c.chain[0].hash).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe('tamper detection — names the entry (AC-8)', () => {
  it('detects an altered event and names the index', async () => {
    const c = await chainOf(5);
    c.chain[2].event.decision = 'DENIED';         // entry 2 was ALLOWED; flip it
    const r = await c.verify();
    expect(r.valid).toBe(false);
    expect(r.brokenAt).toBe(2);
    expect(r.reason).toContain('entry 2');
    expect(r.reason).toContain('altered');
  });

  it('detects an altered timestamp', async () => {
    const c = await chainOf(4);
    c.chain[1].timestamp = at(99).toISOString();
    expect((await c.verify()).brokenAt).toBe(1);
  });

  it('detects a removed entry', async () => {
    const c = await chainOf(5);
    c.chain.splice(2, 1);
    const r = await c.verify();
    expect(r.valid).toBe(false);
    expect(r.brokenAt).toBe(2);
  });

  it('detects an inserted entry', async () => {
    const c = await chainOf(4);
    c.chain.splice(2, 0, { ...c.chain[1], index: 2 });
    expect((await c.verify()).valid).toBe(false);
  });

  it('reports the FIRST break when several entries are altered', async () => {
    const c = await chainOf(6);
    c.chain[4].event.decision = 'DENIED';   // 4 was ALLOWED
    c.chain[1].event.decision = 'ALLOWED';  // 1 was DENIED
    expect((await c.verify()).brokenAt).toBe(1);
  });

  it('catches a re-hashed entry, because the NEXT block still links to the old hash', async () => {
    // The sophisticated tamper: edit an entry and recompute its own hash so it
    // is internally consistent. The chain still breaks at the following block.
    const c = await chainOf(5);
    c.chain[2].event.decision = 'DENIED';
    c.chain[2].hash = await hashBlock(c.chain[2]);
    const r = await c.verify();
    expect(r.valid).toBe(false);
    expect(r.brokenAt).toBe(3);
    expect(r.reason).toContain('does not link');
  });

  it('rejects a chain whose genesis does not start at the sentinel', async () => {
    const c = await chainOf(3);
    c.chain[0].previous_hash = 'x'.repeat(64);
    const r = await c.verify();
    expect(r.valid).toBe(false);
    expect(r.brokenAt).toBe(0);
  });
});

describe('preimage is the single -02 canonical form (§9.5, §16.6)', () => {
  it('uses JCS, with no whitespace anywhere', async () => {
    const { canonicalize } = await import('../src/canonical.js');
    const block = {
      index: 1,
      timestamp: '2026-08-28T12:00:01.123Z',
      previous_hash: 'a'.repeat(64),
      event: { decision: 'DENIED', agent: 'x' },
    };
    const pre = blockPreimage(block);
    // The -01 spaced form emitted '", "' between items. JCS emits none.
    expect(pre).not.toContain('", "');
    expect(pre).not.toContain('": "');
    // And it is the same function signatures use — that is the whole point.
    expect(pre).toBe(canonicalize(JSON.parse(pre)));
  });

  it('the hash field is never inside its own preimage (§16.6)', () => {
    const block = {
      index: 0,
      timestamp: '2026-08-28T12:00:00.000Z',
      previous_hash: GENESIS_PREVIOUS_HASH,
      event: { decision: 'ALLOWED' },
    };
    expect(blockPreimage({ ...block, hash: 'deadbeef' })).not.toContain('deadbeef');
    // Adding the hash must not change the preimage at all, or the chain could
    // never verify: the verifier recomputes from a block that already has one.
    expect(blockPreimage({ ...block, hash: 'deadbeef' })).toBe(blockPreimage(block));
  });
});


describe('loading a pasted chain', () => {
  it('round-trips through toJSON/fromJSON', async () => {
    const c = await chainOf(3);
    const back = AuditChain.fromJSON(JSON.parse(JSON.stringify(c.toJSON())));
    expect(await back.verify()).toEqual({ valid: true, brokenAt: null, reason: null });
    expect(back.headHash).toBe(c.headHash);
  });

  it('loads a TAMPERED chain cleanly so the page can display the break', async () => {
    const c = await chainOf(3);
    c.chain[1].event.decision = 'ALLOWED';  // entry 1 was DENIED
    const back = AuditChain.fromJSON(c.toJSON());
    expect((await back.verify()).brokenAt).toBe(1);
  });

  it('treats null as an empty chain', () => {
    expect(AuditChain.fromJSON(null).length).toBe(0);
  });

  for (const [name, val] of Object.entries({
    'a string': 'nope',
    'an object with no chain': { entries: 2 },
    'entries that are not objects': { chain: ['x'] },
    'an entry missing hash': { chain: [{ index: 0, timestamp: 't', previous_hash: 'genesis', event: {} }] },
  })) {
    it(`rejects ${name}`, () => {
      let thrown;
      try { AuditChain.fromJSON(val); } catch (e) { thrown = e; }
      expect(thrown).toBeInstanceOf(DenyError);
      expect(thrown.code).toBe('ERR_SCHEMA_VIOLATION');
    });
  }
});
