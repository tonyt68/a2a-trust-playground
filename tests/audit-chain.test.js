/**
 * §19.7 — tamper-evident audit chain: each entry's hash is SHA-256 over the
 * canonical form of its fields including the previous hash, excluding its own.
 */
import { describe, it, expect } from 'vitest';
import { AuditChain, hashBlock, blockPreimage, GENESIS_PREVIOUS_HASH } from '../src/audit-chain.js';
import { canonicalize } from '../src/canonical.js';
import { seedAuditChain, buildDefaultDocument } from '../src/defaults.js';
import { DenyError } from '../src/errors.js';

const T0 = new Date('2026-09-03T00:00:00Z');
const at = (s) => new Date(T0.getTime() + s * 1000);

async function chainOf(n) {
  const c = new AuditChain();
  for (let i = 0; i < n; i++) await c.append({ action: 'spawn', decision: 'ALLOWED', i }, at(i));
  return c;
}

describe('chain construction', () => {
  it('starts from the genesis sentinel', async () => {
    const c = await chainOf(1);
    expect(c.chain[0].previous_hash).toBe(GENESIS_PREVIOUS_HASH);
    expect(c.chain[0].index).toBe(0);
  });
  it('links each block to the one before it', async () => {
    const c = await chainOf(3);
    expect(c.chain[1].previous_hash).toBe(c.chain[0].hash);
    expect(c.chain[2].previous_hash).toBe(c.chain[1].hash);
    expect(c.headHash).toBe(c.chain[2].hash);
  });
  it('verifies clean, and an empty chain verifies', async () => {
    expect((await (await chainOf(3)).verify()).valid).toBe(true);
    expect((await new AuditChain().verify()).valid).toBe(true);
  });
  it('produces hex SHA-256', async () => {
    expect((await chainOf(1)).chain[0].hash).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe('tamper detection — names the entry', () => {
  it('detects an altered event and names the index', async () => {
    const c = await chainOf(3); c.chain[1].event.decision = 'DENIED';
    expect(await c.verify()).toMatchObject({ valid: false, brokenAt: 1 });
  });
  it('detects an altered timestamp', async () => {
    const c = await chainOf(3); c.chain[2].timestamp = at(99).toISOString();
    expect((await c.verify()).brokenAt).toBe(2);
  });
  it('detects a removed entry', async () => {
    const c = await chainOf(3); c.chain.splice(1, 1);
    expect((await c.verify()).valid).toBe(false);
  });
  it('detects an inserted entry', async () => {
    const c = await chainOf(3); c.chain.splice(1, 0, { ...c.chain[1] });
    expect((await c.verify()).valid).toBe(false);
  });
  it('reports the FIRST break when several entries are altered', async () => {
    const c = await chainOf(4); c.chain[3].event.x = 1; c.chain[1].event.x = 1;
    expect((await c.verify()).brokenAt).toBe(1);
  });
  it('catches a re-hashed entry, because the NEXT block still links to the old hash', async () => {
    const c = await chainOf(3); c.chain[1].event.decision = 'DENIED'; c.chain[1].hash = await hashBlock(c.chain[1]);
    expect((await c.verify()).brokenAt).toBe(2);
  });
  it('rejects a chain whose genesis does not start at the sentinel', async () => {
    const c = await chainOf(2); c.chain[0].previous_hash = '0'.repeat(64);
    expect((await c.verify()).brokenAt).toBe(0);
  });
});

describe('the preimage is the single canonical form (§11.5, §19.7)', () => {
  it('uses JCS over exactly four fields, with no whitespace anywhere', async () => {
    const c = await chainOf(1);
    const pre = blockPreimage(c.chain[0]);
    expect(pre).toBe(canonicalize({ index: 0, timestamp: c.chain[0].timestamp, previous_hash: 'genesis', event: c.chain[0].event }));
    expect(pre).not.toMatch(/\s/);
    expect(pre.startsWith('{"event":')).toBe(true);   // sorted keys
  });
  it('the hash field is never inside its own preimage (§19.7)', () => {
    const pre = blockPreimage({ index: 0, timestamp: 't', previous_hash: 'genesis', event: {}, hash: 'SHOULD-NOT-APPEAR' });
    expect(pre).not.toContain('SHOULD-NOT-APPEAR');
  });
  it('the previous hash IS inside the preimage (§19.7)', () => {
    expect(blockPreimage({ index: 1, timestamp: 't', previous_hash: 'abc', event: {} })).toContain('"previous_hash":"abc"');
  });
});

describe('loading a pasted chain', () => {
  it('round-trips through toJSON/fromJSON', async () => {
    const c = await chainOf(2);
    const back = AuditChain.fromJSON(JSON.parse(JSON.stringify(c.toJSON())));
    expect((await back.verify()).valid).toBe(true);
    expect(back.headHash).toBe(c.headHash);
  });
  it('loads a TAMPERED chain cleanly so the page can display the break', async () => {
    const c = await chainOf(2); c.chain[0].hash = 'x';
    expect(() => AuditChain.fromJSON(c.toJSON())).not.toThrow();
  });
  it('treats null as an empty chain', () => expect(AuditChain.fromJSON(null).length).toBe(0));
  for (const [name, val] of Object.entries({
    'a string': 'x', 'a chain that is not an array': { chain: 'x' }, 'a non-object block': { chain: [1] },
    'a block missing its hash': { chain: [{ index: 0, timestamp: 't', previous_hash: 'genesis', event: {} }] },
  })) {
    it(`rejects ${name}`, () => expect(() => AuditChain.fromJSON(val)).toThrow(DenyError));
  }
});

describe('the seeded audit chain', () => {
  const P = '019b3c8e-2f10-7a4b-9c6d-3e5f7a9b1c2d', C = '8f14e45f-ceea-467a-9c0f-7ad0f1b0d5aa';
  it('seeds enough entries for stage 9 to do real work, and verifies as sealed', async () => {
    const c = await seedAuditChain({ parentId: P, childId: C, now: T0 });
    expect(c.length).toBeGreaterThanOrEqual(3);
    expect((await c.verify()).valid).toBe(true);
  });
  it('is reproducible: a rebuild matches a seed byte for byte', async () => {
    const a = await seedAuditChain({ parentId: P, childId: C, now: T0 });
    const b = await seedAuditChain({ parentId: P, childId: C, now: T0 });
    expect(JSON.stringify(a.toJSON())).toBe(JSON.stringify(b.toJSON()));
  });
  it('names the agents it describes', async () => {
    const c = await seedAuditChain({ parentId: P, childId: C, now: T0 });
    expect(c.chain[0].event.agent).toBe(P);
    expect(c.chain[1].event).toMatchObject({ agent: C, parent: P });
  });
  it('breaks when any single entry is altered', async () => {
    for (let i = 0; i < 3; i++) {
      const c = await seedAuditChain({ parentId: P, childId: C, now: T0 });
      c.chain[i].event.detail = 'altered';
      expect((await c.verify()).brokenAt).toBe(i);
    }
  });
  it('the document the page loads carries a chain that verifies', async () => {
    const d = await buildDefaultDocument();
    expect((await AuditChain.fromJSON(d.audit).verify()).valid).toBe(true);
  }, 30_000);
});
