/**
 * §10.4 — the audit log entry IS the draft's flat object, previous_hash and
 * entry_hash included; §19.7 — each entry's hash is SHA-256 over the canonical
 * form of every member but its own hash.
 */
import { describe, it, expect } from 'vitest';
import {
  AuditChain, hashEntry, entryPreimage, spawnEntry, assertSpawnEntry, GENESIS_PREVIOUS_HASH,
} from '../src/audit-chain.js';
import { canonicalize, AUDIT_SPAWN_FIELDS } from '../src/canonical.js';
import { seedAuditChain, buildDefaultDocument } from '../src/defaults.js';
import { DenyError } from '../src/errors.js';

const T0 = new Date('2026-09-04T00:00:00Z');
const at = (s) => new Date(T0.getTime() + s * 1000);
const P = '019b3c8e-2f10-7a4b-9c6d-3e5f7a9b1c2d', C = '8f14e45f-ceea-467a-9c0f-7ad0f1b0d5aa';
const NONCE = Buffer.alloc(16, 7).toString('base64');

async function chainOf(n) {
  const c = new AuditChain();
  for (let i = 0; i < n; i++) await c.append({ action: 'spawn', outcome: 'ALLOWED', detail: `entry-${i}` }, at(i));
  return c;
}

describe('chain construction', () => {
  it('starts from sixty-four zero digits (§10.4), and carries no index', async () => {
    const c = await chainOf(1);
    expect(c.chain[0].previous_hash).toBe(GENESIS_PREVIOUS_HASH);
    expect(GENESIS_PREVIOUS_HASH).toMatch(/^0{64}$/);
    expect('index' in c.chain[0]).toBe(false);
  });
  it('links each entry to the one before it', async () => {
    const c = await chainOf(3);
    expect(c.chain[1].previous_hash).toBe(c.chain[0].entry_hash);
    expect(c.chain[2].previous_hash).toBe(c.chain[1].entry_hash);
    expect(c.headHash).toBe(c.chain[2].entry_hash);
  });
  it('verifies clean, and an empty chain verifies', async () => {
    expect((await (await chainOf(3)).verify()).valid).toBe(true);
    expect((await new AuditChain().verify()).valid).toBe(true);
  });
  it('produces hex SHA-256', async () => {
    expect((await chainOf(1)).chain[0].entry_hash).toMatch(/^[0-9a-f]{64}$/);
  });
  it('refuses a non-flat entry, and a caller that supplies the chain members itself', async () => {
    const c = new AuditChain();
    await expect(c.append({ action: 'x', nested: {} })).rejects.toBeInstanceOf(DenyError);
    await expect(c.append({ action: 'x', previous_hash: 'y' })).rejects.toBeInstanceOf(DenyError);
  });
});

describe('tamper detection — names the entry', () => {
  it('detects an altered member and names the index', async () => {
    const c = await chainOf(3); c.chain[1].outcome = 'DENIED';
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
    const c = await chainOf(4); c.chain[3].x = 'a'; c.chain[1].x = 'a';
    expect((await c.verify()).brokenAt).toBe(1);
  });
  it('catches a re-hashed entry, because the NEXT entry still links to the old hash', async () => {
    const c = await chainOf(3); c.chain[1].outcome = 'DENIED'; c.chain[1].entry_hash = await hashEntry(c.chain[1]);
    expect((await c.verify()).brokenAt).toBe(2);
  });
  it('rejects a chain whose genesis does not start at the sentinel', async () => {
    const c = await chainOf(2); c.chain[0].previous_hash = 'genesis';
    expect((await c.verify()).brokenAt).toBe(0);
  });
});

describe('the preimage is the single canonical form (§11.5, §19.7)', () => {
  it('uses JCS over every member but entry_hash, with no whitespace anywhere', async () => {
    const c = await chainOf(1);
    const pre = entryPreimage(c.chain[0]);
    const { entry_hash, ...rest } = c.chain[0];
    expect(pre).toBe(canonicalize(rest));
    expect(pre).not.toMatch(/\s/);
    expect(pre.startsWith('{"action":')).toBe(true);   // sorted keys
  });
  it('the hash member is never inside its own preimage (§19.7)', () => {
    const pre = entryPreimage({ timestamp: 't', previous_hash: GENESIS_PREVIOUS_HASH, action: 'x', entry_hash: 'SHOULD-NOT-APPEAR' });
    expect(pre).not.toContain('SHOULD-NOT-APPEAR');
  });
  it('the previous hash IS inside the preimage (§19.7)', () => {
    expect(entryPreimage({ timestamp: 't', previous_hash: 'abc', action: 'x' })).toContain('"previous_hash":"abc"');
  });
});

describe('§10.4 Table 6 — the spawn entry', () => {
  const allowed = () => spawnEntry({ spawningAgentId: P, childTemplateId: C, requestedScopes: ['a:b'], spawnNonce: NONCE, outcome: 'ALLOWED' });
  it('an ALLOWED entry carries exactly the members of Table 6, and grants what was requested', async () => {
    const c = new AuditChain();
    const e = await c.append(allowed(), T0);
    expect(Object.keys(e).sort()).toEqual([...AUDIT_SPAWN_FIELDS].sort());
    expect(e.granted_scopes).toEqual(['a:b']);
    expect(() => c.assertEntries()).not.toThrow();
  });
  it('a DENIED entry grants nothing and carries a reason; an ALLOWED one carries none', async () => {
    const denied = spawnEntry({ spawningAgentId: P, childTemplateId: C, requestedScopes: ['a:b'], spawnNonce: NONCE, outcome: 'DENIED', reason: 'ERR_X: why' });
    expect(denied.granted_scopes).toEqual([]);
    expect(denied.reason).toBe('ERR_X: why');
    expect('reason' in allowed()).toBe(false);
  });
  it('grant_id is present exactly when the spawn was under a grant', () => {
    expect('grant_id' in allowed()).toBe(false);
    expect(spawnEntry({ spawningAgentId: P, childTemplateId: C, requestedScopes: ['a:b'], spawnNonce: NONCE, grantId: P, outcome: 'ALLOWED' }).grant_id).toBe(P);
  });
  it('assertEntries refuses a spawn entry that breaks a Table 6 rule, with its own code', async () => {
    const bad = async (mutate) => {
      const c = new AuditChain(); await c.append(allowed(), T0); mutate(c.chain[0]);
      let caught = null; try { c.assertEntries(); } catch (e) { caught = e; }
      expect(caught).toBeInstanceOf(DenyError); expect(caught.code).toBe('ERR_AUDIT_ENTRY_INVALID');
      return caught;
    };
    await bad((e) => { e.outcome = 'MAYBE'; });
    await bad((e) => { delete e.spawn_nonce; });
    await bad((e) => { e.extra = 'x'; });
    await bad((e) => { e.reason = 'an ALLOWED entry with a reason'; });
    await bad((e) => { e.outcome = 'DENIED'; });                 // DENIED with granted scopes and no reason
    await bad((e) => { e.granted_scopes = []; });                // ALLOWED that granted nothing
    await bad((e) => { e.spawning_agent_id = 'not-a-uuid'; });
    await bad((e) => { e.nested = { a: 1 }; });
  });
  it('assertSpawnEntry accepts a well-formed DENIED entry', async () => {
    const c = new AuditChain();
    const e = await c.append(spawnEntry({ spawningAgentId: P, childTemplateId: C, requestedScopes: ['a:b'], spawnNonce: NONCE, outcome: 'DENIED', reason: 'refused' }), T0);
    expect(() => assertSpawnEntry(e)).not.toThrow();
  });
  it('an entry that is not about a spawn is only held to the chain members', async () => {
    const c = await chainOf(2);
    expect(() => c.assertEntries()).not.toThrow();
    c.chain[0].previous_hash = 'genesis';
    expect(() => c.assertEntries()).toThrow(DenyError);
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
    const c = await chainOf(2); c.chain[0].entry_hash = 'x';
    expect(() => AuditChain.fromJSON(c.toJSON())).not.toThrow();
  });
  it('treats null as an empty chain', () => expect(AuditChain.fromJSON(null).length).toBe(0));
  for (const [name, val] of Object.entries({
    'a string': 'x', 'a chain that is not an array': { chain: 'x' }, 'a non-object entry': { chain: [1] },
    'an entry missing its hash': { chain: [{ timestamp: 't', previous_hash: GENESIS_PREVIOUS_HASH, action: 'x' }] },
  })) {
    it(`rejects ${name}`, () => expect(() => AuditChain.fromJSON(val)).toThrow(DenyError));
  }
});

describe('the seeded audit chain', () => {
  const seed = () => seedAuditChain({ parentId: P, childId: C, childScopes: ['read:events'], spawnNonce: NONCE, now: T0 });
  it('seeds enough entries for stage 9 to do real work, and verifies as sealed', async () => {
    const c = await seed();
    expect(c.length).toBeGreaterThanOrEqual(3);
    expect((await c.verify()).valid).toBe(true);
    expect(() => c.assertEntries()).not.toThrow();
  });
  it('is reproducible: a rebuild matches a seed byte for byte', async () => {
    expect(JSON.stringify((await seed()).toJSON())).toBe(JSON.stringify((await seed()).toJSON()));
  });
  it('names the agents it describes, and records the spawn as a Table 6 entry', async () => {
    const c = await seed();
    expect(c.chain[0]).toMatchObject({ action: 'issue_template', agent: P });
    const spawn = c.chain.find((e) => 'spawning_agent_id' in e);
    expect(spawn).toMatchObject({ spawning_agent_id: P, child_template_id: C, spawn_nonce: NONCE, outcome: 'ALLOWED' });
  });
  it('breaks when any single entry is altered', async () => {
    for (let i = 0; i < 3; i++) {
      const c = await seed();
      c.chain[i].timestamp = at(999).toISOString();
      expect((await c.verify()).brokenAt).toBe(i);
    }
  });
  it('the document the page loads carries the Registry’s own chain, which verifies and conforms', async () => {
    const d = await buildDefaultDocument();
    const c = AuditChain.fromJSON(d.audit);
    expect((await c.verify()).valid).toBe(true);
    expect(() => c.assertEntries()).not.toThrow();
    expect(c.chain.some((e) => 'spawning_agent_id' in e && e.outcome === 'ALLOWED')).toBe(true);
  }, 30_000);
});
