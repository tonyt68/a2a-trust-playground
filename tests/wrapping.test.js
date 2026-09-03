/**
 * Signature wrapping and the single-entrance property.
 *
 * XML Signature Wrapping (the SAML attack) works when the verifier and the
 * consumer resolve a name to DIFFERENT objects. Under -03 the surface for that
 * is much smaller than it was: every bound is inside a CA-signed certificate
 * extension and every envelope signs its whole body. What remains is the
 * document's power to point one signed thing at another — a policy at the
 * wrong template, a grant at the wrong template, a chain at the wrong parent —
 * and each of those pointers is checked against a signed value.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { readFile } from 'node:fs/promises';
import { runPipeline } from '../src/pipeline.js';
import { parseDocument } from '../src/validate-input.js';
import { buildDefaultDocument } from '../src/defaults.js';
import { childOf, parentOf, resignPolicy, spawnAcrossOrganizations } from '../src/scenarios.js';
import { signEnvelope, privateKeyFromPem } from '../src/crypto-sign.js';
import { locateFailure } from '../src/locate.js';
import { DenyError } from '../src/errors.js';

let base, now;
beforeAll(async () => { now = new Date(); base = await buildDefaultDocument({ now }); }, 30_000);

async function attack(mutate) {
  const d = JSON.parse(JSON.stringify(base));
  await mutate(d);
  try {
    const r = await runPipeline({ document: parseDocument(JSON.stringify(d)), now });
    return { verdict: r.verdict, code: r.error_code };
  } catch (e) {
    if (e instanceof DenyError) return { verdict: 'DENY', code: e.code };
    return { verdict: 'THREW', code: `${e.constructor.name}: ${e.message}` };
  }
}

describe('pointing a signed thing at the wrong object', () => {
  it('a policy pointed at the PARENT is bounded by the parent, not the child', async () => {
    // Legitimate: the policy names the parent and stays within the parent's
    // ceiling. The point is that the bound follows the subject the policy
    // names, read from THAT certificate.
    const r = await attack(async (d) => {
      d.policy.body.subject = parentOf(d).metadata.agent_id; d.policy.body.scopes = ['write:events']; await resignPolicy(d);
    });
    expect(r.verdict).toBe('PASS');
  });
  it('a policy pointed at the parent but wider than the parent is refused', async () => {
    const r = await attack(async (d) => {
      d.policy.body.subject = parentOf(d).metadata.agent_id; d.policy.body.scopes = ['admin:all']; await resignPolicy(d);
    });
    expect(r.code).toBe('ERR_POLICY_EXCEEDS_TEMPLATE');
  });
  it('a policy signed for the child cannot be re-pointed at the parent without re-signing', async () => {
    const r = await attack((d) => { d.policy.body.subject = parentOf(d).metadata.agent_id; });
    expect(r.code).toBe('ERR_OWNER_SIG_INVALID');
  });
  it('a grant pointed at the wrong template is refused even though correctly signed', async () => {
    const r = await attack(async (d) => {
      await spawnAcrossOrganizations(d, { template: parentOf(d).metadata.agent_id }, { now });
    });
    expect(r.code).toBe('ERR_GRANT_INVALID');
  });
  it('the chain cannot name a parent the CA did not attest', async () => {
    const r = await attack((d) => { childOf(d).metadata.parent_agent_id = parentOf(d).metadata.agent_id.replace(/^./, (c) => (c === '0' ? '1' : '0')); });
    expect(r.code).toBe('ERR_PARENT_MISMATCH');
  });
  it('a policy padded with an unsigned field is refused before any signature is checked', async () => {
    const r = await attack((d) => { d.policy.body.shadow_scopes = ['admin:all']; });
    expect(r.code).toBe('ERR_UNKNOWN_POLICY_FIELD');
  });
  it('the two authorities cannot be one key wearing two hats', async () => {
    const r = await attack(async (d) => {
      d.authorities.pa = { ...d.authorities.owner };
      const key = await privateKeyFromPem(d.authorities.owner.key_pem);
      d.policy = await signEnvelope(d.policy.body, key, key, { withHash: true });
    });
    expect(r.code).toBe('ERR_SINGLE_SIGNATURE');
  });
});

describe('the chain document carries no authority', () => {
  it('a -02 metadata bound is refused as an unknown field, never read', async () => {
    const r = await attack((d) => { childOf(d).metadata.allowed_scopes = ['admin:all']; });
    expect(r.code).toBe('ERR_SCHEMA_VIOLATION');
  });
  it('file-path fields have no home in the document at all', async () => {
    const r = await attack((d) => { childOf(d).metadata.cert_path = '../../../../etc/passwd'; });
    expect(r.code).toBe('ERR_SCHEMA_VIOLATION');
  });
});

describe('the editor is the only input, and it has one door', () => {
  it('no module reads the editor with a bare JSON.parse', async () => {
    const src = await readFile(new URL('../src/app.js', import.meta.url), 'utf8');
    expect(src).not.toMatch(/JSON\.parse\s*\(\s*docBox\.value/);
  });
  it('the highlighter survives malformed input rather than throwing', () => {
    for (const text of [
      '{\n  "\\q": 1\n}', '{\n  "\\": 1\n}', '{\n  "a": "\\u00"\n}',
      `{"a":${'['.repeat(500)}`, ']'.repeat(500), '{"__proto__": {"a": 1}}', '\u0000\u0001\u0002', '', '   ',
    ]) {
      expect(() => locateFailure(text, { path: ['a', 'b'], values: ['x'] })).not.toThrow();
    }
  });
  it('exports a structured error rather than throwing on unparseable input', async () => {
    const src = await readFile(new URL('../src/app.js', import.meta.url), 'utf8');
    expect(src).toMatch(/parseDocument\(docBox\.value/);
    expect(src).toMatch(/ERR_UNPARSEABLE/);
  });
});
