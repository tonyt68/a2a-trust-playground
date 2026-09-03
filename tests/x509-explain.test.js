/**
 * The decoder is checked DIFFERENTIALLY against OpenSSL rather than against
 * hand-written expectations. Every field below is compared to what
 * `openssl x509` reports for the same bytes.
 *
 * This caught a real bug once: the fingerprint was computed from a
 * re-serialisation, which produced 1128 bytes where the original DER was 1147.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync, existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { describeCertificate, describeName, VALIDATION_STEPS, normalizeOid } from '../src/x509-explain.js';
import { parseCertificate, TEMPLATE_EXT_OID, SPAWN_EXT_OID } from '../src/x509.js';
import { ERRORS } from '../src/errors.js';
import { mintChain, DEMO_NOTICE_OID } from '../src/mint.js';
import { toPem } from '../src/mint.js';
import { Extension } from 'pkijs';
import { replaceExtension, resign } from './support/cert-surgery.js';
import { templateFor } from '../src/defaults.js';

const dir = fileURLToPath(new URL('./fixtures/certs/', import.meta.url));
const read = (f) => readFileSync(dir + f, 'utf8');
const openssl = (...args) => execFileSync('openssl', args, { encoding: 'utf8' }).trim();
const x509 = (f, ...args) => openssl('x509', '-in', dir + f, '-noout', ...args);

let A, B;
const CERTS = ['ca-root.crt', 'agent-a.crt', 'agent-b.crt', 'owner.crt', 'pa.crt', 'rsa3072-agent.crt', 'ed25519-agent.crt'];

beforeAll(() => {
  if (!existsSync(dir + 'ca-root.crt')) throw new Error('run `pnpm fixtures`');
  A = read('agent-a.uuid').trim(); B = read('agent-b.uuid').trim();
});

describe('digests agree with OpenSSL, byte for byte', () => {
  for (const f of CERTS) {
    it(`${f} — SHA-256 fingerprint over the ORIGINAL DER`, async () => {
      const mine = (await describeCertificate(read(f))).fingerprint_sha256;
      const theirs = x509(f, '-fingerprint', '-sha256').split('=')[1].replace(/:/g, '').toLowerCase();
      expect(mine).toBe(theirs);
    });
  }
  it('reports the original DER length, not a re-encoding', async () => {
    const d = await describeCertificate(read('agent-a.crt'));
    expect(d.der_bytes).toBe(execFileSync('openssl', ['x509', '-in', dir + 'agent-a.crt', '-outform', 'der']).length);
  });
  it('hashes the tbsCertificate — the bytes the signature actually covers', async () => {
    const d = await describeCertificate(read('agent-a.crt'));
    const der = execFileSync('openssl', ['x509', '-in', dir + 'agent-a.crt', '-outform', 'der']);
    const readLen = (b, i) => { const n = b[i]; if (n < 0x80) return [n, i + 1]; const k = n & 0x7f;
      return [parseInt(b.subarray(i + 1, i + 1 + k).toString('hex'), 16), i + 1 + k]; };
    let i = 1; [, i] = readLen(der, i);
    const start = i; i += 1;
    let len; [len, i] = readLen(der, i);
    const tbs = der.subarray(start, i + len);
    expect(d.signed_bytes.length).toBe(tbs.length);
    expect(d.signed_bytes.sha256).toBe(Buffer.from(await crypto.subtle.digest('SHA-256', tbs)).toString('hex'));
  });
});

describe('fields agree with OpenSSL', () => {
  it('serial number', async () => {
    const d = await describeCertificate(read('agent-a.crt'));
    expect(d.serial_number.replace(/:/g, '').toLowerCase().replace(/^0+/, ''))
      .toBe(x509('agent-a.crt', '-serial').split('=')[1].toLowerCase().replace(/^0+/, ''));
  });
  it('validity window', async () => {
    const d = await describeCertificate(read('agent-a.crt'));
    const dates = x509('agent-a.crt', '-dates');
    const parse = (k) => new Date(dates.match(new RegExp(`${k}=(.+)`))[1]).toISOString();
    expect(d.validity.not_before).toBe(parse('notBefore'));
    expect(d.validity.not_after).toBe(parse('notAfter'));
    expect(d.validity.duration_seconds).toBe(86400);
  });
  it('public key type and size, for every Table 2 row', async () => {
    for (const [f, type, bits, text] of [
      ['agent-a.crt', 'P-256', 256, 'Public-Key: (256 bit)'], ['p384-agent.crt', 'P-384', 384, 'Public-Key: (384 bit)'],
      ['rsa3072-agent.crt', 'RSA', 3072, 'Public-Key: (3072 bit)'], ['rsa2048-agent.crt', 'RSA', 2048, 'Public-Key: (2048 bit)'],
      ['ed25519-agent.crt', 'Ed25519', 256, 'ED25519 Public-Key'],
    ]) {
      const d = await describeCertificate(read(f));
      expect(d.public_key.type, f).toBe(type);
      expect(d.public_key.bits, f).toBe(bits);
      expect(x509(f, '-text')).toContain(text);
    }
    expect((await describeCertificate(read('rsa2048-agent.crt'))).public_key.meets_minimum).toBe(false);
    expect((await describeCertificate(read('agent-a.crt'))).public_key.meets_minimum).toBe(true);
  });
  it('subject and issuer DNs, in encoding order', async () => {
    const d = await describeCertificate(read('agent-a.crt'));
    expect(d.subject.attributes.map((a) => a.name)).toEqual(['C', 'O', 'OU', 'CN']);
    expect(d.common_name).toBe(A);
    expect(d.issuer_common_name).toBe('A2A-Trust-Playground-CA');
    expect(x509('agent-a.crt', '-subject')).toContain('C=US');
  });
  it('signature algorithm', async () => {
    expect((await describeCertificate(read('agent-a.crt'))).signature.algorithm).toBe('ecdsa-with-SHA256');
    expect(x509('agent-a.crt', '-text')).toContain('ecdsa-with-SHA256');
    expect((await describeCertificate(read('ed-leaf.crt'))).signature.algorithm).toBe('Ed25519');
    expect((await describeCertificate(read('sha1-leaf.crt'))).signature.algorithm).toBe('ecdsa-with-SHA1');
  });
  it('version is 3, and self-signed matches the CA/leaf split', async () => {
    expect((await describeCertificate(read('agent-a.crt'))).version).toBe(3);
    expect((await describeCertificate(read('ca-root.crt'))).self_signed).toBe(true);
    expect((await describeCertificate(read('agent-a.crt'))).self_signed).toBe(false);
  });
});

describe('extension decoding', () => {
  it('decodes the leaf profile as OpenSSL renders it', async () => {
    const d = await describeCertificate(read('agent-a.crt'));
    const by = (n) => d.extensions.find((e) => e.name === n);
    const text = x509('agent-a.crt', '-text');
    expect(by('basicConstraints')).toMatchObject({ critical: true, summary: 'CA:FALSE' });
    expect(text).toContain('CA:FALSE');
    expect(by('keyUsage')).toMatchObject({ critical: true, value: ['digitalSignature'] });
    expect(by('extendedKeyUsage').value).toEqual(['clientAuth']);
    expect(by('cRLDistributionPoints').summary).toContain('http://crl.a2a-playground.invalid/ca.crl');
    expect(text).toContain('http://crl.a2a-playground.invalid/ca.crl');
  });
  it('decodes the Agent Template extension both ways (§8.2)', async () => {
    const d = await describeCertificate(read('agent-a.crt'));
    const t = d.extensions.find((e) => e.oid === TEMPLATE_EXT_OID);
    expect(t.critical).toBe(true);
    expect(t.views.any_x509_stack).toMatch(/OCTET STRING.*critical/);
    expect(t.views.conformant_validator).toMatch(/9 members, JCS/);
    expect(d.agent_template.members.map((m) => m.member).sort()).toEqual(['allowed_scopes', 'can_spawn', 'max_children',
      'org_id', 'owner', 'permitted_operations', 'policy_ref', 'subject', 'ttl_seconds']);
    expect(d.agent_template.members.find((m) => m.member === 'subject').value).toBe(A);
    expect(d.agent_spawn).toBeNull();
  });
  it('decodes the Agent Spawn extension on the child (§10.5)', async () => {
    const d = await describeCertificate(read('agent-b.crt'));
    expect(d.agent_spawn.members.find((m) => m.member === 'parent_agent_id').value).toBe(A);
    expect(d.extensions.find((e) => e.oid === SPAWN_EXT_OID).critical).toBe(true);
  });
  it('describes, rather than refuses, a template that is not JCS — and says why', async () => {
    const d = await describeCertificate(read('bad-jcs.crt'));
    expect(d.agent_template.problem).toMatch(/not JCS/);
    expect(d.extensions.find((e) => e.oid === TEMPLATE_EXT_OID).views.conformant_validator).toMatch(/refused/);
  });
  it('decodes the CA name constraints, including the permitted dirName subtree', async () => {
    const d = await describeCertificate(read('ca-root.crt'));
    const nc = d.extensions.find((e) => e.name === 'nameConstraints');
    expect(nc.critical).toBe(true);
    expect(nc.value.permitted.find((p) => p.kind === 'dirName').value).toContain('OU=DEMO ONLY - NOT FOR PRODUCTION');
    expect(nc.value.permitted.some((p) => p.kind === 'dNSName' && p.value === '.invalid')).toBe(true);
  });
  it('shows CA:TRUE with pathlen on the root, and keyUsage bits for a CA', async () => {
    const d = await describeCertificate(read('ca-root.crt'));
    expect(d.extensions.find((e) => e.name === 'basicConstraints').summary).toBe('CA:TRUE, pathlen:0');
    expect(d.extensions.find((e) => e.name === 'keyUsage').value).toEqual(['keyCertSign', 'cRLSign']);
  });
  it('renders the demo notice as readable text, non-critical, under the corrected OID', async () => {
    const d = await describeCertificate(read('agent-a.crt'));
    const notice = d.extensions.find((e) => e.oid === DEMO_NOTICE_OID);
    expect(notice.critical).toBe(false);
    expect(notice.summary).toContain('demonstration only');
  });
  it('flags a critical extension it cannot honour', async () => {
    const d = await describeCertificate(read('critical-demo-ext.crt'));
    expect(d.extensions.find((e) => e.oid === DEMO_NOTICE_OID).critical).toBe(true);
  });
});

describe('describeName', () => {
  it('preserves RDN order and maps OIDs to short names', () => {
    const n = describeName(parseCertificate(read('agent-a.crt')).subject);
    expect(n.rfc4514).toBe(`C=US, O=PhalanxAI A2A Playground, OU=DEMO ONLY - NOT FOR PRODUCTION, CN=${A}`);
  });
});

describe('VALIDATION_STEPS documents the real sequence', () => {
  it('is numbered, ordered and complete', () => {
    expect(VALIDATION_STEPS.map((s) => s.n)).toEqual(VALIDATION_STEPS.map((_, i) => i + 1));
    expect(VALIDATION_STEPS.map((s) => s.check)).toContain('agent_template');
    expect(VALIDATION_STEPS.map((s) => s.check)).toContain('revocation_source');
  });
  it('names error codes that actually exist', () => {
    for (const s of VALIDATION_STEPS) {
      for (const code of s.on_failure.split(' / ')) expect(ERRORS[code], code).toBeTruthy();
    }
  });
  it('parses the extension AFTER the signature, as §8.2 recommends', () => {
    const at = (c) => VALIDATION_STEPS.findIndex((s) => s.check === c);
    expect(at('signature')).toBeLessThan(at('agent_template'));
    expect(at('name_constraints')).toBeGreaterThan(at('signature'));
  });
});

describe('OID normalisation — large arcs', () => {
  it('decodes a 2.25 UUID arc as base-128, not as a big-endian integer', () => {
    expect(normalizeOid('2.25.{035f4d6f7a7d027223711b224f113d10242d3b}')).toBe(TEMPLATE_EXT_OID);
  });
  it('leaves ordinary OIDs untouched', () => expect(normalizeOid('2.5.29.19')).toBe('2.5.29.19'));
  it('reports the profile OIDs identically for OpenSSL-built and browser-minted certs', async () => {
    const id = '019b3c8e-2f10-7a4b-9c6d-3e5f7a9b1c2d';
    const minted = await mintChain({ parent: templateFor({ subject: id, scopes: ['a:b'], permittedOperations: ['spawn'] }) });
    const mine = (await describeCertificate(minted.agents[0].cert_pem)).extensions.map((e) => e.oid);
    const theirs = (await describeCertificate(read('agent-a.crt'))).extensions.map((e) => e.oid);
    expect(mine).toContain(TEMPLATE_EXT_OID);
    expect(theirs).toContain(TEMPLATE_EXT_OID);
    expect(mine).toContain(DEMO_NOTICE_OID);
    expect(theirs).toContain(DEMO_NOTICE_OID);
  });
});

// ── Lenient decoding: the view shows what is there even when x509.js refuses it ──
describe('what the view says about extensions the validator refuses', () => {
  const withTemplateBytes = async (bytes) => {
    const cert = parseCertificate(read('agent-a.crt'));
    replaceExtension(cert, TEMPLATE_EXT_OID,
      new Extension({ extnID: TEMPLATE_EXT_OID, critical: true, extnValue: bytes.buffer }));
    return resign(cert, read('ca-root.key'));
  };
  it('names a duplicate member, and bytes that are not UTF-8 JSON', async () => {
    let d = await describeCertificate(await withTemplateBytes(new TextEncoder().encode('{"a":1,"a":2}')));
    expect(d.agent_template.problem).toBe('duplicate member name');
    d = await describeCertificate(await withTemplateBytes(new Uint8Array([0xff, 0xfe])));
    expect(d.agent_template.problem).toBe('not valid UTF-8 JSON');
  });
  it('an extension whose value cannot be decoded is still listed, and says so', async () => {
    const cert = parseCertificate(read('agent-a.crt'));
    replaceExtension(cert, '2.5.29.19',
      new Extension({ extnID: '2.5.29.19', critical: true, extnValue: new Uint8Array([0xff]).buffer }));
    const d = await describeCertificate(await toPem(cert));
    expect(d.extensions.find((x) => x.oid === '2.5.29.19').summary).toBe('present, could not be decoded');
  });
});
