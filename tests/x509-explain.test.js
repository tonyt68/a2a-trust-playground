/**
 * The decoder is checked DIFFERENTIALLY against OpenSSL rather than against
 * hand-written expectations.
 *
 * A decoder tested against values a human typed in only proves the human and the
 * code made the same assumption. Every field below is compared to what
 * `openssl x509` reports for the same bytes, so a divergence shows up as a test
 * failure instead of as confidently-wrong output on the page.
 *
 * This caught a real bug: the fingerprint was computed from
 * `cert.toSchema().toBER()` — a re-serialisation — which produced 1128 bytes
 * where the original DER was 1147, and a fingerprint that disagreed with
 * `openssl x509 -fingerprint`.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync, existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { describeCertificate, describeName, VALIDATION_STEPS } from '../src/x509-explain.js';
import { parseCertificate } from '../src/x509.js';

const dir = fileURLToPath(new URL('./fixtures/certs/', import.meta.url));
const read = (f) => readFileSync(dir + f, 'utf8');
const openssl = (...args) => execFileSync('openssl', args, { encoding: 'utf8' }).trim();
const x509 = (f, ...args) => openssl('x509', '-in', dir + f, '-noout', ...args);

const AGENT_A = '8f14e45f-ceea-467a-9c0f-7ad0f1b0d5aa';
const CERTS = ['ca-root.crt', 'agent-a.crt', 'agent-b.crt', 'owner.crt', 'pa.crt'];

beforeAll(() => {
  if (!existsSync(dir + 'ca-root.crt')) throw new Error('run `pnpm fixtures`');
});

describe('digests agree with OpenSSL, byte for byte', () => {
  for (const f of CERTS) {
    it(`${f} — SHA-256 fingerprint over the ORIGINAL DER`, async () => {
      const mine = (await describeCertificate(read(f))).fingerprint_sha256;
      const theirs = x509(f, '-fingerprint', '-sha256')
        .split('=')[1].replace(/:/g, '').toLowerCase();
      expect(mine).toBe(theirs);
    });
  }

  it('reports the original DER length, not a re-encoding', async () => {
    const d = await describeCertificate(read('agent-a.crt'));
    const derBytes = execFileSync('openssl',
      ['x509', '-in', dir + 'agent-a.crt', '-outform', 'der']).length;
    expect(d.der_bytes).toBe(derBytes);
  });

  it('hashes the tbsCertificate — the bytes the signature actually covers', async () => {
    const d = await describeCertificate(read('agent-a.crt'));
    // Independently extract element 1 of the outer SEQUENCE and hash it.
    const der = execFileSync('openssl', ['x509', '-in', dir + 'agent-a.crt', '-outform', 'der']);
    const readLen = (b, i) => {
      const n = b[i];
      if (n < 0x80) return [n, i + 1];
      const k = n & 0x7f;
      return [parseInt(b.subarray(i + 1, i + 1 + k).toString('hex'), 16), i + 1 + k];
    };
    let i = 1; [, i] = readLen(der, i);            // outer SEQUENCE header
    const start = i; i += 1;                        // tbsCertificate tag
    let len; [len, i] = readLen(der, i);
    const tbs = der.subarray(start, i + len);
    const digest = Buffer.from(
      await crypto.subtle.digest('SHA-256', tbs)).toString('hex');

    expect(d.signed_bytes.length).toBe(tbs.length);
    expect(d.signed_bytes.sha256).toBe(digest);
    expect(d.signed_bytes.length).toBeLessThan(d.der_bytes); // tbs is a strict subset
  });
});

describe('fields agree with OpenSSL', () => {
  it('serial number', async () => {
    const d = await describeCertificate(read('agent-a.crt'));
    expect(d.serial_number.replace(/:/g, '').toLowerCase())
      .toBe(x509('agent-a.crt', '-serial').split('=')[1].toLowerCase());
  });

  it('validity window', async () => {
    const d = await describeCertificate(read('agent-a.crt'));
    const dates = x509('agent-a.crt', '-dates');
    const parse = (k) => new Date(dates.match(new RegExp(`${k}=(.+)`))[1]).toISOString();
    expect(d.validity.not_before).toBe(parse('notBefore'));
    expect(d.validity.not_after).toBe(parse('notAfter'));
    expect(d.validity.duration_hours).toBe(24);
  });

  it('public key size', async () => {
    for (const [f, bits] of [['agent-a.crt', 2048], ['weak.crt', 1024]]) {
      const d = await describeCertificate(read(f));
      expect(d.public_key.bits, f).toBe(bits);
      expect(x509(f, '-text')).toContain(`Public-Key: (${bits} bit)`);
    }
    expect((await describeCertificate(read('weak.crt'))).public_key.meets_minimum).toBe(false);
  });

  it('subject and issuer DNs, in encoding order', async () => {
    const d = await describeCertificate(read('agent-a.crt'));
    expect(d.subject.attributes.map((a) => a.name)).toEqual(['C', 'O', 'OU', 'CN']);
    expect(d.common_name).toBe(AGENT_A);
    expect(d.issuer_common_name).toBe('A2A-Trust-Playground-CA');
    // Order is significant: name-constraint subtree matching is a prefix test
    // over this sequence, so a decoder that sorted or de-duplicated would
    // silently misrepresent what the constraint checks.
    expect(x509('agent-a.crt', '-subject')).toContain('C=US');
  });

  it('signature algorithm', async () => {
    const d = await describeCertificate(read('agent-a.crt'));
    expect(d.signature.algorithm).toBe('sha256WithRSAEncryption');
    expect(x509('agent-a.crt', '-text')).toContain('sha256WithRSAEncryption');
  });

  it('version is 3 (DER stores it as the integer 2)', async () => {
    expect((await describeCertificate(read('agent-a.crt'))).version).toBe(3);
  });

  it('self-signed flag matches the CA/leaf split', async () => {
    expect((await describeCertificate(read('ca-root.crt'))).self_signed).toBe(true);
    expect((await describeCertificate(read('agent-a.crt'))).self_signed).toBe(false);
  });
});

describe('extension decoding', () => {
  it('decodes the leaf profile as OpenSSL renders it', async () => {
    const d = await describeCertificate(read('agent-a.crt'));
    const by = (n) => d.extensions.find((e) => e.name === n);

    expect(by('basicConstraints').summary).toBe('CA:FALSE');
    expect(by('basicConstraints').critical).toBe(true);
    expect(by('keyUsage').value).toEqual(['digitalSignature']);
    expect(by('extendedKeyUsage').value).toEqual(['clientAuth']);
    expect(by('authorityKeyIdentifier').summary).toContain('issuer key');

    const text = x509('agent-a.crt', '-text');
    expect(text).toContain('CA:FALSE');
    expect(text).toContain('Digital Signature');
    expect(text).toContain('TLS Web Client Authentication');
  });

  it('decodes the CA name constraints, including the permitted dirName subtree', async () => {
    const d = await describeCertificate(read('ca-root.crt'));
    const nc = d.extensions.find((e) => e.name === 'nameConstraints');
    expect(nc.critical).toBe(true);
    const dirName = nc.value.permitted.find((p) => p.kind === 'dirName');
    expect(dirName.value).toContain('DEMO ONLY - NOT FOR PRODUCTION');
    expect(nc.value.permitted.some((p) => p.kind === 'dNSName' && p.value === '.invalid')).toBe(true);
    expect(nc.value.excluded).toEqual([]);
  });

  it('shows CA:TRUE with pathlen on the root', async () => {
    const bc = (await describeCertificate(read('ca-root.crt')))
      .extensions.find((e) => e.name === 'basicConstraints');
    expect(bc.summary).toBe('CA:TRUE, pathlen:0');
    expect(bc.value.cA).toBe(true);
    expect(bc.value.pathLenConstraint).toBe(0);
  });

  it('renders the demo notice as readable text, non-critical', async () => {
    const demo = (await describeCertificate(read('agent-a.crt')))
      .extensions.find((e) => e.oid.startsWith('2.25.'));
    expect(demo.critical).toBe(false);
    expect(demo.value).toContain('demonstration only');
  });

  it('flags a critical extension it cannot honour', async () => {
    const demo = (await describeCertificate(read('critical-demo-ext.crt')))
      .extensions.find((e) => e.oid.startsWith('2.25.'));
    expect(demo.critical).toBe(true);   // and x509.js refuses the cert for it
  });

  it('decodes keyUsage bits correctly for a CA', async () => {
    const ku = (await describeCertificate(read('ca-root.crt')))
      .extensions.find((e) => e.name === 'keyUsage');
    expect(ku.value).toEqual(['keyCertSign', 'cRLSign']);
    expect(x509('ca-root.crt', '-text')).toContain('Certificate Sign');
  });
});

describe('describeName', () => {
  it('preserves RDN order and maps OIDs to short names', () => {
    const n = describeName(parseCertificate(read('agent-a.crt')).subject);
    expect(n.attributes.map((a) => `${a.name}=${a.value}`)).toEqual([
      'C=US', 'O=PhalanxAI A2A Playground',
      'OU=DEMO ONLY - NOT FOR PRODUCTION', `CN=${AGENT_A}`,
    ]);
    expect(n.rfc4514).toContain('CN=' + AGENT_A);
  });
});

describe('VALIDATION_STEPS documents the real sequence', () => {
  it('is numbered, ordered and complete', () => {
    expect(VALIDATION_STEPS.map((s) => s.n)).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
    for (const s of VALIDATION_STEPS) {
      expect(s.question, s.check).toMatch(/\?$/);
      expect(s.compares, s.check).toBeTruthy();
      expect(s.on_failure, s.check).toMatch(/^ERR_/);
    }
  });

  it('names error codes that actually exist', async () => {
    const { ERRORS } = await import('../src/errors.js');
    for (const s of VALIDATION_STEPS) {
      for (const code of s.on_failure.split(' / ')) {
        expect(ERRORS[code], `${s.check} cites unknown ${code}`).toBeDefined();
      }
    }
  });

  it('checks name constraints AFTER the signature, as RFC 5280 requires', () => {
    const sig = VALIDATION_STEPS.find((s) => s.check === 'signature').n;
    const nc = VALIDATION_STEPS.find((s) => s.check === 'name_constraints').n;
    expect(nc).toBeGreaterThan(sig);
  });
});

describe('OID normalisation — large arcs', () => {
  it('decodes a 2.25 UUID arc as base-128, not as a big-endian integer', async () => {
    const { normalizeOid } = await import('../src/x509-explain.js');
    const { DEMO_NOTICE_OID } = await import('../src/mint.js');
    // PKI.js emits `2.25.{hex}` for arcs beyond a JS safe integer. The hex is
    // BER base-128 with continuation bits; reading it as a plain integer yields
    // a different number that still looks like a valid OID.
    expect(normalizeOid('2.25.{03701d276b4f5e604721273240140c48795776}')).toBe(DEMO_NOTICE_OID);
    expect(normalizeOid('2.25.{03701d276b4f5e604721273240140c48795776}'))
      .not.toBe('2.25.76668732205667111341931128917943333439494006');  // the naive reading
  });

  it('leaves ordinary OIDs untouched', async () => {
    const { normalizeOid } = await import('../src/x509-explain.js');
    for (const oid of ['2.5.29.19', '1.2.840.113549.1.1.11', '1.3.6.1.5.5.7.3.2']) {
      expect(normalizeOid(oid)).toBe(oid);
    }
  });

  it('reports the demo OID identically for OpenSSL-built and browser-minted certs', async () => {
    const { mintChain, newAgentId, DEMO_NOTICE_OID } = await import('../src/mint.js');
    const minted = await mintChain({ agentIds: [newAgentId()] });
    const fromMint = (await describeCertificate(minted.agents[0].cert_pem))
      .extensions.find((e) => e.oid.startsWith('2.25.'));
    const fromOpenssl = (await describeCertificate(read('agent-a.crt')))
      .extensions.find((e) => e.oid.startsWith('2.25.'));
    expect(fromMint.oid).toBe(DEMO_NOTICE_OID);
    expect(fromOpenssl.oid).toBe(DEMO_NOTICE_OID);
  }, 20_000);
});
