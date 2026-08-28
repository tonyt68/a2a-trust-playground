/**
 * Stage 2 — X.509 identity (§6) and the profile's inertness guarantee (AC-9).
 *
 * Fixtures are built by OpenSSL, not by the page's own generator: a validator
 * tested only against certificates it produced itself proves that two copies of
 * one bug agree. Run `pnpm fixtures` first (the pretest hook does it).
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { DenyError } from '../src/errors.js';
import {
  validateCertificate, parseCertificate, subjectCN, issuerCN,
  isSelfSigned, isSignedBy, isOutsideValidity, rsaKeyBits, MIN_RSA_BITS,
  assertCriticalExtensionsRecognized, assertNameConstraints,
  assertBasicConstraints, assertStrongSignature, parseCertificate,
} from '../src/x509.js';

const dir = fileURLToPath(new URL('./fixtures/certs/', import.meta.url));
const read = (f) => readFileSync(dir + f, 'utf8');

const AGENT_A = '8f14e45f-ceea-467a-9c0f-7ad0f1b0d5aa';
const AGENT_B = 'c669186f-a84b-4d7a-81f3-05880df87114';

let ca;
beforeAll(() => {
  if (!existsSync(dir + 'ca-root.crt')) {
    throw new Error('cert fixtures missing — run `pnpm fixtures`');
  }
  ca = read('ca-root.crt');
});

async function denies(code, fn) {
  let thrown;
  try { await fn(); } catch (e) { thrown = e; }
  expect(thrown, 'expected a DenyError, nothing was thrown').toBeDefined();
  expect(thrown, `threw ${thrown?.constructor?.name}: ${thrown?.message}`).toBeInstanceOf(DenyError);
  expect(thrown.code).toBe(code);
}

describe('parsing and field extraction', () => {
  it('reads the UUID4 subject CN', () => {
    expect(subjectCN(parseCertificate(read('agent-a.crt')))).toBe(AGENT_A);
    expect(subjectCN(parseCertificate(read('agent-b.crt')))).toBe(AGENT_B);
  });

  it('reads the issuer CN', () => {
    expect(issuerCN(parseCertificate(read('agent-a.crt')))).toBe('A2A-Trust-Playground-CA');
  });

  it('measures RSA key size from the modulus', () => {
    expect(rsaKeyBits(parseCertificate(read('agent-a.crt')))).toBe(2048);
    expect(rsaKeyBits(parseCertificate(read('weak.crt')))).toBe(1024);
  });

  it('identifies the self-signed CA and the CA-signed leaves', () => {
    expect(isSelfSigned(parseCertificate(ca))).toBe(true);
    expect(isSelfSigned(parseCertificate(read('agent-a.crt')))).toBe(false);
    expect(isSelfSigned(parseCertificate(read('selfsigned.crt')))).toBe(true);
  });

  it('refuses a malformed PEM rather than best-effort parsing', async () => {
    await denies('ERR_MALFORMED_PEM', () => parseCertificate('-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n'));
    await denies('ERR_MALFORMED_PEM', () => parseCertificate('not a pem'));
  });
});

describe('signature verification', () => {
  it('accepts the real chain', async () => {
    for (const f of ['agent-a.crt', 'agent-b.crt', 'owner.crt', 'pa.crt']) {
      expect(await isSignedBy(parseCertificate(read(f)), parseCertificate(ca)), f).toBe(true);
    }
  });

  it('rejects a certificate issued by a different CA', async () => {
    expect(await isSignedBy(parseCertificate(read('forged.crt')), parseCertificate(ca))).toBe(false);
  });

  it('rejects a self-signed agent certificate', async () => {
    expect(await isSignedBy(parseCertificate(read('selfsigned.crt')), parseCertificate(ca))).toBe(false);
  });
});

describe('full §6 validation — the happy path', () => {
  it('accepts agent-a against the CA', async () => {
    const { cert, keyBits } = await validateCertificate({
      certPem: read('agent-a.crt'), caPem: ca, agentId: AGENT_A,
    });
    expect(subjectCN(cert)).toBe(AGENT_A);
    expect(keyBits).toBeGreaterThanOrEqual(MIN_RSA_BITS);
  });

  it('accepts agent-b', async () => {
    await expect(validateCertificate({
      certPem: read('agent-b.crt'), caPem: ca, agentId: AGENT_B,
    })).resolves.toBeTruthy();
  });
});

describe('full §6 validation — every refusal', () => {
  it('ERR_SUBJECT_MISMATCH when the CN is not the agent_id', () =>
    denies('ERR_SUBJECT_MISMATCH', () => validateCertificate({
      certPem: read('agent-a.crt'), caPem: ca, agentId: AGENT_B,
    })));

  it('ERR_SELF_SIGNED for a self-signed agent cert (§6.1)', () =>
    denies('ERR_SELF_SIGNED', () => validateCertificate({
      certPem: read('selfsigned.crt'), caPem: ca, agentId: AGENT_A,
    })));

  it('ERR_FORGED_ISSUER when signed by a rogue CA', () =>
    denies('ERR_FORGED_ISSUER', () => validateCertificate({
      certPem: read('forged.crt'), caPem: ca, agentId: AGENT_A,
    })));

  it('ERR_CERT_EXPIRED for a cert outside its window', () =>
    denies('ERR_CERT_EXPIRED', () => validateCertificate({
      certPem: read('expired.crt'), caPem: ca, agentId: AGENT_A,
    })));

  it('ERR_KEY_TOO_SMALL for a 1024-bit key', () =>
    denies('ERR_KEY_TOO_SMALL', () => validateCertificate({
      certPem: read('weak.crt'), caPem: ca, agentId: AGENT_A,
    })));

  it('ERR_CERT_EXPIRED when the clock is moved past notAfter', async () => {
    const future = new Date(Date.now() + 1000 * 60 * 60 * 48); // +48h, past the 24h window
    await denies('ERR_CERT_EXPIRED', () => validateCertificate({
      certPem: read('agent-a.crt'), caPem: ca, agentId: AGENT_A, now: future,
    }));
  });

  it('ERR_CERT_EXPIRED when the clock is before notBefore', async () => {
    const past = new Date(Date.now() - 1000 * 60 * 60 * 48);
    await denies('ERR_CERT_EXPIRED', () => validateCertificate({
      certPem: read('agent-a.crt'), caPem: ca, agentId: AGENT_A, now: past,
    }));
  });
});

describe('demo-only profile (AC-9) — inert by construction', () => {
  it('issues 24-hour certificates', () => {
    const cert = parseCertificate(read('agent-a.crt'));
    const hours = (cert.notAfter.value - cert.notBefore.value) / 36e5;
    expect(hours).toBeCloseTo(24, 0);
  });

  it('marks every subject DEMO ONLY - NOT FOR PRODUCTION', () => {
    for (const f of ['ca-root.crt', 'agent-a.crt', 'agent-b.crt', 'owner.crt', 'pa.crt']) {
      const dns = parseCertificate(read(f)).subject.typesAndValues
        .map((tv) => String(tv.value.valueBlock.value));
      expect(dns, f).toContain('DEMO ONLY - NOT FOR PRODUCTION');
    }
  });

  it('carries the demo notice as a NON-critical extension', () => {
    // Critical would make the certificate unparseable to every RFC 5280
    // validator — including the reference implementation's `openssl verify`,
    // which is what the round-trip proof depends on.
    const cert = parseCertificate(read('agent-a.crt'));
    const demo = cert.extensions.find((e) => e.extnID.startsWith('2.25.'));
    expect(demo, 'demo notice extension is missing').toBeDefined();
    expect(demo.critical).toBe(false);
  });

  it('constrains the CA with a CRITICAL nameConstraints extension', () => {
    // This is where the inertness guarantee actually lives: a recognised
    // critical extension a compliant validator enforces, rather than an
    // unrecognised one it chokes on.
    const nc = parseCertificate(ca).extensions.find((e) => e.extnID === '2.5.29.30');
    expect(nc, 'nameConstraints is missing from the CA').toBeDefined();
    expect(nc.critical).toBe(true);
  });

  it('makes leaves incapable of signing other certificates', () => {
    const cert = parseCertificate(read('agent-a.crt'));
    const bc = cert.extensions.find((e) => e.extnID === '2.5.29.19');  // basicConstraints
    expect(bc.critical).toBe(true);
    expect(bc.parsedValue.cA).toBeFalsy();
  });

  it('keeps the CA self-signed and the leaves CA-signed', () => {
    expect(isSelfSigned(parseCertificate(ca))).toBe(true);
    for (const f of ['agent-a.crt', 'agent-b.crt', 'owner.crt', 'pa.crt']) {
      expect(isSelfSigned(parseCertificate(read(f))), f).toBe(false);
    }
  });
});

describe('RFC 5280 §4.2.1.10 — name constraints are enforced', () => {
  it('refuses a repurposed certificate the CA signed but was not permitted to', async () => {
    // The signature verifies — the CA really did issue it. The constraint is
    // what makes it invalid, and a validator that skips this is strictly weaker
    // than RFC 5280 and than OpenSSL.
    await denies('ERR_NAME_CONSTRAINT', () => validateCertificate({
      certPem: read('repurposed.crt'), caPem: ca, agentId: 'login.bank.example.com',
    }));
  });

  it('agrees with OpenSSL on the same certificate', async () => {
    const { execFileSync } = await import('node:child_process');
    let opensslAccepted = true;
    try {
      execFileSync('openssl', ['verify', '-CAfile', dir + 'ca-root.crt', dir + 'repurposed.crt'],
        { stdio: 'ignore' });
    } catch { opensslAccepted = false; }
    expect(opensslAccepted, 'openssl should refuse the repurposed cert').toBe(false);
  });

  it('still accepts certificates inside the permitted subtree', async () => {
    await expect(validateCertificate({
      certPem: read('agent-a.crt'), caPem: ca, agentId: AGENT_A,
    })).resolves.toBeTruthy();
  });
});

describe('RFC 5280 §4.2 — unrecognised critical extensions are rejected', () => {
  it('accepts the shipped profile, whose only unusual extension is non-critical', () => {
    for (const f of ['agent-a.crt', 'agent-b.crt', 'owner.crt', 'pa.crt', 'ca-root.crt']) {
      expect(() => assertCriticalExtensionsRecognized(parseCertificate(read(f))), f).not.toThrow();
    }
  });

  it('rejects a certificate carrying an unknown CRITICAL extension', async () => {
    // This is the check that would have made the originally-specified profile
    // unusable: a critical demo notice is rejected by every conformant
    // validator, including this one.
    const cert = parseCertificate(read('critical-demo-ext.crt'));
    expect(() => assertCriticalExtensionsRecognized(cert)).toThrow(DenyError);
    await denies('ERR_UNKNOWN_CRITICAL_EXT', () => validateCertificate({
      certPem: read('critical-demo-ext.crt'), caPem: ca, agentId: AGENT_A,
    }));
  });
});

/**
 * Structural validity, as distinct from cryptographic validity.
 *
 * Every certificate in this block VERIFIES. `openssl verify -CAfile ca-root.crt`
 * returns OK for all three — the fixture generator asserts that explicitly, so
 * the distinction is not taken on trust. Each was accepted by this validator
 * too, until the checks below existed.
 *
 * The lesson is the one the whole playground is built around: a chain that
 * verifies answers "was this issued by the CA", and nothing else. Whether the
 * certificate is entitled to be USED the way it is being used is a separate
 * question with a separate answer, and the signature does not contain it.
 */
describe('structural validity — certificates that verify but are not usable', () => {
  it('refuses an agent certificate asserting basicConstraints CA:TRUE', async () => {
    // The serious one. A leaf entitled to sign certificates is an agent that
    // can mint its own children outside the spawn rules entirely — §8.1 and
    // §8.3 both become advisory, because the agent no longer needs the CA.
    await denies('ERR_BASIC_CONSTRAINTS', () => validateCertificate({
      certPem: read('ca-true-leaf.crt'), caPem: ca, agentId: AGENT_A,
    }));
  });

  it('refuses a certificate signed with SHA-1', async () => {
    // MIN_RSA_BITS puts a floor under the key. This is the matching floor under
    // the DIGEST. SHA-1 has practical chosen-prefix collisions, so a 2048-bit
    // key signed over a broken hash is not a 2048-bit guarantee.
    await denies('ERR_WEAK_SIGNATURE', () => validateCertificate({
      certPem: read('sha1-leaf.crt'), caPem: ca, agentId: AGENT_A,
    }));
  });

  it('refuses a certificate carrying no basicConstraints at all', async () => {
    // A certificate that does not state its role does not get one assumed. The
    // critical-extension check asks "is there something critical I would
    // ignore" — a different question from "is what I need present".
    await denies('ERR_BASIC_CONSTRAINTS', () => validateCertificate({
      certPem: read('no-bc-leaf.crt'), caPem: ca, agentId: AGENT_A,
    }));
  });

  it('refuses a trust anchor that does not assert CA:TRUE', () => {
    expect(() => assertBasicConstraints(parseCertificate(read('agent-a.crt')), { mustBeCa: true }))
      .toThrow(DenyError);
  });

  it('accepts the real profile in both roles', () => {
    expect(() => assertBasicConstraints(parseCertificate(ca), { mustBeCa: true })).not.toThrow();
    expect(() => assertBasicConstraints(parseCertificate(read('agent-a.crt')), { mustBeCa: false })).not.toThrow();
    expect(() => assertStrongSignature(parseCertificate(read('agent-a.crt')))).not.toThrow();
    expect(() => assertStrongSignature(parseCertificate(ca))).not.toThrow();
  });

  it('a certificate minted in the browser satisfies both checks', async () => {
    // Parity: the checks must not be ones only OpenSSL-built fixtures pass.
    const { mintChain } = await import('../src/mint.js');
    const minted = await mintChain({ agentIds: [AGENT_A], now: new Date() });
    expect(() => assertBasicConstraints(parseCertificate(minted.ca.cert_pem), { mustBeCa: true })).not.toThrow();
    expect(() => assertBasicConstraints(parseCertificate(minted.agents[0].cert_pem), { mustBeCa: false })).not.toThrow();
    expect(() => assertStrongSignature(parseCertificate(minted.agents[0].cert_pem))).not.toThrow();
  }, 30_000);
});
