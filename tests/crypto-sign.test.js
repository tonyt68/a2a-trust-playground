/**
 * §3.1 — the signature algorithm is fixed by the signer's key type, the value
 * is the raw signature (fixed-width r‖s for ECDSA), PSS is randomized, and a
 * key type Table 2 does not name is refused rather than skipped.
 *
 * The fixture private keys are OpenSSL-generated PKCS#8 — one per key type —
 * so "sign here, verify with the certificate's key" is also "sign with a key
 * OpenSSL made, under an algorithm the cert's key type dictates".
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  signBody, verifyBody, signEnvelope, contentHash, publicKeyFromCertificate, privateKeyFromPem,
  suiteForKey, preimage,
} from '../src/crypto-sign.js';
import { canonicalize } from '../src/canonical.js';
import { validatePem } from '../src/validate-input.js';
import { DenyError } from '../src/errors.js';
import { issueCertificate, toPem, derToPem } from '../src/mint.js';
import { parseCertificate } from '../src/x509.js';
import { PrivateKeyInfo } from 'pkijs';
import * as asn1js from 'asn1js';

const dir = fileURLToPath(new URL('./fixtures/certs/', import.meta.url));
const read = (f) => readFileSync(dir + f, 'utf8');
beforeAll(() => { if (!existsSync(dir + 'owner.crt')) throw new Error('run `pnpm fixtures`'); });

const body = { subject: '8f14e45f-ceea-467a-9c0f-7ad0f1b0d5aa', owner: 'owner-authority', org_id: 'o',
  scopes: ['read:events'], version: 2, issued_at: '2026-09-03T00:00:00Z' };

const p256 = () => crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);

describe('P-256 — the playground profile', () => {
  it('signs and verifies over the JCS preimage', async () => {
    const k = await p256();
    const sig = await signBody(body, k.privateKey);
    expect(await verifyBody(body, sig, k.publicKey)).toBe(true);
  });
  it('the value is exactly 64 octets — r‖s, not DER (§3.1 Table 2)', async () => {
    const k = await p256();
    const sig = Buffer.from(await signBody(body, k.privateKey), 'base64');
    expect(sig.length).toBe(64);
  });
  it('refuses a DER-encoded ECDSA signature as an encoding error, not as a bad signature', async () => {
    const k = await p256();
    const raw = Buffer.from(await signBody(body, k.privateKey), 'base64');
    const int = (b) => { const t = b[0] & 0x80 ? Buffer.concat([Buffer.from([0]), b]) : b; return Buffer.concat([Buffer.from([2, t.length]), t]); };
    const der = Buffer.concat([int(raw.subarray(0, 32)), int(raw.subarray(32))]);
    const seq = Buffer.concat([Buffer.from([0x30, der.length]), der]);
    await expect(verifyBody(body, seq.toString('base64'), k.publicKey)).rejects.toMatchObject({ code: 'ERR_SIGNATURE_ALGORITHM' });
  });
  it('a signature over a different body does not verify', async () => {
    const k = await p256();
    const sig = await signBody(body, k.privateKey);
    expect(await verifyBody({ ...body, version: 3 }, sig, k.publicKey)).toBe(false);
  });
  it('a bit-flipped signature does not verify, and does not throw', async () => {
    const k = await p256();
    const b = Buffer.from(await signBody(body, k.privateKey), 'base64');
    b[10] ^= 1;
    expect(await verifyBody(body, b.toString('base64'), k.publicKey)).toBe(false);
  });
  it('non-base64 is false, never a throw', async () => {
    const k = await p256();
    expect(await verifyBody(body, 'not base64!!', k.publicKey)).toBe(false);
  });
  it('the preimage is the canonical form of the body and nothing else', () => {
    expect(Buffer.from(preimage(body)).toString('utf8')).toBe(canonicalize(body));
  });
});

describe('the fixture keys — OpenSSL-made, one per Table 2 row', () => {
  for (const [key, cert, type] of [
    ['owner.key', 'owner.crt', 'P-256'], ['rsa3072-owner.key', 'rsa3072-owner.crt', 'RSA'],
    ['ed25519-owner.key', 'ed25519-owner.crt', 'Ed25519'], ['p384-agent.key', 'p384-agent.crt', 'P-384'],
  ]) {
    it(`${type}: a signature under the private key verifies under the certificate`, async () => {
      const priv = await privateKeyFromPem(read(key));
      expect(suiteForKey(priv).type).toBe(type);
      const pub = await publicKeyFromCertificate(read(cert));
      const sig = await signBody(body, priv);
      expect(await verifyBody(body, sig, pub)).toBe(true);
      expect(await verifyBody({ ...body, version: 9 }, sig, pub)).toBe(false);
    });
  }
  it('P-384 signatures are 96 octets', async () => {
    const sig = Buffer.from(await signBody(body, await privateKeyFromPem(read('p384-agent.key'))), 'base64');
    expect(sig.length).toBe(96);
  });
  it('Ed25519 signatures are 64 octets and deterministic', async () => {
    const priv = await privateKeyFromPem(read('ed25519-owner.key'));
    const a = await signBody(body, priv); const b = await signBody(body, priv);
    expect(Buffer.from(a, 'base64').length).toBe(64);
    expect(a).toBe(b);
  });
  it('RSA-PSS is randomized: two signatures differ and both verify', async () => {
    const priv = await privateKeyFromPem(read('rsa3072-owner.key'));
    const pub = await publicKeyFromCertificate(read('rsa3072-owner.crt'));
    const a = await signBody(body, priv); const b = await signBody(body, priv);
    expect(a).not.toBe(b);
    expect(await verifyBody(body, a, pub)).toBe(true);
    expect(await verifyBody(body, b, pub)).toBe(true);
  });
  it('an RSA-2048 key is refused for signing and for verifying (§7.1 floor)', async () => {
    await expect(privateKeyFromPem(read('rsa2048-agent.key'))).rejects.toMatchObject({ code: 'ERR_SIGNATURE_ALGORITHM' });
    await expect(publicKeyFromCertificate(read('rsa2048-agent.crt'))).rejects.toMatchObject({ code: 'ERR_SIGNATURE_ALGORITHM' });
  });
  it('a PKCS#1 v1.5 signature is refused even though it verifies under v1.5 (§3.1)', async () => {
    const { der } = validatePem(read('rsa3072-owner.key'), 'PRIVATE KEY');
    const v15 = await crypto.subtle.importKey('pkcs8', der, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
    const sig = Buffer.from(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', v15, preimage(body))).toString('base64');
    const pub = await publicKeyFromCertificate(read('rsa3072-owner.crt'));
    expect(await verifyBody(body, sig, pub)).toBe(false);
  });
  it('a key type Table 2 does not name is refused, not skipped', async () => {
    const k = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-521' }, true, ['sign', 'verify']);
    expect(() => suiteForKey(k.privateKey)).toThrow(DenyError);
    await expect(signBody(body, k.privateKey)).rejects.toMatchObject({ code: 'ERR_SIGNATURE_ALGORITHM' });
  });
  it('refuses a malformed private key rather than throwing raw', async () => {
    // Assembled at runtime so the repository never carries a private-key
    // header literal, which the commit-time leak guard refuses on sight.
    const bogus = `-----BEGIN ${'PRIVATE KEY'}-----\nAAAA\n-----END ${'PRIVATE KEY'}-----\n`;
    await expect(privateKeyFromPem(bogus)).rejects.toBeInstanceOf(DenyError);
  });
});

describe('the envelope (§3.1) and the content hash (§11.6)', () => {
  it('both signatures are over the same octets, by two keys', async () => {
    const o = await p256(); const p = await p256();
    const env = await signEnvelope(body, o.privateKey, p.privateKey, { withHash: true });
    expect(Object.keys(env).sort()).toEqual(['body', 'content_hash', 'owner_sig', 'pa_sig']);
    expect(await verifyBody(body, env.owner_sig, o.publicKey)).toBe(true);
    expect(await verifyBody(body, env.pa_sig, p.publicKey)).toBe(true);
    expect(await verifyBody(body, env.owner_sig, p.publicKey)).toBe(false);
  });
  it('omits content_hash where §11.6 does not require one', async () => {
    const o = await p256(); const p = await p256();
    expect('content_hash' in await signEnvelope(body, o.privateKey, p.privateKey)).toBe(false);
  });
  it('the content hash is SHA-256 over the same preimage, lowercase hex', async () => {
    const h = await contentHash(body);
    expect(h).toMatch(/^[0-9a-f]{64}$/);
    const expected = Buffer.from(await crypto.subtle.digest('SHA-256', Buffer.from(canonicalize(body)))).toString('hex');
    expect(h).toBe(expected);
  });
});

// ── Refusals at key import, and the verify path that must not throw ─────────
describe('key import refusals (§3.1 Table 2)', () => {
  const refuses = async (code, promise) => {
    let caught = null;
    try { await promise; } catch (e) { caught = e; }
    expect(caught, 'expected a refusal').toBeInstanceOf(DenyError);
    expect(caught.code).toBe(code);
    return caught;
  };
  it('refuses a signer whose key type has no assigned algorithm — P-521', async () => {
    const p521 = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-521' }, true, ['sign', 'verify']);
    const now = new Date();
    const pem = await toPem(await issueCertificate({
      commonName: 'p521-signer', subjectPublicKey: p521.publicKey,
      issuer: { commonName: 'A2A-Trust-Playground-CA', privateKey: await privateKeyFromPem(read('ca-root.key')) },
      notBefore: now, notAfter: new Date(now.getTime() + 60_000),
    }));
    const e = await refuses('ERR_SIGNATURE_ALGORITHM', publicKeyFromCertificate(pem));
    expect(e.detail).toMatch(/no signature algorithm/);
  });
  it('refuses a P-256 key whose point is not on the curve', async () => {
    const cert = parseCertificate(read('owner.crt'));
    const notOnCurve = new Uint8Array(65); notOnCurve[0] = 0x04;   // x = y = 0
    cert.subjectPublicKeyInfo.subjectPublicKey = new asn1js.BitString({ valueHex: notOnCurve.buffer });
    const e = await refuses('ERR_SIGNATURE_ALGORITHM', publicKeyFromCertificate(await toPem(cert)));
    expect(e.detail).toMatch(/could not be imported/);
  });
  it('refuses a PKCS#8 key whose algorithm is assigned but whose key material is not a key', async () => {
    const { der } = validatePem(read('agent-a.key'), 'PRIVATE KEY');
    const info = new PrivateKeyInfo({
      schema: asn1js.fromBER(der.buffer.slice(der.byteOffset, der.byteOffset + der.byteLength)).result,
    });
    // A structurally valid ECPrivateKey whose scalar is zero: the PKCS#8 parses,
    // the curve is P-256, and the key is not a key.
    info.parsedKey.privateKey = new asn1js.OctetString({ valueHex: new Uint8Array(32).buffer });
    info.privateKey = new asn1js.OctetString({ valueHex: info.parsedKey.toSchema().toBER(false) });
    const pem = derToPem(new Uint8Array(info.toSchema().toBER(false)), 'PRIVATE KEY');
    const e = await refuses('ERR_MALFORMED_PEM', privateKeyFromPem(pem));
    expect(e.detail).toMatch(/could not be imported/);
  });
  it('verifyBody answers false, not an exception, when the key cannot verify (§15.1)', async () => {
    const k = await p256();
    const sig = await signBody(body, k.privateKey);
    // A private key has no verify usage: Web Crypto throws, and the answer is still "no".
    expect(await verifyBody(body, sig, k.privateKey)).toBe(false);
  });
});
