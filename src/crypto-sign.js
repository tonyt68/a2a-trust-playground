/**
 * Envelope signatures — §3.1.
 *
 * Every signature and the content hash are computed over ONE octet string: the
 * JCS serialization of `body`, and nothing else. The algorithm is not carried in
 * the envelope; it is fixed by the type of the signer's public key, read from a
 * certificate the relying party has already validated:
 *
 *   RSA, 3072+   RSASSA-PSS, SHA-256, MGF1-SHA-256, salt 32   PSS octets
 *   EC P-256     ECDSA with SHA-256                           r‖s, 64 octets
 *   EC P-384     ECDSA with SHA-384                           r‖s, 96 octets
 *   Ed25519      Ed25519 (PureEdDSA)                          64 octets
 *
 * A signature under any other key type, or in any other encoding, is refused
 * rather than skipped — a relying party that does not recognise a key type
 * refuses (§19.9), which is the fail-closed outcome.
 *
 * ── Two things the previous design got the other way round ─────────────────
 *
 * It used RSASSA-PKCS1-v1_5 because that is what `openssl dgst -sign` produces
 * and the round-trip proof compared signature octets. §3.1 chooses PSS, which
 * is randomized: the same key and body sign to different octets every time. So
 * a test vector VERIFIES a signature and never byte-compares it, and the
 * one-key-two-roles rule compares public keys, not signature octets — equal
 * signatures would never be observed even when one key holds both roles.
 *
 * Web Crypto's ECDSA output is already the fixed-width r‖s concatenation the
 * draft requires, not DER. That is the one place the platform's default and the
 * specification agree without conversion, and it is checked by length rather
 * than assumed.
 */

import * as asn1js from 'asn1js';
import { PrivateKeyInfo } from 'pkijs';
import { canonicalize } from './canonical.js';
import { parseCertificate, publicKeyInfo, MIN_RSA_BITS, OID } from './x509.js';
import { validatePem, decodeBase64Strict } from './validate-input.js';
import { DenyError } from './errors.js';
import { bytesToHex, bytesToBase64 } from './encoding.js';

const encoder = new TextEncoder();

/** §3.1 Table 2, as Web Crypto parameters. */
const SUITES = Object.freeze({
  'RSA':     { importAlg: { name: 'RSA-PSS', hash: 'SHA-256' }, signAlg: { name: 'RSA-PSS', saltLength: 32 }, label: 'RSASSA-PSS with SHA-256' },
  'P-256':   { importAlg: { name: 'ECDSA', namedCurve: 'P-256' }, signAlg: { name: 'ECDSA', hash: 'SHA-256' }, length: 64, label: 'ECDSA with SHA-256, r‖s' },
  'P-384':   { importAlg: { name: 'ECDSA', namedCurve: 'P-384' }, signAlg: { name: 'ECDSA', hash: 'SHA-384' }, length: 96, label: 'ECDSA with SHA-384, r‖s' },
  'Ed25519': { importAlg: { name: 'Ed25519' }, signAlg: { name: 'Ed25519' }, length: 64, label: 'Ed25519' },
});

/** Which suite a CryptoKey belongs to, from the key's own algorithm. */
export function suiteForKey(key) {
  const a = key?.algorithm ?? {};
  if (a.name === 'RSA-PSS') {
    if ((a.modulusLength ?? 0) < MIN_RSA_BITS) {
      throw new DenyError('ERR_SIGNATURE_ALGORITHM', `RSA-${a.modulusLength} is below the ${MIN_RSA_BITS}-bit floor`);
    }
    return { type: 'RSA', ...SUITES.RSA, length: a.modulusLength / 8 };
  }
  if (a.name === 'ECDSA' && a.namedCurve === 'P-256') return { type: 'P-256', ...SUITES['P-256'] };
  if (a.name === 'ECDSA' && a.namedCurve === 'P-384') return { type: 'P-384', ...SUITES['P-384'] };
  if (a.name === 'Ed25519') return { type: 'Ed25519', ...SUITES.Ed25519 };
  throw new DenyError('ERR_SIGNATURE_ALGORITHM', `no signature algorithm is assigned to a ${a.name ?? 'unknown'} key`);
}

/**
 * The public key from a certificate, imported under the suite its type
 * dictates. The certificate is expected to have been validated to a trust
 * anchor already (§9.2) — this only reads the key.
 */
export async function publicKeyFromCertificate(certPem) {
  const cert = parseCertificate(certPem);
  const info = publicKeyInfo(cert);
  const type = info.type === 'EC' ? info.curve : info.type;
  const suite = SUITES[type];
  if (!suite) {
    throw new DenyError('ERR_SIGNATURE_ALGORITHM',
      `no signature algorithm is assigned to the signer's key type (${info.type ?? 'unknown'})`);
  }
  if (type === 'RSA' && info.bits < MIN_RSA_BITS) {
    throw new DenyError('ERR_SIGNATURE_ALGORITHM', `RSA-${info.bits} is below the ${MIN_RSA_BITS}-bit floor`);
  }
  const spki = cert.subjectPublicKeyInfo.toSchema().toBER(false);
  try {
    return await crypto.subtle.importKey('spki', spki, suite.importAlg, false, ['verify']);
  } catch {
    throw new DenyError('ERR_SIGNATURE_ALGORITHM', 'the signer public key could not be imported for its assigned algorithm');
  }
}

/**
 * Import a PKCS#8 private key under the suite its algorithm identifier
 * dictates. Only the playground's own generated keys reach this.
 */
export async function privateKeyFromPem(keyPem) {
  const { der } = validatePem(keyPem, 'PRIVATE KEY');
  let alg;
  try {
    const asn1 = asn1js.fromBER(der.buffer.slice(der.byteOffset, der.byteOffset + der.byteLength));
    if (asn1.offset === -1) throw new Error('bad BER');
    const info = new PrivateKeyInfo({ schema: asn1.result });
    const id = info.privateKeyAlgorithm.algorithmId;
    if (id === OID.rsaEncryption) alg = SUITES.RSA.importAlg;
    else if (id === OID.ed25519) alg = SUITES.Ed25519.importAlg;
    else if (id === OID.ecPublicKey) {
      const curve = String(info.privateKeyAlgorithm.algorithmParams?.valueBlock?.toString() ?? '');
      alg = curve === OID.p256 ? SUITES['P-256'].importAlg
        : curve === OID.p384 ? SUITES['P-384'].importAlg : null;
    }
  } catch {
    alg = null;
  }
  if (!alg) throw new DenyError('ERR_MALFORMED_PEM', 'private key algorithm is not one Table 2 assigns');
  try {
    const key = await crypto.subtle.importKey('pkcs8', der, alg, false, ['sign']);
    suiteForKey(key);   // an RSA key below the floor is refused here, not at first use
    return key;
  } catch (e) {
    if (e instanceof DenyError) throw e;
    throw new DenyError('ERR_MALFORMED_PEM', 'private key could not be imported (expected PKCS#8)');
  }
}

/** The preimage: JCS of the body, UTF-8. One function, so signing and verifying cannot drift. */
export function preimage(body) {
  return encoder.encode(canonicalize(body));
}

/**
 * Sign a body. Returns base64 of the raw signature value, no PEM framing, per
 * §3.1. The body is signed WHOLE; callers establish its membership first.
 */
export async function signBody(body, privateKey) {
  const suite = suiteForKey(privateKey);
  const sig = await crypto.subtle.sign(suite.signAlg, privateKey, preimage(body));
  return bytesToBase64(new Uint8Array(sig));
}

/**
 * Verify a base64 signature over a body under a public key.
 *
 * A signature of the wrong LENGTH for the key type is refused as an encoding
 * error (§3.1: ECDSA values are fixed-width, not DER) rather than reported as
 * a bad signature. Everything else that fails is `false` — an exception during
 * verification must never become a pass (§15.1).
 */
export async function verifyBody(body, signatureB64, publicKey) {
  const suite = suiteForKey(publicKey);
  let sig;
  try {
    sig = decodeBase64Strict(signatureB64, 'signature');
  } catch {
    return false;
  }
  if (sig.length !== suite.length) {
    throw new DenyError('ERR_SIGNATURE_ALGORITHM',
      `signature is ${sig.length} octets; ${suite.label} produces exactly ${suite.length}`);
  }
  try {
    return await crypto.subtle.verify(suite.signAlg, publicKey, sig, preimage(body));
  } catch {
    return false;
  }
}

/** §11.6 — SHA-256 over the same preimage as the signatures, lowercase hex. */
export async function contentHash(body) {
  const digest = await crypto.subtle.digest('SHA-256', preimage(body));
  return bytesToHex(new Uint8Array(digest));
}

/**
 * Wrap a body in a §3.1 envelope: both signatures over the same JCS octets,
 * and the content hash where §11.6 requires one (policies) and not where it
 * does not (grants, templates).
 */
export async function signEnvelope(body, ownerKey, paKey, { withHash = false } = {}) {
  const envelope = {
    body,
    owner_sig: await signBody(body, ownerKey),
    pa_sig: await signBody(body, paKey),
  };
  if (withHash) envelope.content_hash = await contentHash(body);
  return envelope;
}
