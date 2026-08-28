/**
 * RSA-SHA256 signing and verification over canonical JSON (§9.3).
 *
 * This is the interoperability seam. `policy_validator.py` verifies by shelling
 * out to OpenSSL:
 *
 *     openssl x509 -in cert.crt -pubkey -noout > pub.pem
 *     openssl dgst -sha256 -verify pub.pem -signature sig.bin data.dat
 *
 * `openssl dgst -sha256 -sign` produces a PKCS#1 v1.5 signature over a SHA-256
 * digest. The Web Crypto equivalent is exactly `RSASSA-PKCS1-v1_5` with
 * `SHA-256` — not RSA-PSS, which is also RSA-with-SHA-256 and is what a reader
 * skimming for "modern" would reach for. PSS is randomised and produces a
 * different signature every time; OpenSSL's `dgst -verify` would reject it and
 * the failure would look like a key mismatch rather than an algorithm mismatch.
 *
 * ── What is actually signed ────────────────────────────────────────────────
 *
 * Not the metadata document. A FILTERED SUBSET of it, serialised canonically:
 *
 *     owner_sig = RSA-SHA256( canonicalize( identity fields of the cert ) )
 *     pa_sig    = RSA-SHA256( canonicalize( policy fields of the update  ) )
 *
 * Two signatures over two disjoint-but-for-`owner` field sets, by two different
 * keys. That is the whole mechanism of §9.3: the Owner attests that identity has
 * not moved, the Policy Authority authorises the policy change, and neither can
 * do the other's job. Signing the whole document with one key would be a
 * different, weaker scheme that happens to also involve RSA.
 *
 * Every byte of the signed input comes from `canonical.js`. If that module and
 * Python's `json.dumps` disagree by one character, every signature here fails
 * verification and looks like a crypto bug. It is not; it is a serialisation
 * bug, which is why canonicalisation was built and proven first.
 */

import { canonicalize } from './canonical.js';
import { parseCertificate } from './x509.js';
import { validatePem } from './validate-input.js';
import { DenyError } from './errors.js';

/** Matches `openssl dgst -sha256 -sign`. */
const ALGORITHM = Object.freeze({ name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' });

const encoder = new TextEncoder();

/** Base64 -> bytes, strictly. A signature that is not valid base64 is a DENY, not a retry. */
function decodeBase64(b64, field) {
  if (typeof b64 !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(b64) || b64.length % 4 !== 0) {
    throw new DenyError('ERR_SCHEMA_VIOLATION', `${field} is not valid base64`);
  }
  try {
    return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  } catch {
    throw new DenyError('ERR_SCHEMA_VIOLATION', `${field} could not be decoded`);
  }
}

function encodeBase64(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

/**
 * The public key from a certificate, ready to verify with.
 *
 * PKI.js's `getPublicKey` is used rather than reaching into the SPKI bytes: it
 * applies the algorithm parameters the certificate declares, which is the same
 * thing `openssl x509 -pubkey` does before handing the key to `dgst -verify`.
 */
export async function publicKeyFromCertificate(certPem) {
  const cert = parseCertificate(certPem);
  try {
    return await cert.getPublicKey({ algorithm: { algorithm: ALGORITHM, usages: ['verify'] } });
  } catch {
    throw new DenyError('ERR_CHAIN_INVALID', 'certificate public key could not be imported');
  }
}

/** Import a PKCS#8 private key. Only the playground's own generated keys reach this. */
export async function privateKeyFromPem(keyPem) {
  const { der } = validatePem(keyPem, 'PRIVATE KEY');
  try {
    return await crypto.subtle.importKey('pkcs8', der, ALGORITHM, false, ['sign']);
  } catch {
    throw new DenyError('ERR_MALFORMED_PEM', 'private key could not be imported (expected PKCS#8)');
  }
}

/**
 * Sign a canonical string. Returns base64, matching what the metadata document
 * carries and what `policy_validator.py` base64-decodes before verifying.
 */
export async function signCanonical(canonicalString, privateKey) {
  const sig = await crypto.subtle.sign(ALGORITHM, privateKey, encoder.encode(canonicalString));
  return encodeBase64(new Uint8Array(sig));
}

/**
 * Verify a base64 signature over a canonical string.
 *
 * Returns a boolean rather than throwing: the caller decides which §9.3 phase
 * failed and therefore which error code applies. Any internal failure is `false`
 * — an exception during verification must never become a pass (§13.1).
 */
export async function verifyCanonical(canonicalString, signatureB64, publicKey) {
  let sig;
  try {
    sig = decodeBase64(signatureB64, 'signature');
  } catch {
    return false;
  }
  try {
    return await crypto.subtle.verify(ALGORITHM, publicKey, sig, encoder.encode(canonicalString));
  } catch {
    return false;
  }
}

/**
 * Sign a field subset the way §9.3 does: filter, canonicalise, sign.
 * The filter is applied here rather than by the caller so the bytes that get
 * signed and the bytes that get verified are produced by one code path.
 */
export async function signFieldSet(document, extractor, privateKey) {
  return signCanonical(canonicalize(extractor(document)), privateKey);
}

/** The verification counterpart of `signFieldSet`. */
export async function verifyFieldSet(document, extractor, signatureB64, publicKey) {
  return verifyCanonical(canonicalize(extractor(document)), signatureB64, publicKey);
}
