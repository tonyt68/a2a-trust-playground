/**
 * X.509 identity checks (§6) — ported from
 * ietf-a2a-trust-poc/services/mcp_server/cert_validator.py
 *
 * The reference implementation shells out to `openssl verify`, `openssl x509
 * -text` and friends, then parses the human-readable output with regexes. None
 * of that exists in a browser, so the checks are reimplemented over PKI.js and
 * Web Crypto — but the checks themselves, and the order they run in, are the
 * PoC's:
 *
 *   1. parse succeeds                      (fail-closed on anything malformed)
 *   2. subject CN matches the agent id
 *   3. chain verifies to the CA
 *   4. not self-signed                     (§6.1)
 *   5. inside its validity window
 *   6. RSA key >= 2048 bits
 *
 * Everything here is fail-closed: a check that cannot be completed is a DENY,
 * never a pass. `cert_validator.py` is explicit about this and it is the whole
 * posture of §13.1 — an exception during validation must not become an ALLOW.
 */

import * as asn1js from 'asn1js';
import { Certificate } from 'pkijs';
import { DenyError } from './errors.js';
import { validatePem } from './validate-input.js';

/** OID 2.5.4.3 — commonName. */
const OID_CN = '2.5.4.3';
/** RFC 5280 minimum for this profile; matches cert_validator.py's 2048 floor. */
export const MIN_RSA_BITS = 2048;

/**
 * Parse one PEM certificate. Input goes through the PEM contract first, so a
 * malformed block is refused before any ASN.1 parser sees it.
 */
export function parseCertificate(pem) {
  const { der } = validatePem(pem, 'CERTIFICATE');
  let cert;
  try {
    const asn1 = asn1js.fromBER(der.buffer.slice(der.byteOffset, der.byteOffset + der.byteLength));
    if (asn1.offset === -1) throw new Error('bad BER');
    cert = new Certificate({ schema: asn1.result });
  } catch {
    // The parser's message can echo attacker-controlled bytes; it never reaches
    // the page. The code and the field name are all the visitor needs.
    throw new DenyError('ERR_MALFORMED_PEM', 'certificate is not valid DER');
  }
  return cert;
}

function rdnValue(typesAndValues, oid) {
  const match = typesAndValues.find((tv) => tv.type === oid);
  return match ? String(match.value.valueBlock.value) : null;
}

export function subjectCN(cert) {
  return rdnValue(cert.subject.typesAndValues, OID_CN);
}

export function issuerCN(cert) {
  return rdnValue(cert.issuer.typesAndValues, OID_CN);
}

/**
 * §6.1 — an agent certificate is issued by the CA, never self-signed.
 *
 * Compares the full issuer and subject DNs, not just the CN. Comparing CNs alone
 * would call a certificate CA-signed merely because the two names differ, which
 * is the check the PoC performs and is weaker than it looks.
 */
export function isSelfSigned(cert) {
  const dn = (name) => name.typesAndValues
    .map((tv) => `${tv.type}=${String(tv.value.valueBlock.value)}`).join(',');
  return dn(cert.subject) === dn(cert.issuer);
}

export function validityWindow(cert) {
  return { notBefore: cert.notBefore.value, notAfter: cert.notAfter.value };
}

/** True when `now` is outside [notBefore, notAfter]. A cert not yet valid is as unusable as an expired one. */
export function isOutsideValidity(cert, now = new Date()) {
  const { notBefore, notAfter } = validityWindow(cert);
  return now < notBefore || now > notAfter;
}

/**
 * RSA modulus size in bits, or null when the key is not RSA.
 * Read from the modulus rather than a declared parameter, so a certificate that
 * misstates its own key size cannot talk its way past the floor.
 */
export function rsaKeyBits(cert) {
  const spki = cert.subjectPublicKeyInfo;
  if (spki.algorithm.algorithmId !== '1.2.840.113549.1.1.1') return null; // rsaEncryption
  try {
    const parsed = spki.parsedKey;
    if (!parsed?.modulus) return null;
    let bytes = new Uint8Array(parsed.modulus.valueBlock.valueHexView);
    let i = 0;
    while (i < bytes.length && bytes[i] === 0x00) i++;   // strip DER sign padding
    if (i >= bytes.length) return 0;
    const leading = bytes[i];
    let topBits = 8;
    for (let mask = 0x80; mask && !(leading & mask); mask >>= 1) topBits--;
    return (bytes.length - i - 1) * 8 + topBits;
  } catch {
    return null;
  }
}


/**
 * RFC 5280 4.2.1.9 basicConstraints.
 *
 * A certificate that does not say what it is does not get to have that guessed
 * on its behalf, and one that says it is a CA does not get used as a leaf. Both
 * were accepted before this existed: a leaf carrying `CA:TRUE` validated as a
 * normal agent, which is an agent that is structurally a certificate authority.
 * Nothing downstream would have stopped it issuing its own certificates.
 *
 * `basicConstraints` was absent from RECOGNIZED_CRITICAL_EXTENSIONS' purpose
 * entirely — that check asks "is there a critical extension I would ignore",
 * which is a different question from "is the extension I need present at all".
 * A certificate with NO basicConstraints passes the first and fails the second.
 */
export function assertBasicConstraints(cert, { mustBeCa }) {
  const ext = (cert.extensions ?? []).find((e) => e.extnID === '2.5.29.19');
  if (!ext) {
    throw new DenyError('ERR_BASIC_CONSTRAINTS',
      'certificate carries no basicConstraints — its role is unstated, so it is not assumed');
  }
  // PKI.js exposes the parsed value as `cA`; absent means FALSE per the ASN.1 default.
  const isCa = ext.parsedValue?.cA === true;
  if (mustBeCa && !isCa) {
    throw new DenyError('ERR_BASIC_CONSTRAINTS',
      'trust anchor does not assert basicConstraints CA:TRUE');
  }
  if (!mustBeCa && isCa) {
    throw new DenyError('ERR_BASIC_CONSTRAINTS',
      'agent certificate asserts CA:TRUE — an agent may not be a certificate authority');
  }
}

/**
 * Signature digest floor.
 *
 * `MIN_RSA_BITS` puts a floor under the key. This puts the matching floor under
 * the DIGEST, which was missing: a certificate signed with SHA-1 verified
 * cleanly, and SHA-1 has practical collision attacks — a chosen-prefix collision
 * lets an attacker obtain a signature over one certificate and present it as a
 * signature over another. A 2048-bit key signed with a broken hash is not a
 * 2048-bit guarantee.
 *
 * The signature verifying is not the question. WHAT it verifies over is.
 */
const STRONG_SIGNATURE_ALGORITHMS = new Set([
  '1.2.840.113549.1.1.11', // sha256WithRSAEncryption
  '1.2.840.113549.1.1.12', // sha384WithRSAEncryption
  '1.2.840.113549.1.1.13', // sha512WithRSAEncryption
  '1.2.840.113549.1.1.10', // RSASSA-PSS — digest checked by the provider
]);

export function assertStrongSignature(cert) {
  const oid = cert.signatureAlgorithm?.algorithmId;
  if (!STRONG_SIGNATURE_ALGORITHMS.has(oid)) {
    throw new DenyError('ERR_WEAK_SIGNATURE',
      `signature algorithm ${oid ?? 'unknown'} is weaker than SHA-256 with RSA`);
  }
}

/**
 * Extensions this validator understands well enough to honour.
 *
 * RFC 5280 §4.2: "A certificate-using system MUST reject the certificate if it
 * encounters a critical extension it does not recognize." That rule is the
 * reason the demo notice on generated certificates is NON-critical — marking it
 * critical would make every generated certificate unusable to every conformant
 * validator, this one included, and break the round-trip proof.
 *
 * Adding an OID here is a claim that the code below actually enforces it. Do not
 * add one to silence a rejection.
 */
const RECOGNIZED_CRITICAL_EXTENSIONS = new Set([
  '2.5.29.15', // keyUsage
  '2.5.29.17', // subjectAltName
  '2.5.29.19', // basicConstraints
  '2.5.29.30', // nameConstraints
  '2.5.29.37', // extendedKeyUsage
]);

/** RFC 5280 §4.2 — an unrecognised critical extension is a rejection, not a warning. */
export function assertCriticalExtensionsRecognized(cert) {
  for (const ext of cert.extensions ?? []) {
    if (ext.critical && !RECOGNIZED_CRITICAL_EXTENSIONS.has(ext.extnID)) {
      throw new DenyError('ERR_UNKNOWN_CRITICAL_EXT', `critical extension ${ext.extnID} is not recognised`);
    }
  }
}

/**
 * RFC 4518-style light normalisation for DN comparison: case-folded, whitespace
 * collapsed. Full DN canonicalisation is more involved than this, but the
 * attribute types in play here are all string-valued and this is the comparison
 * OpenSSL's behaviour agrees with on the profile the playground issues.
 */
const normalizeDnValue = (v) => String(v).trim().replace(/\s+/g, ' ').toLowerCase();

const rdnSequence = (name) => name.typesAndValues
  .map((tv) => ({ type: tv.type, value: normalizeDnValue(tv.value.valueBlock.value) }));

/**
 * RFC 5280 §4.2.1.10: a directoryName subtree matches when the constraint's RDN
 * sequence is an INITIAL SUBSEQUENCE of the subject's. It is a prefix test on
 * the RDN list, not a substring test on a rendered DN string.
 */
function withinDirNameSubtree(subject, constraint) {
  if (constraint.length > subject.length) return false;
  return constraint.every((c, i) => subject[i].type === c.type && subject[i].value === c.value);
}

/**
 * Enforce the issuing CA's nameConstraints against a leaf (§4.2.1.10).
 *
 * Without this the validator is strictly weaker than RFC 5280 and than OpenSSL:
 * it would accept a certificate carrying `CN=login.bank.example.com, O=Real
 * Bank` purely because the CA's signature verifies — which is exactly the
 * repurposing the constraint exists to prevent, and would hollow out the
 * demo-only inertness guarantee.
 */
export function assertNameConstraints(cert, caCert) {
  const nc = (caCert.extensions ?? []).find((e) => e.extnID === '2.5.29.30');
  if (!nc?.parsedValue) return;

  const subject = rdnSequence(cert.subject);
  const dirNameSubtrees = (list) => (list ?? [])
    .filter((st) => st.base?.type === 4)
    .map((st) => rdnSequence(st.base.value));

  for (const excluded of dirNameSubtrees(nc.parsedValue.excludedSubtrees)) {
    if (withinDirNameSubtree(subject, excluded)) {
      throw new DenyError('ERR_NAME_CONSTRAINT', 'subject is inside an excluded subtree');
    }
  }

  const permitted = dirNameSubtrees(nc.parsedValue.permittedSubtrees);
  // Only enforce when the CA actually constrains directoryName. A CA that
  // constrains solely DNS or email says nothing about DNs, and treating an empty
  // permitted-dirName list as "permit nothing" would reject every certificate.
  if (permitted.length > 0 && !permitted.some((p) => withinDirNameSubtree(subject, p))) {
    throw new DenyError('ERR_NAME_CONSTRAINT',
      'subject is outside every permitted subtree of the issuing CA');
  }
}

/**
 * Verify that `cert` was signed by `issuerCert`'s private key.
 *
 * PKI.js's own `verify()` is used rather than a hand-rolled Web Crypto call: it
 * handles the signature-algorithm mapping and the exact bytes covered by the
 * signature (the tbsCertificate), both of which are easy to get subtly wrong and
 * produce a validator that accepts forgeries.
 */
export async function isSignedBy(cert, issuerCert) {
  try {
    return await cert.verify(issuerCert);
  } catch {
    return false; // fail closed — an error verifying is never a pass
  }
}

/**
 * Full §6 identity validation, in the reference implementation's order.
 *
 * @param {object}  opts
 * @param {string}  opts.certPem   the agent certificate
 * @param {string}  opts.caPem     the trust anchor
 * @param {string}  opts.agentId   expected subject CN
 * @param {Date}    [opts.now]     injectable clock, so expiry is testable
 * @returns {Promise<{cert: Certificate, keyBits: number}>} throws DenyError on refusal
 */
export async function validateCertificate({ certPem, caPem, agentId, now = new Date() }) {
  const cert = parseCertificate(certPem);
  const ca = parseCertificate(caPem);

  // RFC 5280 §4.2 — before honouring anything in the certificate, confirm there
  // is nothing critical in it we would be silently ignoring.
  assertCriticalExtensionsRecognized(cert);


  const cn = subjectCN(cert);
  if (cn === null) {
    throw new DenyError('ERR_SUBJECT_MISMATCH', 'certificate has no common name');
  }
  if (cn !== agentId) {
    throw new DenyError('ERR_SUBJECT_MISMATCH',
      `certificate CN does not match the agent_id in the metadata`);
  }

  if (isSelfSigned(cert)) {
    throw new DenyError('ERR_SELF_SIGNED', 'subject and issuer are the same entity');
  }

  // Structure before cryptography. A signature is only as meaningful as the
  // digest that produced it and the role the certificate is entitled to claim,
  // so both are settled before `isSignedBy` is asked anything.
  //
  // Placed after the identity checks deliberately: a self-signed certificate
  // generated with `openssl req -x509` also carries CA:TRUE, and "this is
  // self-signed" (§6.1) is the more useful thing to tell someone than "this
  // asserts CA:TRUE". Both refuse; only the ordering decides which is said.
  assertStrongSignature(cert);
  assertStrongSignature(ca);
  assertBasicConstraints(cert, { mustBeCa: false });
  assertBasicConstraints(ca, { mustBeCa: true });

  if (!(await isSignedBy(cert, ca))) {
    // Distinguish "signed by someone else" from "signature does not verify":
    // the forged-issuer sabotage should name what actually happened.
    const code = issuerCN(cert) !== subjectCN(ca) ? 'ERR_FORGED_ISSUER' : 'ERR_CHAIN_INVALID';
    throw new DenyError(code, 'certificate does not verify against the trust anchor');
  }

  // §4.2.1.10 — the signature verifying only says the CA issued it. The CA's own
  // constraints say whether it was allowed to.
  assertNameConstraints(cert, ca);

  if (isOutsideValidity(cert, now)) {
    const { notBefore, notAfter } = validityWindow(cert);
    throw new DenyError('ERR_CERT_EXPIRED',
      now > notAfter
        ? `certificate expired at ${notAfter.toISOString()}`
        : `certificate is not valid until ${notBefore.toISOString()}`);
  }

  const keyBits = rsaKeyBits(cert);
  if (keyBits === null) {
    throw new DenyError('ERR_KEY_TOO_SMALL', 'certificate does not carry an RSA public key');
  }
  if (keyBits < MIN_RSA_BITS) {
    throw new DenyError('ERR_KEY_TOO_SMALL', `RSA key is ${keyBits} bits, minimum is ${MIN_RSA_BITS}`);
  }

  return { cert, keyBits };
}
