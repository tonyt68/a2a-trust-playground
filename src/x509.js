/**
 * X.509 identity checks — §7, the certificate profile of §7.1, and the two
 * extensions this profile defines: the Agent Template extension (§8.2) and the
 * Agent Spawn extension (§10.5).
 *
 * Everything here is fail-closed: a check that cannot be completed is a DENY,
 * never a pass. That is the whole posture of §15.1 — an exception during
 * validation must not become an ALLOW.
 *
 * ── Order ───────────────────────────────────────────────────────────────────
 *
 *   identity  → structure → cryptography → constraints → time → key → content
 *
 * Structure before cryptography: a signature is only as meaningful as the
 * digest that produced it and the role the certificate is entitled to claim.
 * Content last, and only after the signature has verified: §8.2 says the
 * extension is attacker-controlled input until the issuer's signature has been
 * checked, and SHOULD be parsed only afterwards. Here it is.
 *
 * ── Both extensions are CRITICAL, on purpose ────────────────────────────────
 *
 * RFC 5280 §4.2 makes any validator that does not recognise them refuse the
 * certificate. That is the fail-closed outcome §8.2 wants: an agent certificate
 * has no legitimate use outside this specification, so a stack that does not
 * implement it must refuse rather than accept an ordinary-looking client
 * certificate and grant whatever its chain would grant. It also means
 * `openssl verify` refuses these certificates by design, which is why the
 * round-trip harness parses the extensions itself rather than asking OpenSSL.
 */

import * as asn1js from 'asn1js';
import { Certificate, RSASSAPSSParams } from 'pkijs';
import { DenyError } from './errors.js';
import {
  validatePem, validateUuid, validateText, validateReference, validateScopeSet, validateInteger,
  validateTtl, validateTimestamp, validateNonce, assertFlatObject, parseJsonStrict,
  JsonSyntaxError, MAX_CHILDREN,
} from './validate-input.js';
import { canonicalize, TEMPLATE_FIELDS, SPAWN_FIELDS, SPAWN_OPTIONAL_FIELDS } from './canonical.js';
import { bytesToHex } from './encoding.js';

/** OID 2.5.4.3 — commonName. */
const OID_CN = '2.5.4.3';

/** §8.2 — the Agent Template extension. */
export const TEMPLATE_EXT_OID = '2.25.318754453516410815925104555075461256891';
/** §10.5 — the Agent Spawn extension. */
export const SPAWN_EXT_OID = '2.25.316124730704531463413455892107752909312';

/**
 * §8.2 — the limits a relying party imposes on extnValue BEFORE parsing it:
 * 16384 octets for the Agent Template extension (two hundred scopes at the
 * §10.3 maximum fit), 1024 for the Agent Spawn extension (a fixed-shape
 * object with room to spare). Stated by the draft, not chosen here.
 */
export const MAX_TEMPLATE_EXTENSION_BYTES = 16384;
export const MAX_SPAWN_EXTENSION_BYTES = 1024;
/** RFC 5280 §4.1.2.2 — a serial number is at most 20 octets. */
export const MAX_SERIAL_OCTETS = 20;

/** §7.1 — 128-bit security level (SP 800-57): RSA-3072, P-256, P-384, Ed25519. */
export const MIN_SECURITY_BITS = 128;
export const MIN_RSA_BITS = 3072;

/**
 * Every object identifier this implementation names, in one table. The signer
 * (mint.js), the envelope code (crypto-sign.js) and the validator dispatch on
 * the same strings, so a key type or extension cannot be accepted by one half
 * and unknown to the other.
 */
export const OID = Object.freeze({
  // Name attributes (RFC 4519)
  CN: '2.5.4.3', C: '2.5.4.6', O: '2.5.4.10', OU: '2.5.4.11',
  // Key types and curves (§3.1 Table 2, §7.1)
  rsaEncryption: '1.2.840.113549.1.1.1',
  rsassaPss: '1.2.840.113549.1.1.10',
  ecPublicKey: '1.2.840.10045.2.1',
  p256: '1.2.840.10045.3.1.7',
  p384: '1.3.132.0.34',
  ed25519: '1.3.101.112',
  sha256: '2.16.840.1.101.3.4.2.1',
  sha384: '2.16.840.1.101.3.4.2.2',
  sha512: '2.16.840.1.101.3.4.2.3',
  basicConstraints: '2.5.29.19',
  keyUsage: '2.5.29.15',
  nameConstraints: '2.5.29.30',
  crlDistributionPoints: '2.5.29.31',
  extKeyUsage: '2.5.29.37',
  clientAuth: '1.3.6.1.5.5.7.3.2',
  authorityInfoAccess: '1.3.6.1.5.5.7.1.1',
  ocsp: '1.3.6.1.5.5.7.48.1',
});

/**
 * PKI.js renders an OID arc it cannot hold in a JS number as `2.25.{hex…}`.
 * Both extension OIDs live under the 2.25 UUID arc and are 128 bits, so every
 * comparison against them goes through this. The hex is the arc's raw BER
 * bytes, base-128 with a continuation bit — not a big-endian integer.
 */
export function normalizeOid(oid) {
  return String(oid).replace(/\{([0-9a-fA-F]+)\}/g, (_, h) => {
    let value = 0n;
    for (let i = 0; i < h.length; i += 2) {
      value = (value << 7n) | (BigInt(parseInt(h.slice(i, i + 2), 16)) & 0x7fn);
    }
    return value.toString();
  });
}

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
  // PKI.js renders the two 2.25-arc extension OIDs as `2.25.{hex}`. Normalised
  // once here, so every later lookup is a string comparison.
  for (const ext of cert.extensions ?? []) ext.extnID = normalizeOid(ext.extnID);
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
 * §7.3 — an agent certificate is issued by the CA, never self-signed.
 * Compares the full issuer and subject DNs, not just the CN.
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

/** Extensions under `oid`. `parseCertificate` has already normalised the identifiers. */
function extensions(cert, oid) {
  return (cert.extensions ?? []).filter((e) => e.extnID === oid);
}

// ── Keys ────────────────────────────────────────────────────────────────────

function bitLength(bytes) {
  let i = 0;
  while (i < bytes.length && bytes[i] === 0x00) i++;   // strip DER sign padding
  if (i >= bytes.length) return 0;
  let topBits = 8;
  for (let mask = 0x80; mask && !(bytes[i] & mask); mask >>= 1) topBits--;
  return (bytes.length - i - 1) * 8 + topBits;
}

/** SP 800-57 Table 2 — security strength of an RSA modulus. */
function rsaSecurityBits(bits) {
  if (bits >= 15360) return 256;
  if (bits >= 7680) return 192;
  if (bits >= 3072) return 128;
  if (bits >= 2048) return 112;
  return 80;
}

/**
 * What kind of public key a certificate carries, measured from the key itself
 * rather than from anything the certificate declares about it.
 *
 * @returns {{type: string|null, curve?: string, bits: number|null, security: number|null, raw?: Uint8Array}}
 */
export function publicKeyInfo(cert) {
  const spki = cert.subjectPublicKeyInfo;
  const alg = spki.algorithm.algorithmId;
  try {
    if (alg === OID.rsaEncryption || alg === OID.rsassaPss) {
      const parsed = spki.parsedKey;
      if (!parsed?.modulus) return { type: null, bits: null, security: null };
      const bits = bitLength(new Uint8Array(parsed.modulus.valueBlock.valueHexView));
      return { type: 'RSA', bits, security: rsaSecurityBits(bits) };
    }
    if (alg === OID.ecPublicKey) {
      const params = spki.algorithm.algorithmParams;
      const curve = params?.valueBlock ? String(params.valueBlock.toString()) : null;
      if (curve === OID.p256) return { type: 'EC', curve: 'P-256', bits: 256, security: 128 };
      if (curve === OID.p384) return { type: 'EC', curve: 'P-384', bits: 384, security: 192 };
      return { type: 'EC', curve: null, bits: null, security: null };
    }
    if (alg === OID.ed25519) {
      const raw = new Uint8Array(spki.subjectPublicKey.valueBlock.valueHexView);
      return { type: 'Ed25519', bits: 256, security: 128, raw };
    }
  } catch {
    // fall through — an unreadable key is an unknown key
  }
  return { type: null, bits: null, security: null };
}

/** §7.1 — at least 128 bits of security. An RSA-2048 key is refused. */
export function assertKeyStrength(cert) {
  const info = publicKeyInfo(cert);
  if (info.type === null || info.security === null) {
    throw new DenyError('ERR_KEY_TOO_SMALL', 'public key is not RSA, P-256, P-384 or Ed25519');
  }
  if (info.security < MIN_SECURITY_BITS) {
    throw new DenyError('ERR_KEY_TOO_SMALL',
      `${info.type}-${info.bits} provides ${info.security}-bit security; ${MIN_SECURITY_BITS} is the floor`);
  }
  return info;
}

/** The DER of subjectPublicKeyInfo, hex — the thing §3.1 compares across the two authorities. */
export function spkiHex(cert) {
  return bytesToHex(new Uint8Array(cert.subjectPublicKeyInfo.toSchema().toBER(false)));
}

// ── Profile checks (§7.1) ───────────────────────────────────────────────────

/**
 * RFC 5280 4.2.1.9 basicConstraints.
 *
 * A certificate that does not say what it is does not get to have that guessed
 * on its behalf, and one that says it is a CA does not get used as a leaf. §7.1
 * states both normatively: an agent asserting cA = TRUE is an agent entitled to
 * issue its own children, which removes both checks of §10.1 from the spawn
 * path without any signature failing.
 */
export function assertBasicConstraints(cert, { mustBeCa }) {
  const ext = extensions(cert, OID.basicConstraints)[0];
  if (!ext) {
    throw new DenyError('ERR_BASIC_CONSTRAINTS',
      'certificate carries no basicConstraints — its role is unstated, so it is not assumed');
  }
  const isCa = ext.parsedValue?.cA === true;
  if (mustBeCa && !isCa) {
    throw new DenyError('ERR_BASIC_CONSTRAINTS', 'trust anchor does not assert basicConstraints CA:TRUE');
  }
  if (mustBeCa && !ext.critical) {
    throw new DenyError('ERR_BASIC_CONSTRAINTS', 'trust anchor basicConstraints is not marked critical');
  }
  if (!mustBeCa && isCa) {
    throw new DenyError('ERR_BASIC_CONSTRAINTS',
      'agent certificate asserts CA:TRUE — an agent may not be a certificate authority');
  }
}

/** RFC 5280 §4.2.1.3 bit positions. The signer sets them; the validator and the view read them. */
export const KEY_USAGE = Object.freeze({ digitalSignature: 0, keyCertSign: 5, cRLSign: 6 });
/** The nine keyUsage bits, by position — for the certificate view. */
export const KEY_USAGE_NAMES = Object.freeze([
  'digitalSignature', 'nonRepudiation', 'keyEncipherment', 'dataEncipherment', 'keyAgreement',
  'keyCertSign', 'cRLSign', 'encipherOnly', 'decipherOnly',
]);

/** The set of asserted bit positions in a keyUsage BIT STRING. Throws on an undecodable value. */
export function keyUsageBits(ext) {
  const view = new Uint8Array(ext.parsedValue.valueBlock.valueHexView);
  const unused = ext.parsedValue.valueBlock.unusedBits ?? 0;
  const total = view.length * 8 - unused;
  const set = new Set();
  for (let i = 0; i < Math.min(total, KEY_USAGE_NAMES.length); i++) {
    if (view[Math.floor(i / 8)] & (0x80 >> (i % 8))) set.add(i);
  }
  return set;
}

/**
 * §7.1 — keyUsage. An agent certificate carries it, critical, asserting
 * digitalSignature and nothing else; keyCertSign and cRLSign are refused
 * INDEPENDENTLY of basicConstraints. A CA asserts keyCertSign.
 */
export function assertKeyUsage(cert, { isCa }) {
  const ext = extensions(cert, OID.keyUsage)[0];
  if (!ext) throw new DenyError('ERR_KEY_USAGE', 'certificate carries no keyUsage extension');
  if (!ext.critical) throw new DenyError('ERR_KEY_USAGE', 'keyUsage is not marked critical');
  let bits;
  try { bits = keyUsageBits(ext); } catch {
    throw new DenyError('ERR_KEY_USAGE', 'keyUsage could not be decoded');
  }
  if (isCa) {
    if (!bits.has(KEY_USAGE.keyCertSign)) {
      throw new DenyError('ERR_KEY_USAGE', 'trust anchor does not assert keyCertSign');
    }
    return;
  }
  if (bits.has(KEY_USAGE.keyCertSign) || bits.has(KEY_USAGE.cRLSign)) {
    throw new DenyError('ERR_KEY_USAGE',
      'agent certificate asserts keyCertSign or cRLSign — an agent never issues');
  }
  if (!bits.has(KEY_USAGE.digitalSignature) || bits.size !== 1) {
    throw new DenyError('ERR_KEY_USAGE', 'keyUsage must assert digitalSignature and no other bit');
  }
}

/**
 * §7.1 — at least 64 bits of CSPRNG output in the serial. A relying party cannot
 * measure entropy, but it can measure length: a serial that fits in seven
 * octets was not produced as required.
 */
export function assertSerialEntropy(cert) {
  const bytes = new Uint8Array(cert.serialNumber.valueBlock.valueHexView);
  let i = 0;
  while (i < bytes.length - 1 && bytes[i] === 0x00) i++;   // DER sign padding
  const significant = bytes.length - i;
  if (significant < 8) {
    throw new DenyError('ERR_SERIAL_ENTROPY',
      `serial number is ${significant} octet(s); 64 bits of randomness needs eight`);
  }
}

/**
 * §7.1 — the serial is an ASN.1 INTEGER that RFC 5280 requires to be positive,
 * at most 20 octets, and in minimal DER form. The content octets are read
 * as encoded: a leading 0x00 is legal only when the octet after it has its
 * top bit set (X.690 §8.3.2), and a first octet with its top bit set is a
 * negative number.
 */
export function assertSerialEncoding(cert) {
  const bytes = new Uint8Array(cert.serialNumber.valueBlock.valueHexView);
  if (bytes.length === 0) {
    throw new DenyError('ERR_SERIAL_ENCODING', 'serial number is empty');
  }
  if (bytes.length > MAX_SERIAL_OCTETS) {
    throw new DenyError('ERR_SERIAL_ENCODING',
      `serial number is ${bytes.length} octets; RFC 5280 permits at most ${MAX_SERIAL_OCTETS}`);
  }
  if (bytes[0] & 0x80) {
    throw new DenyError('ERR_SERIAL_ENCODING', 'serial number encodes a negative INTEGER');
  }
  if (bytes.length > 1 && bytes[0] === 0x00 && !(bytes[1] & 0x80)) {
    throw new DenyError('ERR_SERIAL_ENCODING',
      'serial number carries a leading zero octet the next octet does not need — not minimal DER');
  }
}

/**
 * Signature digest floor (§7.1). The key floor is elsewhere; this puts the
 * matching floor under the DIGEST. SHA-1 has practical collision attacks, and a
 * strong key signed with a broken hash is not a strong guarantee.
 */
const STRONG_SIGNATURE_ALGORITHMS = new Set([
  '1.2.840.113549.1.1.11', // sha256WithRSAEncryption
  '1.2.840.113549.1.1.12', // sha384WithRSAEncryption
  '1.2.840.113549.1.1.13', // sha512WithRSAEncryption
  '1.2.840.10045.4.3.2',   // ecdsa-with-SHA256
  '1.2.840.10045.4.3.3',   // ecdsa-with-SHA384
  '1.2.840.10045.4.3.4',   // ecdsa-with-SHA512
  OID.ed25519,             // Ed25519 (PureEdDSA)
]);
const STRONG_DIGESTS = new Set([OID.sha256, OID.sha384, OID.sha512]);

export function assertStrongSignature(cert) {
  const oid = cert.signatureAlgorithm?.algorithmId;
  if (oid === OID.rsassaPss) {
    // The digest lives in the parameters, and RFC 4055 defaults them to SHA-1
    // when absent — so "no parameters" is a weak signature, not a neutral one.
    let hash = null;
    try {
      const params = new RSASSAPSSParams({ schema: cert.signatureAlgorithm.algorithmParams });
      hash = params.hashAlgorithm?.algorithmId ?? null;
    } catch { hash = null; }
    if (!STRONG_DIGESTS.has(hash)) {
      throw new DenyError('ERR_WEAK_SIGNATURE', 'RSASSA-PSS parameters do not name SHA-256 or stronger');
    }
    return;
  }
  if (!STRONG_SIGNATURE_ALGORITHMS.has(oid)) {
    throw new DenyError('ERR_WEAK_SIGNATURE',
      `signature algorithm ${oid ?? 'unknown'} is weaker than SHA-256`);
  }
}

/**
 * §14.4 — every certificate other than a self-signed anchor says where its
 * revocation state lives: cRLDistributionPoints, or authorityInfoAccess with
 * an id-ad-ocsp accessMethod. One that says neither is refused, because the
 * obligation to consult revocation state cannot be discharged against it.
 */
export function assertRevocationSource(cert) {
  if (extensions(cert, OID.crlDistributionPoints).length) return;
  for (const ext of extensions(cert, OID.authorityInfoAccess)) {
    const descs = ext.parsedValue?.accessDescriptions ?? [];
    if (descs.some((d) => d.accessMethod === OID.ocsp)) return;
  }
  throw new DenyError('ERR_NO_REVOCATION_SOURCE',
    'no cRLDistributionPoints and no OCSP accessMethod — revocation cannot be consulted');
}

/**
 * Extensions this validator understands well enough to honour.
 *
 * RFC 5280 §4.2: "A certificate-using system MUST reject the certificate if it
 * encounters a critical extension it does not recognize." Adding an OID here is
 * a claim that the code in this file enforces it: the two profile extensions are
 * here because `parseTemplateExtension` and `parseSpawnExtension` are that
 * enforcement. Do not add one to silence a rejection.
 */
const RECOGNIZED_CRITICAL_EXTENSIONS = new Set([
  '2.5.29.15', // keyUsage
  '2.5.29.17', // subjectAltName
  '2.5.29.19', // basicConstraints
  '2.5.29.30', // nameConstraints
  '2.5.29.37', // extendedKeyUsage
  TEMPLATE_EXT_OID,
  SPAWN_EXT_OID,
]);

/** RFC 5280 §4.2 — an unrecognised critical extension is a rejection, not a warning. */
export function assertCriticalExtensionsRecognized(cert) {
  for (const ext of cert.extensions ?? []) {
    const oid = normalizeOid(ext.extnID);
    if (ext.critical && !RECOGNIZED_CRITICAL_EXTENSIONS.has(oid)) {
      throw new DenyError('ERR_UNKNOWN_CRITICAL_EXT', `critical extension ${oid} is not recognised`);
    }
  }
}

/**
 * RFC 4518-style light normalisation for DN comparison: case-folded, whitespace
 * collapsed. The attribute types in play are all string-valued and this is the
 * comparison OpenSSL's behaviour agrees with on the profile the playground issues.
 */
const normalizeDnValue = (v) => String(v).trim().replace(/\s+/g, ' ').toLowerCase();

const rdnSequence = (name) => name.typesAndValues
  .map((tv) => ({ type: tv.type, value: normalizeDnValue(tv.value.valueBlock.value) }));

/** RFC 5280 §4.2.1.10: a directoryName subtree is a PREFIX test over the RDN sequence. */
function withinDirNameSubtree(subject, constraint) {
  if (constraint.length > subject.length) return false;
  return constraint.every((c, i) => subject[i].type === c.type && subject[i].value === c.value);
}

/**
 * Enforce the issuing CA's nameConstraints against a leaf (§4.2.1.10). A valid
 * signature says the CA DID issue it; the constraint says whether it MAY.
 */
export function assertNameConstraints(cert, caCert) {
  const nc = extensions(caCert, OID.nameConstraints)[0];
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
  // constrains solely DNS or email says nothing about DNs.
  if (permitted.length > 0 && !permitted.some((p) => withinDirNameSubtree(subject, p))) {
    throw new DenyError('ERR_NAME_CONSTRAINT',
      'subject is outside every permitted subtree of the issuing CA');
  }
}

// ── Signature verification ──────────────────────────────────────────────────

/**
 * Verify that `cert` was signed by `issuerCert`'s private key.
 *
 * PKI.js's own `verify()` is used for RSA and ECDSA: it handles the algorithm
 * mapping and the exact bytes covered (the tbsCertificate). PKI.js cannot
 * import an Ed25519 key, so that case goes to Web Crypto directly over the same
 * tbsCertificate bytes. Any error is `false` — never a pass.
 */
export async function isSignedBy(cert, issuerCert) {
  try {
    const issuerKey = publicKeyInfo(issuerCert);
    if (issuerKey.type === 'Ed25519') {
      if (cert.signatureAlgorithm?.algorithmId !== OID.ed25519) return false;
      const key = await crypto.subtle.importKey('raw', issuerKey.raw, { name: 'Ed25519' }, false, ['verify']);
      const tbs = new Uint8Array(cert.tbsView ?? cert.tbs);
      const sig = new Uint8Array(cert.signatureValue.valueBlock.valueHexView);
      return await crypto.subtle.verify('Ed25519', key, sig, tbs);
    }
    return await cert.verify(issuerCert);
  } catch {
    return false; // fail closed — an error verifying is never a pass
  }
}

// ── The two extensions ──────────────────────────────────────────────────────

/**
 * Decode one JCS-carrying extension (§8.2, §10.5): exactly one occurrence,
 * critical, within the size limit, valid UTF-8, strictly parsed JSON, flat, and
 * byte-identical to its own canonical form. "Not valid JCS" is refused rather
 * than repaired — the draft forbids re-canonicalizing.
 */
function decodeJcsExtension(cert, oid, code, label, limit) {
  const found = extensions(cert, oid);
  if (found.length === 0) return null;
  if (found.length > 1) {
    throw new DenyError(code, `certificate carries ${found.length} ${label} extensions — exactly one is permitted`);
  }
  const ext = found[0];
  if (!ext.critical) throw new DenyError(code, `${label} extension is not marked critical`);
  const bytes = new Uint8Array(ext.extnValue.valueBlock.valueHexView);
  // §8.2 — the limit is applied to the octets, before any of them is decoded.
  if (bytes.length > limit) {
    throw new DenyError('ERR_EXTENSION_TOO_LARGE',
      `${label} extension is ${bytes.length} octets; the limit is ${limit}, and it is not parsed`);
  }
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    throw new DenyError(code, `${label} extension is not valid UTF-8`);
  }
  let obj;
  try {
    obj = parseJsonStrict(text);
  } catch (e) {
    if (e instanceof DenyError) throw e;    // duplicate member (§3) keeps its own clause
    if (e instanceof JsonSyntaxError) throw new DenyError(code, `${label} extension is not JSON`);
    throw e;
  }
  assertFlatObject(obj, label);
  if (canonicalize(obj) !== text) {
    throw new DenyError(code, `${label} extension is not valid JCS — it is not its own canonical form`);
  }
  return obj;
}

function assertExactMembers(obj, fields, code, label, optional = []) {
  const keys = Object.keys(obj);
  const missing = fields.filter((f) => !keys.includes(f));
  if (missing.length) throw new DenyError(code, `${label} extension omits ${missing.join(', ')}`);
  const extra = keys.filter((k) => !fields.includes(k) && !optional.includes(k)).sort();
  if (extra.length) throw new DenyError(code, `${label} extension carries ${extra.join(', ')}, which its table lists no member for`);
}

const OPERATION = /^[a-z0-9:_-]{1,64}$/;

/**
 * The member rules of §8.2 Table 5, shared by the relying party (which reads
 * them out of a certificate) and the Registry (which applies them as the §9.1
 * conformance gate before signing and again before issuing). One function, so
 * the gate and the validator cannot disagree about what conforms.
 *
 * @param {object} t          the candidate template
 * @param {string} [code]     the refusal code to use for a structural failure
 */
export function assertTemplateMembers(t, code = 'ERR_TEMPLATE_EXT_INVALID') {
  if (t === null || typeof t !== 'object' || Array.isArray(t)) {
    throw new DenyError(code, 'template is not a JSON object');
  }
  assertFlatObject(t, 'template');
  assertExactMembers(t, TEMPLATE_FIELDS, code, 'Agent Template');
  try {
    validateUuid(t.subject, 'subject');
    validateText(t.owner, 'owner');
    validateText(t.org_id, 'org_id');
    if (!Array.isArray(t.permitted_operations)
        || !t.permitted_operations.every((op) => typeof op === 'string' && OPERATION.test(op))
        || new Set(t.permitted_operations).size !== t.permitted_operations.length) {
      throw new DenyError(code, 'permitted_operations must be a set of operation names');
    }
    validateScopeSet(t.allowed_scopes, 'allowed_scopes');
    if (!Array.isArray(t.can_spawn)) throw new DenyError(code, 'can_spawn must be an array');
    t.can_spawn.forEach((id) => validateUuid(id, 'can_spawn entry'));
    if (new Set(t.can_spawn).size !== t.can_spawn.length) {
      throw new DenyError(code, 'can_spawn contains duplicates');
    }
    validateInteger(t.max_children, 'max_children', 0, MAX_CHILDREN);
    // §8.1 — a template defines one agent, so each CanSpawn entry names a child
    // that exists at most once at a time; a cap above that count is a cap on
    // nothing, and the gate refuses it rather than let a validator count
    // toward a limit that can never be reached.
    if (t.max_children > t.can_spawn.length) {
      throw new DenyError('ERR_MAX_CHILDREN_EXCEEDS_CAN_SPAWN',
        `max_children is ${t.max_children} but can_spawn names ${t.can_spawn.length} child(ren)`);
    }
    validateReference(t.policy_ref, 'policy_ref');
    validateTtl(t.ttl_seconds, 'ttl_seconds');
  } catch (e) {
    // Member-level refusals keep their own clause (scope syntax is §10.3, the
    // TTL cap is §9.3, the identifier form is §7.2); everything else takes the
    // caller's code.
    if (e instanceof DenyError && e.code !== 'ERR_FIELD_CHARSET' && e.code !== 'ERR_FIELD_RANGE'
        && e.code !== 'ERR_SCHEMA_VIOLATION') throw e;
    throw new DenyError(code, e.detail || e.message);
  }
  return t;
}

/**
 * §8.2 — parse and validate the Agent Template extension.
 *
 * @returns {object} the nine members, typed and checked
 */
export function parseTemplateExtension(cert) {
  const t = decodeJcsExtension(cert, TEMPLATE_EXT_OID, 'ERR_TEMPLATE_EXT_INVALID', 'Agent Template',
    MAX_TEMPLATE_EXTENSION_BYTES);
  if (t === null) {
    throw new DenyError('ERR_TEMPLATE_EXT_MISSING', 'agent certificate carries no Agent Template extension');
  }
  assertTemplateMembers(t);
  // §9.3 — the CA sets the subject CN from the subject member. A certificate
  // where the two differ was not issued as the draft requires.
  const cn = subjectCN(cert);
  if (cn !== t.subject) {
    throw new DenyError('ERR_SUBJECT_MISMATCH',
      'the Agent Template subject member differs from the certificate subject common name');
  }
  return t;
}

/**
 * §10.5 — parse and validate the Agent Spawn extension, or return null when the
 * certificate carries none. Whether it SHOULD carry one is the pipeline's
 * question, because it depends on the chain.
 */
export function parseSpawnExtension(cert) {
  const s = decodeJcsExtension(cert, SPAWN_EXT_OID, 'ERR_SPAWN_EXT_INVALID', 'Agent Spawn',
    MAX_SPAWN_EXTENSION_BYTES);
  if (s === null) return null;
  assertExactMembers(s, SPAWN_FIELDS, 'ERR_SPAWN_EXT_INVALID', 'Agent Spawn', SPAWN_OPTIONAL_FIELDS);
  try {
    validateUuid(s.parent_agent_id, 'parent_agent_id');
    validateTimestamp(s.spawned_at, 'spawned_at');
    validateNonce(s.spawn_nonce, 'spawn_nonce');
    // §10.5 — present exactly when the spawn was cross-organizational; whether
    // it SHOULD be present depends on the parent, which is the pipeline's question.
    if ('grant_id' in s) validateUuid(s.grant_id, 'grant_id');
  } catch (e) {
    if (e instanceof DenyError && e.code !== 'ERR_SCHEMA_VIOLATION') throw e;
    throw new DenyError('ERR_SPAWN_EXT_INVALID', e.detail || e.message);
  }
  return s;
}

/**
 * §9.3 — notAfter minus notBefore, in whole seconds, MUST NOT exceed
 * ttl_seconds. That exact arithmetic, so there is no boundary question.
 */
export function assertValidityWithinTtl(cert, ttlSeconds) {
  const { notBefore, notAfter } = validityWindow(cert);
  const seconds = Math.floor((notAfter.getTime() - notBefore.getTime()) / 1000);
  if (seconds > ttlSeconds) {
    throw new DenyError('ERR_VALIDITY_EXCEEDS_TTL',
      `certificate is valid for ${seconds} seconds but its ttl_seconds is ${ttlSeconds}`);
  }
}

// ── Whole-certificate validation ────────────────────────────────────────────

/**
 * Validate the trust anchor itself. Nothing beneath it means anything if the
 * anchor is not a CA, is weakly signed, or does not verify under its own key.
 */
export async function validateAnchor(caPem, { now = new Date() } = {}) {
  const ca = parseCertificate(caPem);
  assertCriticalExtensionsRecognized(ca);
  if (!isSelfSigned(ca)) {
    throw new DenyError('ERR_CHAIN_INVALID', 'trust anchor is not self-signed');
  }
  assertStrongSignature(ca);
  assertBasicConstraints(ca, { mustBeCa: true });
  assertKeyUsage(ca, { isCa: true });
  assertKeyStrength(ca);
  if (!(await isSignedBy(ca, ca))) {
    throw new DenyError('ERR_CHAIN_INVALID', 'trust anchor does not verify under its own key');
  }
  // §15.1 — an expired certificate is a MUST-DENY, and the anchor is the one
  // every other certificate is measured against.
  if (isOutsideValidity(ca, now)) {
    const { notBefore, notAfter } = validityWindow(ca);
    throw new DenyError('ERR_CERT_EXPIRED',
      now > notAfter
        ? `trust anchor expired at ${notAfter.toISOString()} — every certificate beneath it is void`
        : `trust anchor is not valid until ${notBefore.toISOString()}`);
  }
  return ca;
}

/**
 * Full §7 validation of a leaf against the anchor, in the order the module
 * header describes.
 *
 * @param {object}  opts
 * @param {string}  opts.certPem    the certificate
 * @param {string}  [opts.caPem]    the trust anchor, as PEM
 * @param {Certificate} [opts.caCert]  the trust anchor already parsed (from `validateAnchor`); wins over caPem
 * @param {string}  opts.agentId    expected subject CN — the identifier the presenting party claims
 * @param {Date}    [opts.now]      injectable clock, so expiry is testable
 * @param {'agent'|'authority'} [opts.role]  agents carry the Agent Template extension; authorities do not
 * @returns {Promise<{cert: Certificate, key: object, template: object|null, spawn: object|null}>}
 */
export async function validateCertificate({ certPem, caPem = null, caCert = null, agentId, now = new Date(), role = 'agent' }) {
  const cert = parseCertificate(certPem);
  const ca = caCert ?? parseCertificate(caPem);

  // RFC 5280 §4.2 — before honouring anything in the certificate, confirm there
  // is nothing critical in it we would be silently ignoring.
  assertCriticalExtensionsRecognized(cert);

  const cn = subjectCN(cert);
  if (cn === null) {
    throw new DenyError('ERR_SUBJECT_MISMATCH', 'certificate has no common name');
  }
  if (role === 'agent') validateUuid(cn, 'subject common name');
  if (cn !== agentId) {
    throw new DenyError('ERR_SUBJECT_MISMATCH',
      'certificate common name does not match the identifier the document claims');
  }

  if (isSelfSigned(cert)) {
    throw new DenyError('ERR_SELF_SIGNED', 'subject and issuer are the same entity');
  }

  // Structure before cryptography.
  assertStrongSignature(cert);
  assertStrongSignature(ca);
  assertBasicConstraints(cert, { mustBeCa: false });
  assertBasicConstraints(ca, { mustBeCa: true });
  assertKeyUsage(cert, { isCa: false });
  assertKeyUsage(ca, { isCa: true });
  assertSerialEncoding(cert);
  assertSerialEntropy(cert);

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
  if (isOutsideValidity(ca, now)) {
    throw new DenyError('ERR_CERT_EXPIRED', 'the trust anchor is outside its validity window — nothing beneath it is valid');
  }

  const key = assertKeyStrength(cert);
  assertRevocationSource(cert);

  // Content last: the signature has verified, so the extension is now the CA's
  // statement rather than the presenter's (§8.2).
  let template = null;
  let spawn = null;
  if (role === 'agent') {
    template = parseTemplateExtension(cert);
    spawn = parseSpawnExtension(cert);
    assertValidityWithinTtl(cert, template.ttl_seconds);
  }

  return { cert, key, template, spawn };
}
