/**
 * Certificate internals, decoded for a human.
 *
 * `x509.js` decides whether a certificate is valid. This module explains what is
 * *in* one and what each check actually compares, because the point of the
 * playground is that a second implementer can build their own — and nobody
 * builds from a PASS/FAIL.
 *
 * ── What a certificate actually is ──────────────────────────────────────────
 *
 * An X.509 certificate is three DER-encoded pieces, in this order:
 *
 *     Certificate ::= SEQUENCE {
 *       tbsCertificate       TBSCertificate,      -- everything being attested
 *       signatureAlgorithm   AlgorithmIdentifier, -- how it was signed
 *       signatureValue       BIT STRING           -- the signature itself
 *     }
 *
 * The single most misread detail: **the signature covers the tbsCertificate
 * bytes only** — not the whole certificate, and not a re-serialisation of the
 * parsed fields. This is why re-encoding a certificate can break its signature
 * even when every field is unchanged.
 *
 * ── Two views of the same extension ─────────────────────────────────────────
 *
 * The Agent Template extension (§8.2) and the Agent Spawn extension (§10.5)
 * are critical OCTET STRINGs holding JCS. A stack that does not implement the
 * draft sees an unrecognised critical OID and a blob, and must refuse the
 * certificate (RFC 5280 §4.2). A conformant validator sees the members. Both
 * views are produced here, side by side, because the difference IS the design:
 * the certificate is unusable except by a party that understands what it says.
 */

import * as asn1js from 'asn1js';
import {
  parseCertificate, subjectCN, issuerCN, publicKeyInfo, isSelfSigned, validityWindow,
  normalizeOid, TEMPLATE_EXT_OID, SPAWN_EXT_OID, MIN_SECURITY_BITS, KEY_USAGE_NAMES, keyUsageBits,
} from './x509.js';
import { bytesToHex } from './encoding.js';
import { validatePem, parseJsonStrict } from './validate-input.js';
import { canonicalize } from './canonical.js';

export { normalizeOid };

/** Attribute types that appear in the DNs this profile issues. */
const DN_NAMES = {
  '2.5.4.3': 'CN', '2.5.4.6': 'C', '2.5.4.7': 'L', '2.5.4.8': 'ST',
  '2.5.4.10': 'O', '2.5.4.11': 'OU', '1.2.840.113549.1.9.1': 'emailAddress',
};

const EXT_NAMES = {
  '2.5.29.14': 'subjectKeyIdentifier',
  '2.5.29.15': 'keyUsage',
  '2.5.29.17': 'subjectAltName',
  '2.5.29.19': 'basicConstraints',
  '2.5.29.30': 'nameConstraints',
  '2.5.29.31': 'cRLDistributionPoints',
  '2.5.29.32': 'certificatePolicies',
  '2.5.29.35': 'authorityKeyIdentifier',
  '2.5.29.37': 'extendedKeyUsage',
  '1.3.6.1.5.5.7.1.1': 'authorityInfoAccess',
  [TEMPLATE_EXT_OID]: 'agentTemplate (draft-tonyai-a2a-trust §8.2)',
  [SPAWN_EXT_OID]: 'agentSpawn (draft-tonyai-a2a-trust §10.5)',
};

const SIG_ALGS = {
  '1.2.840.113549.1.1.11': 'sha256WithRSAEncryption',
  '1.2.840.113549.1.1.12': 'sha384WithRSAEncryption',
  '1.2.840.113549.1.1.13': 'sha512WithRSAEncryption',
  '1.2.840.113549.1.1.10': 'RSASSA-PSS',
  '1.2.840.113549.1.1.1': 'rsaEncryption',
  '1.2.840.10045.4.1': 'ecdsa-with-SHA1',
  '1.2.840.10045.4.3.2': 'ecdsa-with-SHA256',
  '1.2.840.10045.4.3.3': 'ecdsa-with-SHA384',
  '1.2.840.10045.4.3.4': 'ecdsa-with-SHA512',
  '1.2.840.10045.2.1': 'id-ecPublicKey',
  '1.3.101.112': 'Ed25519',
};

const EKU_NAMES = {
  '1.3.6.1.5.5.7.3.1': 'serverAuth',
  '1.3.6.1.5.5.7.3.2': 'clientAuth',
  '1.3.6.1.5.5.7.3.3': 'codeSigning',
  '1.3.6.1.5.5.7.3.4': 'emailProtection',
};

const hex = bytesToHex;
const hexColons = (bytes) => bytesToHex(bytes).toUpperCase().match(/../g).join(':');

/** Structured DN: ordered attributes, because RDN ORDER IS SIGNIFICANT (§4.2.1.10). */
export function describeName(name) {
  const attributes = name.typesAndValues.map((tv) => ({
    oid: tv.type,
    name: DN_NAMES[tv.type] ?? tv.type,
    value: String(tv.value.valueBlock.value),
  }));
  return { attributes, rfc4514: attributes.map((a) => `${a.name}=${a.value}`).join(', ') };
}

/** The same decoder the validator uses, so the view and the verdict cannot disagree about what a certificate asserts. */
function describeKeyUsage(ext) {
  const bits = keyUsageBits(ext);
  return KEY_USAGE_NAMES.filter((_, i) => bits.has(i));
}

/**
 * The two views of a profile extension. `raw` is what any X.509 stack sees;
 * `decoded` is what a conformant validator sees. Decoding here is descriptive
 * and lenient — it shows what is there even when `x509.js` would refuse it,
 * and says so.
 */
function describeJcsExtension(ext, base, label) {
  const raw = new Uint8Array(ext.extnValue.valueBlock.valueHexView);
  const generic = {
    ...base,
    value: hex(raw).slice(0, 64),
    summary: `${raw.length} bytes — an OCTET STRING under an OID this stack does not know; ` +
      (ext.critical ? 'critical, so RFC 5280 §4.2 requires refusing the certificate' : 'NOT critical, so it would be silently ignored'),
  };
  let text = null;
  let members = null;
  let problem = null;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(raw);
    const obj = parseJsonStrict(text);
    if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) problem = 'not a JSON object';
    else if (canonicalize(obj) !== text) problem = 'valid JSON but not its own canonical form (not JCS)';
    else members = Object.entries(obj).map(([k, v]) => ({ member: k, value: v }));
  } catch (e) {
    problem = e?.code === 'ERR_DUPLICATE_MEMBER' ? 'duplicate member name' : 'not valid UTF-8 JSON';
  }
  return {
    ...generic,
    label,
    critical: Boolean(ext.critical),
    views: {
      any_x509_stack: generic.summary,
      conformant_validator: problem
        ? `refused — ${problem}`
        : `${members.length} members, JCS, ${raw.length} bytes`,
    },
    decoded: { members, problem, jcs: text },
  };
}

function describeExtension(ext) {
  const oid = normalizeOid(ext.extnID);
  const base = { oid, name: EXT_NAMES[oid] ?? null, critical: Boolean(ext.critical) };
  try {
    switch (oid) {
      case TEMPLATE_EXT_OID:
        return describeJcsExtension(ext, base, 'Agent Template');
      case SPAWN_EXT_OID:
        return describeJcsExtension(ext, base, 'Agent Spawn');
      case '2.5.29.19': {
        const v = ext.parsedValue;
        return { ...base, value: { cA: Boolean(v.cA), pathLenConstraint: v.pathLenConstraint ?? null },
          summary: v.cA ? `CA:TRUE${v.pathLenConstraint != null ? `, pathlen:${v.pathLenConstraint}` : ''}` : 'CA:FALSE' };
      }
      case '2.5.29.15': {
        const usages = describeKeyUsage(ext);
        return { ...base, value: usages, summary: usages.join(', ') };
      }
      case '2.5.29.37': {
        const kps = (ext.parsedValue.keyPurposes ?? []).map((k) => EKU_NAMES[k] ?? k);
        return { ...base, value: kps, summary: kps.join(', ') };
      }
      case '2.5.29.30': {
        const subtree = (list) => (list ?? []).map((st) => (st.base.type === 4
          ? { kind: 'dirName', value: describeName(st.base.value).rfc4514 }
          : { kind: st.base.type === 2 ? 'dNSName' : st.base.type === 1 ? 'rfc822Name' : `type${st.base.type}`,
              value: String(st.base.value) }));
        const permitted = subtree(ext.parsedValue.permittedSubtrees);
        const excluded = subtree(ext.parsedValue.excludedSubtrees);
        return { ...base, value: { permitted, excluded },
          summary: `permitted: ${permitted.map((p) => `${p.kind}:${p.value}`).join(' | ') || 'none'}`
                 + (excluded.length ? `; excluded: ${excluded.map((e) => `${e.kind}:${e.value}`).join(' | ')}` : '') };
      }
      case '2.5.29.31': {
        const uris = (ext.parsedValue?.distributionPoints ?? [])
          .flatMap((dp) => (Array.isArray(dp.distributionPoint) ? dp.distributionPoint : []))
          .filter((gn) => gn.type === 6).map((gn) => String(gn.value));
        return { ...base, value: uris, summary: uris.length ? `URI:${uris.join(', ')}` : 'present' };
      }
      case '2.5.29.14':
        return { ...base, value: hex(new Uint8Array(ext.parsedValue.valueBlock.valueHexView)),
          summary: 'key identifier (SHA-1 of the public key)' };
      case '2.5.29.35': {
        const kid = ext.parsedValue?.keyIdentifier;
        const v = kid ? hex(new Uint8Array(kid.valueBlock.valueHexView)) : null;
        return { ...base, value: v,
          summary: v ? `points at issuer key ${v.slice(0, 16)}…` : 'issuer key identifier' };
      }
      default: {
        // Unknown OIDs still get shown — including the demo notice, whose whole
        // job is to be readable in any certificate viewer.
        const raw = new Uint8Array(ext.extnValue.valueBlock.valueHexView);
        let text = null;
        try {
          const inner = asn1js.fromBER(raw.buffer.slice(raw.byteOffset, raw.byteOffset + raw.byteLength));
          if (inner.offset !== -1 && typeof inner.result.valueBlock?.value === 'string') {
            text = inner.result.valueBlock.value;
          }
        } catch { /* not a printable inner value; fall through to hex */ }
        const known = EXT_NAMES[oid] ? 'not decoded by this validator' : 'unrecognised OID';
        return { ...base, value: text ?? hex(raw).slice(0, 64),
          summary: text ?? `${raw.length} bytes, ${known}` };
      }
    }
  } catch {
    return { ...base, value: null, summary: 'present, could not be decoded' };
  }
}

/**
 * Decode one certificate into displayable inner detail.
 *
 * Everything here is derived from the certificate itself. Nothing is inferred
 * and nothing is trusted: this is a description, not a validation. Ask
 * `validateCertificate` whether it should be accepted.
 */
export async function describeCertificate(pem) {
  const cert = parseCertificate(pem);
  const { notBefore, notAfter } = validityWindow(cert);

  // Both digests are taken over the ORIGINAL DER as it arrived, never over a
  // re-serialisation of the parsed structure: `cert.toSchema().toBER()`
  // re-encodes, and a fingerprint over that disagrees with OpenSSL's.
  const { der } = validatePem(pem, 'CERTIFICATE');
  const whole = der;
  const fingerprint = new Uint8Array(await crypto.subtle.digest('SHA-256', whole));

  const tbsRaw = new Uint8Array(cert.tbsView ?? cert.tbs);
  const tbsDigest = new Uint8Array(await crypto.subtle.digest('SHA-256', tbsRaw));

  const sigBytes = new Uint8Array(cert.signatureValue.valueBlock.valueHexView);
  const key = publicKeyInfo(cert);
  const extensions = (cert.extensions ?? []).map(describeExtension);

  return {
    subject: describeName(cert.subject),
    issuer: describeName(cert.issuer),
    common_name: subjectCN(cert),
    issuer_common_name: issuerCN(cert),
    self_signed: isSelfSigned(cert),

    version: cert.version + 1,   // DER stores v3 as the integer 2
    serial_number: hexColons(new Uint8Array(cert.serialNumber.valueBlock.valueHexView)),

    validity: {
      not_before: notBefore.toISOString(),
      not_after: notAfter.toISOString(),
      duration_seconds: Math.round((notAfter - notBefore) / 1000),
      duration_hours: Math.round((notAfter - notBefore) / 36e5),
    },

    public_key: {
      algorithm: SIG_ALGS[cert.subjectPublicKeyInfo.algorithm.algorithmId]
                 ?? cert.subjectPublicKeyInfo.algorithm.algorithmId,
      type: key.type === 'EC' ? key.curve : key.type,
      bits: key.bits,
      security_bits: key.security,
      meets_minimum: key.security !== null && key.security >= MIN_SECURITY_BITS,
    },

    signature: {
      algorithm: SIG_ALGS[cert.signatureAlgorithm.algorithmId] ?? cert.signatureAlgorithm.algorithmId,
      bits: sigBytes.length * 8,
      value_prefix: `${hex(sigBytes.slice(0, 16))}…`,
    },

    signed_bytes: {
      what: 'tbsCertificate — the certificate body, excluding signatureAlgorithm and signatureValue',
      length: tbsRaw.length,
      sha256: hex(tbsDigest),
      note: 'The issuer signs THIS digest. Verification re-hashes these exact bytes as encoded, '
          + 'never a re-serialisation of the parsed fields.',
    },

    fingerprint_sha256: hex(fingerprint),
    extensions,
    agent_template: extensions.find((e) => e.oid === TEMPLATE_EXT_OID)?.decoded ?? null,
    agent_spawn: extensions.find((e) => e.oid === SPAWN_EXT_OID)?.decoded ?? null,
    der_bytes: whole.length,
  };
}

/**
 * The §7 validation sequence as data: what is checked, in what order, comparing
 * what against what, and which clause requires it. Order matters and is
 * `validateCertificate`'s.
 */
export const VALIDATION_STEPS = Object.freeze([
  { n: 1, check: 'parse',              section: null,
    question: 'Is this well-formed DER carrying an X.509 certificate?',
    compares: 'PEM base64 -> DER -> ASN.1 SEQUENCE',
    on_failure: 'ERR_MALFORMED_PEM' },
  { n: 2, check: 'critical_extensions', section: '7.1',
    question: 'Does it carry a critical extension this validator cannot honour?',
    compares: 'each ext.critical OID against the recognised set, the two profile extensions included',
    on_failure: 'ERR_UNKNOWN_CRITICAL_EXT',
    why: 'RFC 5280 §4.2 — a validator MUST reject what it cannot understand but is told it must obey.' },
  { n: 3, check: 'subject_cn',         section: '7.2',
    question: 'Does the certificate name the agent the document claims, as a UUID?',
    compares: 'subject CN vs the restated agent_id',
    on_failure: 'ERR_SUBJECT_MISMATCH / ERR_AGENT_ID_FORMAT',
    why: 'Every restatement of an identifier must equal the subject CN; none is advisory.' },
  { n: 4, check: 'not_self_signed',    section: '7.3',
    question: 'Was it issued by someone, or did it issue itself?',
    compares: 'full subject DN vs full issuer DN',
    on_failure: 'ERR_SELF_SIGNED',
    why: 'A self-signed agent certificate is an agent asserting its own authority.' },
  { n: 5, check: 'profile',            section: '7.1',
    question: 'Is it shaped as the profile requires?',
    compares: 'digest ≥ SHA-256; basicConstraints CA:FALSE; keyUsage critical digitalSignature only; serial ≥ 64 bits',
    on_failure: 'ERR_WEAK_SIGNATURE / ERR_BASIC_CONSTRAINTS / ERR_KEY_USAGE / ERR_SERIAL_ENTROPY' },
  { n: 6, check: 'signature',          section: '7',
    question: 'Did the CA actually sign these bytes?',
    compares: 'the CA public key against the signature over tbsCertificate (ECDSA, RSA or Ed25519)',
    on_failure: 'ERR_FORGED_ISSUER / ERR_CHAIN_INVALID' },
  { n: 7, check: 'name_constraints',   section: '7.1',
    question: 'Was the CA permitted to issue for this name?',
    compares: 'subject RDN sequence against the CA permitted/excluded subtrees',
    on_failure: 'ERR_NAME_CONSTRAINT',
    why: 'RFC 5280 §4.2.1.10. A valid signature says the CA DID issue it; the constraint says whether it MAY.' },
  { n: 8, check: 'validity_window',    section: '7',
    question: 'Is it being used inside its lifetime?',
    compares: 'now against notBefore and notAfter',
    on_failure: 'ERR_CERT_EXPIRED' },
  { n: 9, check: 'key_strength',       section: '7.1',
    question: 'Does the public key provide 128-bit security?',
    compares: 'RSA modulus ≥ 3072, or P-256 / P-384 / Ed25519, measured from the key',
    on_failure: 'ERR_KEY_TOO_SMALL' },
  { n: 10, check: 'revocation_source', section: '14.4',
    question: 'Does it say where its revocation state lives?',
    compares: 'cRLDistributionPoints, or authorityInfoAccess with id-ad-ocsp',
    on_failure: 'ERR_NO_REVOCATION_SOURCE' },
  { n: 11, check: 'agent_template',    section: '8.2',
    question: 'Does it carry the nine template members, as JCS, critical, subject equal to the CN?',
    compares: 'the Agent Template extension against Table 5, and its bytes against its own canonical form',
    on_failure: 'ERR_TEMPLATE_EXT_MISSING / ERR_TEMPLATE_EXT_INVALID / ERR_TTL_TOO_LONG',
    why: 'Parsed only after the signature verified: until then the extension is attacker input.' },
  { n: 12, check: 'agent_spawn',       section: '10.5',
    question: 'If it has a parent, does the CA attest which one, when, and under what nonce?',
    compares: 'the Agent Spawn extension against Table 6',
    on_failure: 'ERR_SPAWN_EXT_INVALID / ERR_PARENT_MISMATCH' },
  { n: 13, check: 'validity_within_ttl', section: '9.3',
    question: 'Is the certificate no longer-lived than its own template says?',
    compares: 'notAfter − notBefore in seconds against ttl_seconds',
    on_failure: 'ERR_VALIDITY_EXCEEDS_TTL' },
]);
