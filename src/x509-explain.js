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
 * parsed fields. Verifying means re-hashing the exact tbsCertificate DER as it
 * appeared on the wire and checking that hash against the signature using the
 * ISSUER's public key. This is why re-encoding a certificate can break its
 * signature even when every field is unchanged, and why `describeCertificate`
 * below reports the tbsCertificate length and digest explicitly.
 *
 * A certificate therefore proves exactly one thing: *the holder of the issuer's
 * private key asserted this binding of a public key to a name, during this
 * window.* It carries no authorisation. That is why this draft keeps
 * authorisation in a separate signed metadata document (§7) — the certificate
 * answers "who", the metadata answers "may they".
 */

import * as asn1js from 'asn1js';
import { parseCertificate, subjectCN, issuerCN, rsaKeyBits, isSelfSigned, validityWindow } from './x509.js';
import { validatePem } from './validate-input.js';

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
};

const SIG_ALGS = {
  '1.2.840.113549.1.1.11': 'sha256WithRSAEncryption',
  '1.2.840.113549.1.1.12': 'sha384WithRSAEncryption',
  '1.2.840.113549.1.1.13': 'sha512WithRSAEncryption',
  '1.2.840.113549.1.1.1': 'rsaEncryption',
};

/** RFC 5280 §4.2.1.3 — keyUsage bits, in their defined order. */
const KEY_USAGE_BITS = [
  'digitalSignature', 'nonRepudiation', 'keyEncipherment', 'dataEncipherment',
  'keyAgreement', 'keyCertSign', 'cRLSign', 'encipherOnly', 'decipherOnly',
];

const EKU_NAMES = {
  '1.3.6.1.5.5.7.3.1': 'serverAuth',
  '1.3.6.1.5.5.7.3.2': 'clientAuth',
  '1.3.6.1.5.5.7.3.3': 'codeSigning',
  '1.3.6.1.5.5.7.3.4': 'emailProtection',
};

/**
 * PKI.js renders an OID arc it cannot hold in a JS number as `2.25.{hex…}`.
 * The 2.25 (UUID) arc is always 128 bits, so every OID under it hits this. The
 * value is correct on the wire — OpenSSL reads it back fine — but showing
 * `2.25.{03701d27…}` on a page about certificate internals would be displaying
 * a decoding artefact as if it were the certificate's content.
 */
export function normalizeOid(oid) {
  return String(oid).replace(/\{([0-9a-fA-F]+)\}/g, (_, h) => {
    // The hex is the arc's raw BER bytes, base-128 with a continuation bit in
    // the top position of every byte but the last — not a plain big-endian
    // integer. Reading it as one gives a different, wrong number that still
    // looks like a plausible OID, which is the worst kind of wrong.
    let value = 0n;
    for (let i = 0; i < h.length; i += 2) {
      value = (value << 7n) | (BigInt(parseInt(h.slice(i, i + 2), 16)) & 0x7fn);
    }
    return value.toString();
  });
}

const hex = (bytes) => Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
const hexColons = (bytes) => Array.from(bytes).map((b) => b.toString(16).padStart(2, '0').toUpperCase()).join(':');

/** Structured DN: ordered attributes, because RDN ORDER IS SIGNIFICANT (§4.2.1.10). */
export function describeName(name) {
  const attributes = name.typesAndValues.map((tv) => ({
    oid: tv.type,
    name: DN_NAMES[tv.type] ?? tv.type,
    value: String(tv.value.valueBlock.value),
  }));
  return { attributes, rfc4514: attributes.map((a) => `${a.name}=${a.value}`).join(', ') };
}

function describeKeyUsage(ext) {
  const view = new Uint8Array(ext.parsedValue.valueBlock.valueHexView);
  const unused = ext.parsedValue.valueBlock.unusedBits ?? 0;
  const total = view.length * 8 - unused;
  const set = [];
  for (let i = 0; i < Math.min(total, KEY_USAGE_BITS.length); i++) {
    if (view[Math.floor(i / 8)] & (0x80 >> (i % 8))) set.push(KEY_USAGE_BITS[i]);
  }
  return set;
}

function describeExtension(ext) {
  const oid = normalizeOid(ext.extnID);
  const base = { oid, name: EXT_NAMES[oid] ?? null, critical: Boolean(ext.critical) };
  try {
    switch (oid) {
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
        // A named-but-undecoded extension is not the same as an unknown one.
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
  // re-serialisation of the parsed structure.
  //
  // This is not a stylistic preference. `cert.toSchema().toBER()` re-encodes,
  // and for this very certificate that produced 1128 bytes where the original
  // was 1147 — a fingerprint that disagreed with `openssl x509 -fingerprint`
  // and would have been wrong everywhere it was shown. A certificate is the
  // bytes it was issued as; any field-level round trip is a different document.
  const { der } = validatePem(pem, 'CERTIFICATE');
  const whole = der;
  const fingerprint = new Uint8Array(await crypto.subtle.digest('SHA-256', whole));

  // The bytes the signature actually covers: the tbsCertificate, which is the
  // first element inside the outer SEQUENCE. Taken from the parsed view, which
  // preserves the original encoding rather than rebuilding it.
  const tbsRaw = new Uint8Array(cert.tbsView ?? cert.tbs);
  const tbsDigest = new Uint8Array(await crypto.subtle.digest('SHA-256', tbsRaw));

  const sigBytes = new Uint8Array(cert.signatureValue.valueBlock.valueHexView);
  const keyBits = rsaKeyBits(cert);

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
      duration_hours: Math.round((notAfter - notBefore) / 36e5),
    },

    public_key: {
      algorithm: SIG_ALGS[cert.subjectPublicKeyInfo.algorithm.algorithmId]
                 ?? cert.subjectPublicKeyInfo.algorithm.algorithmId,
      bits: keyBits,
      meets_minimum: keyBits !== null && keyBits >= 2048,
    },

    signature: {
      algorithm: SIG_ALGS[cert.signatureAlgorithm.algorithmId] ?? cert.signatureAlgorithm.algorithmId,
      bits: sigBytes.length * 8,
      value_prefix: `${hex(sigBytes.slice(0, 16))}…`,
    },

    // The part people get wrong. Stated explicitly so a reader can see that
    // verification is a hash over these bytes, not over the file.
    signed_bytes: {
      what: 'tbsCertificate — the certificate body, excluding signatureAlgorithm and signatureValue',
      length: tbsRaw.length,
      sha256: hex(tbsDigest),
      note: 'The issuer signs THIS digest. Verification re-hashes these exact bytes as encoded, '
          + 'never a re-serialisation of the parsed fields.',
    },

    fingerprint_sha256: hex(fingerprint),
    extensions: (cert.extensions ?? []).map(describeExtension),
    der_bytes: whole.length,
  };
}

/**
 * The §6 validation sequence as data: what is checked, in what order, comparing
 * what against what, and which clause requires it.
 *
 * The UI renders this as the decision log — DESIGN.md calls the log the
 * signature move — and it doubles as the readable answer to "how do I validate
 * one of these myself?". Order matters and is the reference implementation's.
 */
export const VALIDATION_STEPS = Object.freeze([
  { n: 1, check: 'parse',              section: null,
    question: 'Is this well-formed DER carrying an X.509 certificate?',
    compares: 'PEM base64 -> DER -> ASN.1 SEQUENCE',
    on_failure: 'ERR_MALFORMED_PEM' },
  { n: 2, check: 'critical_extensions', section: '6',
    question: 'Does it carry a critical extension this validator cannot honour?',
    compares: 'each ext.critical OID against the recognised set',
    on_failure: 'ERR_UNKNOWN_CRITICAL_EXT',
    why: 'RFC 5280 §4.2 — a validator MUST reject what it cannot understand but is told it must obey.' },
  { n: 3, check: 'subject_cn',         section: '6',
    question: 'Does the certificate name the agent the metadata claims?',
    compares: 'subject CN vs metadata agent_id',
    on_failure: 'ERR_SUBJECT_MISMATCH',
    why: 'Binds the X.509 identity to the separate authorisation document (§7).' },
  { n: 4, check: 'not_self_signed',    section: '6.1',
    question: 'Was it issued by someone, or did it issue itself?',
    compares: 'full subject DN vs full issuer DN',
    on_failure: 'ERR_SELF_SIGNED',
    why: 'A self-signed agent certificate is an agent asserting its own authority.' },
  { n: 5, check: 'signature',          section: '6',
    question: 'Did the CA actually sign these bytes?',
    compares: 'RSA-SHA256 over tbsCertificate against the CA public key',
    on_failure: 'ERR_FORGED_ISSUER / ERR_CHAIN_INVALID' },
  { n: 6, check: 'name_constraints',   section: '6',
    question: 'Was the CA permitted to issue for this name?',
    compares: 'subject RDN sequence against the CA permitted/excluded subtrees',
    on_failure: 'ERR_NAME_CONSTRAINT',
    why: 'RFC 5280 §4.2.1.10. A valid signature says the CA DID issue it; the constraint '
       + 'says whether it MAY. Skipping this makes a validator weaker than the spec.' },
  { n: 7, check: 'validity_window',    section: '6',
    question: 'Is it being used inside its lifetime?',
    compares: 'now against notBefore and notAfter',
    on_failure: 'ERR_CERT_EXPIRED' },
  { n: 8, check: 'key_strength',       section: '6',
    question: 'Is the public key strong enough?',
    compares: 'RSA modulus bit length against the 2048-bit floor',
    on_failure: 'ERR_KEY_TOO_SMALL',
    why: 'Measured from the modulus, so a certificate misstating its own key size cannot pass.' },
]);
