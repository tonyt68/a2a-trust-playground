/**
 * In-browser certificate issuance — the demo-only profile.
 *
 * Everything here happens in the page. There is no backend to send a CSR to and
 * no key that ever leaves the tab; a refresh discards all of it. That is not a
 * limitation being worked around, it is the claim the page makes.
 *
 * ── The profile, and why it is shaped this way ─────────────────────────────
 *
 * Generated certificates must be impossible to mistake for production
 * credentials — guaranteed by construction, not by a label. The obvious move is
 * a CRITICAL extension saying "demo only", because RFC 5280 §4.2 requires a
 * relying party to reject a critical extension it does not recognise.
 *
 * That move is wrong, and measurably so. A critical unrecognised extension makes
 * the certificate unusable to EVERY conformant validator — including
 * `openssl verify`, which is what the reference implementation's Python calls,
 * and therefore including the round-trip proof that the playground implements
 * the draft rather than something resembling it. Verified: such a certificate
 * fails with `error 34 at 0 depth lookup: unhandled critical extension`.
 *
 * So the guarantee is moved into a CRITICAL extension validators DO implement:
 *
 *   nameConstraints, permitted dirName =
 *       C=US, O=PhalanxAI A2A Playground, OU=DEMO ONLY - NOT FOR PRODUCTION
 *
 * RFC 5280 §4.2.1.10 makes a permitted subtree a prefix test over the subject's
 * RDN sequence, so this CA is structurally incapable of issuing a certificate
 * whose DN does not say DEMO ONLY. Attempting to repurpose it for, say,
 * `CN=login.bank.example.com, O=Real Bank` is refused by any compliant
 * validator with `error 47: permitted subtree violation`.
 *
 * The demo notice is still present, as a NON-critical extension, so it shows up
 * in any certificate viewer. It is documentation; the constraint is enforcement.
 *
 * Leaves additionally get `CA:FALSE` and `keyUsage=digitalSignature`, both
 * critical, so an agent certificate can never sign another certificate, and
 * `pathlen:0` on the CA forbids intermediates. Crypto strength is normal —
 * RSA-2048, SHA-256 — because weakening it to signal "demo" would teach the
 * wrong lesson and break parity with the reference implementation.
 */

import * as asn1js from 'asn1js';
import {
  Certificate, AttributeTypeAndValue, BasicConstraints, ExtKeyUsage,
  Extension, GeneralName, GeneralSubtree, NameConstraints,
  RelativeDistinguishedNames,
} from 'pkijs';

const OID = Object.freeze({
  CN: '2.5.4.3', C: '2.5.4.6', O: '2.5.4.10', OU: '2.5.4.11',
  basicConstraints: '2.5.29.19', keyUsage: '2.5.29.15',
  extKeyUsage: '2.5.29.37', nameConstraints: '2.5.29.30',
  clientAuth: '1.3.6.1.5.5.7.3.2',
});

/**
 * Placeholder OID for the demo notice, under the joint-iso-itu-t UUID arc
 * (2.25). That arc is self-assigning from a UUID and collision-free by
 * construction, so it is a legitimate unregistered OID rather than a squatted
 * one. Swap for an IANA Private Enterprise Number when one is issued.
 */
export const DEMO_NOTICE_OID = '2.25.329800735698586629295641978511506172918';
export const DEMO_NOTICE =
  'PhalanxAI A2A Playground - demonstration only, not valid for any production use';

/** The DN prefix every generated certificate shares. The name constraint pins it. */
export const DN_PREFIX = Object.freeze([
  { oid: OID.C, value: 'US' },
  { oid: OID.O, value: 'PhalanxAI A2A Playground' },
  { oid: OID.OU, value: 'DEMO ONLY - NOT FOR PRODUCTION' },
]);

export const CA_COMMON_NAME = 'A2A-Trust-Playground-CA';
/** §12.3 and the ephemeral-identity thesis: short-lived by default. */
export const LEAF_VALIDITY_HOURS = 24;

const KEY_PARAMS = Object.freeze({
  name: 'RSASSA-PKCS1-v1_5',
  modulusLength: 2048,
  publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
  hash: 'SHA-256',
});

/**
 * Generate an RSA-2048 keypair.
 *
 * MEASURED, not estimated: Chromium on an M-series Mac generates the full
 * five-key chain (CA, Owner, PA, two agents) in ~190ms, slowest single key 80ms
 * across 15 samples. DESIGN.md's "~1-3s, show a spinner" is roughly 10x
 * pessimistic.
 *
 * That measurement decides a design question. The alternative was shipping BAKED
 * keypairs so `Load Defaults` felt instant — which would have meant every
 * visitor sharing one published private key. At 190ms there is nothing to buy,
 * so every visit mints its own keys and "refresh is the reset" is literally
 * true. The progress callback stays for slow devices, where it will rarely be
 * seen.
 *
 * The other half of DESIGN.md's note still holds: do NOT switch to ECDSA to
 * chase speed. RSA-2048 is what the reference implementation signs with, and
 * changing it breaks round-trip parity.
 */
export async function generateKeyPair() {
  return crypto.subtle.generateKey(KEY_PARAMS, true, ['sign', 'verify']);
}

/**
 * Encode a Name as `SEQUENCE OF RelativeDistinguishedName`, one attribute each.
 *
 *     Name            ::= SEQUENCE OF RelativeDistinguishedName
 *     RelativeDistinguishedName ::= SET OF AttributeTypeAndValue
 *
 * PKI.js puts every attribute into a SINGLE SET, which encodes one multi-valued
 * RDN — rendered by OpenSSL as `C=US + O=… + CN=…` rather than the usual
 * `C=US, O=…, CN=…`. Both are legal DER, but they are structurally different
 * names, and RFC 5280 §4.2.1.10 matches a permitted subtree as a PREFIX over the
 * RDN sequence. A four-attribute single RDN has no three-RDN prefix, so the CA
 * rejected the leaves it had just issued:
 *
 *     error 47 at 0 depth lookup: permitted subtree violation
 *
 * PKI.js exposes no option for this, so the schema is built here.
 */
function nameSchema(attributes) {
  return new asn1js.Sequence({
    value: attributes.map(({ oid, value }) => new asn1js.Set({
      value: [new asn1js.Sequence({
        value: [
          new asn1js.ObjectIdentifier({ value: oid }),
          new asn1js.Utf8String({ value }),
        ],
      })],
    })),
  });
}

function setName(name, commonName) {
  const attributes = [...DN_PREFIX, { oid: OID.CN, value: commonName }];
  // Populate typesAndValues so anything reading the object sees the attributes,
  // then override the encoder so what gets SIGNED is the correct structure.
  name.typesAndValues = attributes.map(({ oid, value }) => new AttributeTypeAndValue({
    type: oid, value: new asn1js.Utf8String({ value }),
  }));
  name.toSchema = () => nameSchema(attributes);
}

/** keyUsage is a BIT STRING; these are the bit positions RFC 5280 §4.2.1.3 defines. */
function keyUsageExtension(bits) {
  const buffer = new ArrayBuffer(1);
  const view = new Uint8Array(buffer);
  for (const bit of bits) view[0] |= 0x80 >> bit;
  return new Extension({
    extnID: OID.keyUsage,
    critical: true,
    extnValue: new asn1js.BitString({ valueHex: buffer }).toBER(false),
  });
}
const KEY_USAGE = Object.freeze({ digitalSignature: 0, keyCertSign: 5, cRLSign: 6 });

function demoNoticeExtension() {
  return new Extension({
    extnID: DEMO_NOTICE_OID,
    // NON-critical, deliberately. See the module header.
    critical: false,
    extnValue: new asn1js.Utf8String({ value: DEMO_NOTICE }).toBER(false),
  });
}

/** The critical nameConstraints that make the CA structurally demo-only. */
function nameConstraintsExtension() {
  // A directoryName GeneralName carries a real RelativeDistinguishedNames, not
  // a plain object — PKI.js calls toSchema() on it when encoding.
  // Same encoding problem as setName: the constraint must be a SEQUENCE OF
  // single-attribute RDNs, or it cannot prefix-match a conforming subject.
  const permittedDn = new GeneralName({ type: 4, value: new RelativeDistinguishedNames() });
  permittedDn.value.typesAndValues = DN_PREFIX.map(({ oid, value }) => new AttributeTypeAndValue({
    type: oid, value: new asn1js.Utf8String({ value }),
  }));
  permittedDn.value.toSchema = () => nameSchema(DN_PREFIX);
  const constraints = new NameConstraints({
    permittedSubtrees: [
      new GeneralSubtree({ base: permittedDn }),
      // RFC 2606 reserves .invalid; a generated cert can never name a real host.
      new GeneralSubtree({ base: new GeneralName({ type: 2, value: '.invalid' }) }),
      new GeneralSubtree({ base: new GeneralName({ type: 1, value: '.invalid' }) }),
    ],
  });
  return new Extension({
    extnID: OID.nameConstraints,
    critical: true,
    extnValue: constraints.toSchema().toBER(false),
  });
}

function serialNumber() {
  // 20 random bytes, top bit cleared so the DER INTEGER stays positive.
  const bytes = crypto.getRandomValues(new Uint8Array(20));
  bytes[0] &= 0x7f;
  return new asn1js.Integer({ valueHex: bytes.buffer });
}

async function toPem(cert, label = 'CERTIFICATE') {
  const der = new Uint8Array(cert.toSchema(true).toBER(false));
  return derToPem(der, label);
}

export function derToPem(der, label) {
  let binary = '';
  for (const b of der) binary += String.fromCharCode(b);
  const body = btoa(binary).match(/.{1,64}/g).join('\n');
  return `-----BEGIN ${label}-----\n${body}\n-----END ${label}-----\n`;
}

/** Export a private key as PKCS#8 PEM — the format OpenSSL and Web Crypto agree on. */
export async function privateKeyToPem(privateKey) {
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', privateKey));
  return derToPem(pkcs8, 'PRIVATE KEY');
}

/**
 * Issue a certificate.
 *
 * When `issuer` is omitted the certificate is self-signed and becomes the root
 * CA. Agents are never self-signed — §6.1 requires CSR -> CA, and stage 2
 * refuses a self-signed agent certificate.
 */
async function issue({ commonName, subjectKeys, issuer, isCa, now }) {
  const cert = new Certificate();
  cert.version = 2;                       // v3
  cert.serialNumber = serialNumber();

  setName(cert.subject, commonName);
  setName(cert.issuer, issuer ? issuer.commonName : commonName);

  cert.notBefore.value = now;
  cert.notAfter.value = new Date(now.getTime() + LEAF_VALIDITY_HOURS * 3600 * 1000);

  await cert.subjectPublicKeyInfo.importKey(subjectKeys.publicKey);

  cert.extensions = [
    new Extension({
      extnID: OID.basicConstraints,
      critical: true,
      extnValue: (isCa
        ? new BasicConstraints({ cA: true, pathLenConstraint: 0 })
        : new BasicConstraints({ cA: false })).toSchema().toBER(false),
    }),
    isCa
      ? keyUsageExtension([KEY_USAGE.keyCertSign, KEY_USAGE.cRLSign])
      : keyUsageExtension([KEY_USAGE.digitalSignature]),
    demoNoticeExtension(),
  ];

  if (isCa) {
    cert.extensions.push(nameConstraintsExtension());
  } else {
    cert.extensions.push(new Extension({
      extnID: OID.extKeyUsage,
      critical: true,
      extnValue: new ExtKeyUsage({ keyPurposes: [OID.clientAuth] }).toSchema().toBER(false),
    }));
  }

  await cert.sign(issuer ? issuer.privateKey : subjectKeys.privateKey, 'SHA-256');
  return cert;
}

/**
 * Mint a complete trust structure: root CA, Owner and Policy Authority (§9.3
 * requires independent keys), and one certificate per requested agent.
 *
 * @param {object}   opts
 * @param {string[]} opts.agentIds  UUID4 identities to issue for
 * @param {Date}     [opts.now]
 * @param {(step: string, i: number, total: number) => void} [opts.onProgress]
 */
export async function mintChain({ agentIds, now = new Date(), onProgress = () => {},
                                  caCommonName = CA_COMMON_NAME }) {
  const total = agentIds.length + 3;
  let step = 0;
  const progress = (label) => onProgress(label, ++step, total);

  progress('root CA');
  const caKeys = await generateKeyPair();
  const caCert = await issue({ commonName: caCommonName, subjectKeys: caKeys, isCa: true, now });
  const ca = { commonName: caCommonName, privateKey: caKeys.privateKey };

  const authorities = {};
  for (const [role, cn] of [['owner', 'owner-authority'], ['pa', 'policy-authority']]) {
    progress(cn);
    const keys = await generateKeyPair();
    const cert = await issue({ commonName: cn, subjectKeys: keys, issuer: ca, isCa: false, now });
    authorities[role] = {
      common_name: cn,
      cert_pem: await toPem(cert),
      key_pem: await privateKeyToPem(keys.privateKey),
      privateKey: keys.privateKey,
    };
  }

  const agents = [];
  for (const agentId of agentIds) {
    progress(`agent ${agentId.slice(0, 8)}`);
    const keys = await generateKeyPair();
    const cert = await issue({ commonName: agentId, subjectKeys: keys, issuer: ca, isCa: false, now });
    agents.push({
      agent_id: agentId,
      cert_pem: await toPem(cert),
      key_pem: await privateKeyToPem(keys.privateKey),
      privateKey: keys.privateKey,
    });
  }

  return {
    ca: {
      common_name: caCommonName,
      cert_pem: await toPem(caCert),
      key_pem: await privateKeyToPem(caKeys.privateKey),
      privateKey: caKeys.privateKey,
    },
    authorities,
    agents,
  };
}

/** UUID4, from the platform CSPRNG. Agent identities are never human-readable (§6). */
export function newAgentId() {
  return crypto.randomUUID();
}
