/**
 * In-browser issuance — the Registry, and the certificate profile it issues.
 *
 * Everything here happens in the page. There is no backend to send a CSR to and
 * no key that ever leaves the tab; a refresh discards all of it. That is not a
 * limitation being worked around, it is the claim the page makes.
 *
 * ── Two layers, on purpose ──────────────────────────────────────────────────
 *
 *   Registry           the gates: §9.1 conformance, §9.2 dual attestation, §9.3
 *                      issuance (re-gate, re-verify, copy members unaltered,
 *                      notAfter bound to ttl_seconds), the six steps of §10.2
 *                      at spawn time — Check 1 from the parent's certificate,
 *                      the grant of §13.2, the policy in force (step 3), scope
 *                      containment, the MaxChildren count it holds, one live
 *                      certificate per template — and the §19.2 freshness
 *                      window and nonce store. Every spawn request, accepted
 *                      or refused, becomes a §10.4 audit entry.
 *
 *   issueCertificate   the CA's signing primitive. No gate. Anyone holding the
 *                      CA key can call it with whatever they like — which is
 *                      exactly what a compromised or careless CA does, and what
 *                      the relying party's checks exist to catch. The sabotage
 *                      buttons that need a certificate the Registry would never
 *                      issue use this layer with the CA key the document carries.
 *
 * ── The profile ─────────────────────────────────────────────────────────────
 *
 * Keys are P-256. §7.1 requires 128-bit security and RECOMMENDS EC over RSA:
 * RSA-3072 takes roughly a second per key in a browser, P-256 takes a few
 * milliseconds, and "every visit mints its own keys" only works at the latter.
 * Both certificate extensions are CRITICAL (§8.2, §10.5). Every non-root
 * certificate carries cRLDistributionPoints pointing at a `.invalid` host
 * (§14.4, RFC 2606): honest that there is no live CRL, and consistent with the
 * name-constraint posture that nothing here can ever name a real host.
 *
 * Generated certificates must be impossible to mistake for production
 * credentials, by construction: the CA carries a critical nameConstraints
 * permitting only `C=US, O=PhalanxAI A2A Playground, OU=DEMO ONLY - NOT FOR
 * PRODUCTION`. RFC 5280 §4.2.1.10 makes that a prefix test over the subject's
 * RDN sequence, so this CA is structurally incapable of issuing a certificate
 * whose DN does not say DEMO ONLY. The demo notice is also present as a
 * NON-critical extension, so it shows up in any certificate viewer. It is
 * documentation; the constraint is enforcement.
 */

import * as asn1js from 'asn1js';
import {
  Certificate, AttributeTypeAndValue, BasicConstraints, ExtKeyUsage,
  Extension, GeneralName, GeneralSubtree, NameConstraints,
  RelativeDistinguishedNames, CRLDistributionPoints, DistributionPoint,
} from 'pkijs';
import { preimage } from './crypto-sign.js';
import { signBody, verifyBody, publicKeyFromCertificate, signEnvelope } from './crypto-sign.js';
import {
  TEMPLATE_EXT_OID, SPAWN_EXT_OID, assertTemplateMembers, parseCertificate, subjectCN, OID, KEY_USAGE,
  MAX_SERIAL_OCTETS,
} from './x509.js';
import {
  validateTimestamp, validateNonce, validateScopeSet, FRESHNESS_WINDOW_MS,
} from './validate-input.js';
import { validateGrant } from './bounds.js';
import {
  assertEnvelope, assertFieldGuard, assertRequiredFields, assertWithinTemplateBounds,
} from './policy.js';
import { AuditChain, spawnEntry } from './audit-chain.js';
import { DenyError } from './errors.js';
import { bytesToBase64 } from './encoding.js';

/** §19.2 — re-exported so the page and the tests read the window from the issuer. */
export { FRESHNESS_WINDOW_MS };

/**
 * The demo-notice OID, under the joint-iso-itu-t UUID arc (2.25). The arc is
 * self-assigning from a UUID: 2.25.<decimal of the UUID>. This one is the
 * decimal form of UUIDv4 15b1bbb1-6b8d-451b-80e9-636fbe6e69cd. That gives it a
 * negligible collision probability with any other 2.25 OID — the same
 * guarantee as the UUID itself, and no more. The previous value decoded to the
 * RFC 4122 example UUID, which is the one value under that arc guaranteed to be
 * used by everyone.
 */
export const DEMO_NOTICE_OID = '2.25.28836631322710226650474936410307455437';
export const DEMO_NOTICE =
  'PhalanxAI A2A Playground - demonstration only, not valid for any production use';

/** The DN prefix every generated certificate shares. The name constraint pins it. */
export const DN_PREFIX = Object.freeze([
  { oid: OID.C, value: 'US' },
  { oid: OID.O, value: 'PhalanxAI A2A Playground' },
  { oid: OID.OU, value: 'DEMO ONLY - NOT FOR PRODUCTION' },
]);

export const CA_COMMON_NAME = 'A2A-Trust-Playground-CA';
export const OWNER_COMMON_NAME = 'owner-authority';
export const PA_COMMON_NAME = 'policy-authority';
/** §14.4 — where revocation state lives. RFC 2606 reserves .invalid, so this can never resolve. */
export const CRL_URI = 'http://crl.a2a-playground.invalid/ca.crl';
/** Authority certificates are not bound to a template TTL; one day, same as the seed's parent. */
export const AUTHORITY_VALIDITY_SECONDS = 86400;
/**
 * §7.1 — random octets drawn for a serial. Nineteen, not twenty: RFC 5280 caps
 * the INTEGER at twenty octets and a top bit that happens to be set needs one
 * more for the sign, so the draw leaves room for it.
 */
export const SERIAL_RANDOM_OCTETS = MAX_SERIAL_OCTETS - 1;
/**
 * §8.2 — this store lays out PolicyRef as `policy-store/{subject}/current`
 * (defaults.js), which is how the Registry resolves a ref to the subject it
 * holds a policy for.
 */
const POLICY_REF = /^policy-store\/([0-9a-f-]{36})\/current$/;

const KEY_PARAMS = Object.freeze({ name: 'ECDSA', namedCurve: 'P-256' });

/** Generate a P-256 keypair (§7.1: 128-bit security, EC RECOMMENDED). */
export async function generateKeyPair() {
  return crypto.subtle.generateKey(KEY_PARAMS, true, ['sign', 'verify']);
}

/**
 * Encode a Name as `SEQUENCE OF RelativeDistinguishedName`, one attribute each.
 * PKI.js puts every attribute into a SINGLE SET, which encodes one multi-valued
 * RDN. Both are legal DER, but RFC 5280 §4.2.1.10 matches a permitted subtree
 * as a PREFIX over the RDN sequence, and a four-attribute single RDN has no
 * three-RDN prefix — so the CA rejected the leaves it had just issued.
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

function demoNoticeExtension() {
  return new Extension({
    extnID: DEMO_NOTICE_OID,
    critical: false,   // documentation, not enforcement — see the module header
    extnValue: new asn1js.Utf8String({ value: DEMO_NOTICE }).toBER(false),
  });
}

/** The critical nameConstraints that make the CA structurally demo-only. */
function nameConstraintsExtension() {
  const permittedDn = new GeneralName({ type: 4, value: new RelativeDistinguishedNames() });
  permittedDn.value.typesAndValues = DN_PREFIX.map(({ oid, value }) => new AttributeTypeAndValue({
    type: oid, value: new asn1js.Utf8String({ value }),
  }));
  permittedDn.value.toSchema = () => nameSchema(DN_PREFIX);
  const constraints = new NameConstraints({
    permittedSubtrees: [
      new GeneralSubtree({ base: permittedDn }),
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

/** §14.4 — cRLDistributionPoints, non-critical as RFC 5280 recommends. */
function crlDistributionPointsExtension() {
  const cdp = new CRLDistributionPoints({
    distributionPoints: [new DistributionPoint({
      distributionPoint: [new GeneralName({ type: 6, value: CRL_URI })],
    })],
  });
  return new Extension({
    extnID: OID.crlDistributionPoints,
    critical: false,
    extnValue: cdp.toSchema().toBER(false),
  });
}

/**
 * §8.2 / §10.5 — a DER OCTET STRING whose contents are the UTF-8 JCS
 * serialization of the object. The OCTET STRING is the extnValue itself; there
 * is no inner ASN.1 type, so what a relying party decodes is exactly the JCS
 * bytes and a byte-comparison against its own canonicalization is meaningful.
 */
function jcsExtension(oid, obj) {
  return new Extension({ extnID: oid, critical: true, extnValue: preimage(obj).buffer });
}

/**
 * §7.1 — a positive INTEGER in minimal DER, at most twenty octets, carrying
 * every bit it was given. The procedure is the draft's: draw the random
 * octets (at most nineteen, so a prepended octet stays within the limit),
 * strip any leading zero octets, and prepend a single 0x00 only when the
 * first remaining octet has its top bit set. Clearing the top bit instead
 * would spend a bit of entropy and, one draw in 256, emit a leading zero
 * followed by an octet under 0x80 — a non-minimal encoding strict parsers
 * refuse.
 *
 * @param {number} [bytes]        octets of CSPRNG output, 1–19; §7.1 requires at least eight
 * @param {Uint8Array} [octets]   use these content octets verbatim — the raw issuer's override
 */
function serialNumber(bytes = SERIAL_RANDOM_OCTETS, octets = null) {
  if (octets) {
    return new asn1js.Integer({ valueHex: Uint8Array.from(octets).buffer });
  }
  const raw = crypto.getRandomValues(new Uint8Array(Math.max(1, Math.min(bytes, SERIAL_RANDOM_OCTETS))));
  let start = 0;
  while (start < raw.length - 1 && raw[start] === 0x00) start++;
  const significant = raw.subarray(start);
  const content = significant[0] & 0x80
    ? Uint8Array.from([0x00, ...significant])
    : Uint8Array.from(significant);
  return new asn1js.Integer({ valueHex: content.buffer });
}

export async function toPem(cert, label = 'CERTIFICATE') {
  const der = new Uint8Array(cert.toSchema(true).toBER(false));
  return derToPem(der, label);
}

export function derToPem(der, label) {
  const body = bytesToBase64(der).match(/.{1,64}/g).join('\n');
  return `-----BEGIN ${label}-----\n${body}\n-----END ${label}-----\n`;
}

/** Export a private key as PKCS#8 PEM — the format OpenSSL and Web Crypto agree on. */
export async function privateKeyToPem(privateKey) {
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', privateKey));
  return derToPem(pkcs8, 'PRIVATE KEY');
}

/**
 * The CA's signing primitive. No gate — see the module header.
 *
 * @param {object}   opts
 * @param {string}   opts.commonName
 * @param {CryptoKey} opts.subjectPublicKey
 * @param {{commonName: string, privateKey: CryptoKey}} [opts.issuer]  omitted = self-signed root
 * @param {boolean}  [opts.isCa]
 * @param {Date}     opts.notBefore
 * @param {Date}     opts.notAfter
 * @param {object}   [opts.template]   Agent Template extension members (§8.2)
 * @param {object}   [opts.spawn]      Agent Spawn extension members (§10.5)
 * @param {number[]} [opts.keyUsageBits]  override the profile's keyUsage
 * @param {number}   [opts.serialBytes]   override the number of random serial octets
 * @param {Uint8Array} [opts.serialOctets] use these serial content octets verbatim
 * @param {boolean}  [opts.revocationSource]  false omits cRLDistributionPoints
 * @param {boolean}  [opts.criticalExtensions] false marks the profile extensions non-critical
 */
export async function issueCertificate({
  commonName, subjectPublicKey, issuer = null, isCa = false, notBefore, notAfter,
  template = null, spawn = null, keyUsageBits = null, serialBytes = SERIAL_RANDOM_OCTETS,
  serialOctets = null, revocationSource = true, criticalExtensions = true, selfSignKey = null,
}) {
  const cert = new Certificate();
  cert.version = 2;                       // v3
  cert.serialNumber = serialNumber(serialBytes, serialOctets);

  setName(cert.subject, commonName);
  setName(cert.issuer, issuer ? issuer.commonName : commonName);

  cert.notBefore.value = notBefore;
  cert.notAfter.value = notAfter;

  await cert.subjectPublicKeyInfo.importKey(subjectPublicKey);

  cert.extensions = [
    new Extension({
      extnID: OID.basicConstraints,
      critical: true,
      extnValue: (isCa
        ? new BasicConstraints({ cA: true, pathLenConstraint: 0 })
        : new BasicConstraints({ cA: false })).toSchema().toBER(false),
    }),
    keyUsageExtension(keyUsageBits ?? (isCa
      ? [KEY_USAGE.keyCertSign, KEY_USAGE.cRLSign]
      : [KEY_USAGE.digitalSignature])),
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
    if (revocationSource) cert.extensions.push(crlDistributionPointsExtension());
  }
  if (template) {
    const ext = jcsExtension(TEMPLATE_EXT_OID, template);
    ext.critical = criticalExtensions;
    cert.extensions.push(ext);
  }
  if (spawn) {
    const ext = jcsExtension(SPAWN_EXT_OID, spawn);
    ext.critical = criticalExtensions;
    cert.extensions.push(ext);
  }

  const signingKey = issuer ? issuer.privateKey : selfSignKey;
  if (!signingKey) throw new Error('issueCertificate: no signing key');
  await cert.sign(signingKey, 'SHA-256');
  return cert;
}

/**
 * §10.1 Check 1 — read from the PARENT's Agent Template extension: it holds
 * `spawn`, and the child is in its CanSpawn list. Shared with bounds.js's
 * `assertSpawnPermitted` (which adds the §10.2 sibling-count consistency
 * check a relying party performs on a document; this Registry enforces
 * MaxChildren from the count it holds instead), so the Registry's own gate at
 * issuance and the relying party's check on the resulting certificate cannot
 * silently disagree about what the rule means.
 */
export function assertCanSpawn(parentTemplate, childId) {
  if (!parentTemplate.permitted_operations.includes('spawn')) {
    throw new DenyError('ERR_SPAWN_NOT_PERMITTED',
      `parent PermittedOperations is [${parentTemplate.permitted_operations.join(', ')}] — spawn is not among them`);
  }
  if (!parentTemplate.can_spawn.includes(childId)) {
    throw new DenyError('ERR_CHILD_NOT_WHITELISTED',
      'child is not in the parent CanSpawn list — a new certificate is required to add it');
  }
}

/** Base64 of 128 bits from the platform CSPRNG (§19.2). */
export function newNonce() {
  return bytesToBase64(crypto.getRandomValues(new Uint8Array(16)));
}

/**
 * The Template Registry and its CA, as one logical entity (§4).
 *
 * Holds the CA key, the Owner and Policy Authority keys, the policy store, the
 * counts §10.2 step 5 compares against, the nonces it has seen, and the audit
 * log of §10.4. The two authorities are minted here because the playground
 * plays every role; in a deployment the Owner's key belongs to the template
 * owner and is never in the Registry's hands.
 */
export class Registry {
  constructor({ commonName, ca, authorities, now }) {
    this.commonName = commonName;
    this.ca = ca;                       // { cert, cert_pem, key_pem, privateKey }
    this.authorities = authorities;     // { owner, pa } each { common_name, cert, cert_pem, key_pem, privateKey }
    this.now = now;
    /** §19.2 — every nonce PRESENTED to this Registry, accepted or refused. Retained for the life of the tab, which exceeds twice the window. */
    this.seenNonces = new Set();
    /** §11 — the policy store: subject → the policy body in force for it. */
    this.policies = new Map();
    /** §10.2 step 5 — subject → notAfter of the certificate this Registry issued for it. One identity, one certificate (§12.1). */
    this.live = new Map();
    /** §10.2 step 5 — parent subject → the children it has spawned. This is the count MaxChildren is compared against. */
    this.children = new Map();
    /** §13.2 — grant_id → spawns issued under it. This is the count MaxSpawns is compared against. */
    this.grantSpawns = new Map();
    /** §10.4 — every spawn request, accepted or refused, plus this Registry's other decisions. */
    this.audit = new AuditChain();
  }

  /**
   * Mint a Registry: root CA, Owner and Policy Authority (§9.2 — independent
   * keys, each holding a CA-issued certificate).
   */
  static async create({ caCommonName = CA_COMMON_NAME, now = new Date(), onProgress = () => {} } = {}) {
    onProgress('root CA', 1, 3);
    const caKeys = await generateKeyPair();
    const caCert = await issueCertificate({
      commonName: caCommonName, subjectPublicKey: caKeys.publicKey, isCa: true,
      notBefore: now, notAfter: new Date(now.getTime() + AUTHORITY_VALIDITY_SECONDS * 1000),
      selfSignKey: caKeys.privateKey,
    });
    const ca = {
      common_name: caCommonName, cert: caCert, cert_pem: await toPem(caCert),
      key_pem: await privateKeyToPem(caKeys.privateKey), privateKey: caKeys.privateKey,
    };
    const issuer = { commonName: caCommonName, privateKey: caKeys.privateKey };

    const authorities = {};
    let step = 1;
    for (const [role, cn] of [['owner', OWNER_COMMON_NAME], ['pa', PA_COMMON_NAME]]) {
      onProgress(cn, ++step, 3);
      const keys = await generateKeyPair();
      const cert = await issueCertificate({
        commonName: cn, subjectPublicKey: keys.publicKey, issuer, isCa: false,
        notBefore: now, notAfter: new Date(now.getTime() + AUTHORITY_VALIDITY_SECONDS * 1000),
      });
      authorities[role] = {
        common_name: cn, cert, cert_pem: await toPem(cert),
        key_pem: await privateKeyToPem(keys.privateKey), privateKey: keys.privateKey,
      };
    }
    return new Registry({ commonName: caCommonName, ca, authorities, now });
  }

  /**
   * Rebuild a Registry from a document that carries its keys, so the page can
   * re-issue under the anchor the document already trusts. The policy store is
   * rebuilt from the envelopes the document says are in force, each verified
   * under the authorities before it is kept. The nonce store, the live set and
   * the counts start empty: a rebuilt Registry has forgotten what it issued,
   * which is the failure §19.2's retention rule exists to name.
   */
  static async fromDocument(doc, { now = new Date() } = {}) {
    const { privateKeyFromPem } = await import('./crypto-sign.js');
    const anchor = (doc.chain ?? []).find((n) => n.role === 'ca');
    if (!anchor?.cert_pem || !anchor?.key_pem) {
      throw new DenyError('ERR_SCHEMA_VIOLATION', 'document carries no trust anchor key to issue under');
    }
    const caCert = parseCertificate(anchor.cert_pem);
    const ca = {
      common_name: subjectCN(caCert), cert: caCert, cert_pem: anchor.cert_pem,
      key_pem: anchor.key_pem, privateKey: await privateKeyFromPem(anchor.key_pem),
    };
    const authorities = {};
    for (const role of ['owner', 'pa']) {
      const a = doc.authorities?.[role];
      if (!a?.cert_pem || !a?.key_pem) {
        throw new DenyError('ERR_SCHEMA_VIOLATION', `document carries no ${role} authority key`);
      }
      const cert = parseCertificate(a.cert_pem);
      authorities[role] = {
        common_name: subjectCN(cert), cert, cert_pem: a.cert_pem, key_pem: a.key_pem,
        privateKey: await privateKeyFromPem(a.key_pem),
      };
    }
    const registry = new Registry({ commonName: ca.common_name, ca, authorities, now });
    const policies = doc.policies ?? [];
    if (!Array.isArray(policies)) {
      throw new DenyError('ERR_SCHEMA_VIOLATION', 'policies must be an array of §3.1 envelopes');
    }
    for (const envelope of policies) await registry.adoptEnvelope(envelope);
    return registry;
  }

  get issuer() {
    return { commonName: this.commonName, privateKey: this.ca.privateKey };
  }

  /**
   * §9.1 — the conformance gate. Every REQUIRED member present, typed and
   * non-null, before anything is signed. Applied again at issuance.
   */
  static conformanceGate(template) {
    return assertTemplateMembers(template, 'ERR_TEMPLATE_NONCONFORMING');
  }

  /**
   * §9.2 — dual attestation. Gate first (a signature over an incomplete body
   * is a valid signature over an incomplete body), then both signatures over
   * the JCS form of the template, by the Owner and the Policy Authority.
   *
   * @returns {Promise<{body: object, owner_sig: string, pa_sig: string}>}
   */
  async attest(template) {
    // A snapshot, not the caller's object: what was signed must not move
    // when the caller later edits their copy.
    const body = { ...Registry.conformanceGate(template) };
    if (body.owner !== this.authorities.owner.common_name) {
      throw new DenyError('ERR_OWNER_CERT_MISMATCH',
        `template owner "${body.owner}" is not the Owner certificate's subject "${this.authorities.owner.common_name}"`);
    }
    return {
      body,
      owner_sig: await signBody(body, this.authorities.owner.privateKey),
      pa_sig: await signBody(body, this.authorities.pa.privateKey),
    };
  }

  /**
   * §9.3 — issuance. Re-apply the gate, re-verify both signatures, copy the
   * signed members into the Agent Template extension unaltered, set the
   * subject CN from the subject member, and bind notAfter to ttl_seconds.
   *
   * @param {{body: object, owner_sig: string, pa_sig: string}} attested
   * @param {object} opts
   * @param {CryptoKeyPair} [opts.subjectKeys]  omitted = a fresh P-256 pair
   * @param {object} [opts.spawn]   Agent Spawn members for a child (§10.5)
   * @param {Date}   [opts.now]
   * @param {boolean} [opts.record] false when `spawn()` is recording the event itself
   */
  async issue(attested, { subjectKeys = null, spawn = null, now = this.now, record = true } = {}) {
    if (!attested || typeof attested !== 'object') {
      throw new DenyError('ERR_TEMPLATE_SIGNATURE', 'nothing to issue: no attested template');
    }
    // §11.6 — a content hash is a member of a POLICY envelope only.
    if ('content_hash' in attested) {
      throw new DenyError('ERR_ENVELOPE_MEMBER',
        'a template envelope carries no content_hash — §11.6 gives that member to a policy, not a template');
    }
    // The gate again. A template that was conforming when signed can be edited
    // afterwards; trusting the signature without re-checking would issue a
    // certificate missing a member the relying party requires.
    const body = Registry.conformanceGate(attested.body);
    if (!attested.owner_sig || !attested.pa_sig) {
      throw new DenyError('ERR_TEMPLATE_SIGNATURE',
        `template carries ${attested.owner_sig ? 'no Policy Authority' : 'no Owner'} signature`);
    }
    if (body.owner !== this.authorities.owner.common_name) {
      throw new DenyError('ERR_OWNER_CERT_MISMATCH',
        `template owner "${body.owner}" is not the Owner certificate's subject`);
    }
    const ownerKey = await publicKeyFromCertificate(this.authorities.owner.cert_pem);
    const paKey = await publicKeyFromCertificate(this.authorities.pa.cert_pem);
    if (!(await verifyBody(body, attested.owner_sig, ownerKey))) {
      throw new DenyError('ERR_TEMPLATE_SIGNATURE', 'Owner signature does not verify over the template');
    }
    if (!(await verifyBody(body, attested.pa_sig, paKey))) {
      throw new DenyError('ERR_TEMPLATE_SIGNATURE', 'Policy Authority signature does not verify over the template');
    }

    const keys = subjectKeys ?? await generateKeyPair();
    const notAfter = new Date(now.getTime() + body.ttl_seconds * 1000);
    const cert = await issueCertificate({
      commonName: body.subject, subjectPublicKey: keys.publicKey, issuer: this.issuer,
      notBefore: now, notAfter, template: body, spawn,
    });
    this.live.set(body.subject, notAfter);
    if (record) {
      await this.audit.append({
        action: 'issue_template', outcome: 'ALLOWED', agent: body.subject,
        detail: 'template attested and issued by the Registry',
      }, now);
    }
    return {
      agent_id: body.subject,
      cert, cert_pem: await toPem(cert),
      key_pem: await privateKeyToPem(keys.privateKey), privateKey: keys.privateKey,
      template: body, spawn,
    };
  }

  /**
   * §10.2 step 3 — the policy in force for an agent, retrieved through the
   * PolicyRef of its certificate and never from anything the agent supplies.
   * A ref this store cannot resolve names no policy, and no policy grants no
   * spawn targets (§11.4).
   */
  policyInForce(policyRef) {
    const m = POLICY_REF.exec(String(policyRef ?? ''));
    return m ? (this.policies.get(m[1]) ?? null) : null;
  }

  /**
   * §11.7 steps 1–4, with the page playing every role: the body passes the
   * field guard and the automated gate against the template it governs
   * (§8.3), the Owner signs and the Policy Authority countersigns, and the
   * store keeps it in force for its subject. A version that does not
   * supersede the one in force is refused (§11.4).
   *
   * @returns {Promise<object>} the §3.1 envelope, content_hash included
   */
  async adoptPolicy(body, { template = null, now = this.now } = {}) {
    assertFieldGuard(body);
    assertRequiredFields(body);
    if (template) assertWithinTemplateBounds(body, template);
    const current = this.policies.get(body.subject);
    if (current && body.version <= current.version) {
      throw new DenyError('ERR_POLICY_VERSION',
        `policy version ${body.version} does not supersede the version in force, ${current.version}`);
    }
    const envelope = await signEnvelope({ ...body },
      this.authorities.owner.privateKey, this.authorities.pa.privateKey, { withHash: true });
    this.policies.set(body.subject, envelope.body);
    await this.audit.append({
      action: 'policy_update', outcome: 'ALLOWED', agent: body.subject,
      detail: `dual-signed policy in force, version ${body.version}`,
    }, now);
    return envelope;
  }

  /**
   * The policy a freshly issued template starts under: its own ceiling as the
   * scopes, and the spawn targets the caller grants — by default everything
   * CanSpawn names, which is what a deployment does the day it registers a
   * template and before any policy narrows it.
   */
  async adoptPolicyFor(template, { spawnTargets = template.can_spawn, scopes = template.allowed_scopes,
                                   version = 1, now = this.now } = {}) {
    return this.adoptPolicy({
      subject: template.subject, owner: template.owner, org_id: template.org_id,
      scopes: [...scopes], spawn_targets: [...spawnTargets], version, issued_at: now.toISOString(),
    }, { template, now });
  }

  /**
   * Rebuild one in-force policy from its envelope, as `fromDocument` does:
   * both signatures verified under this Registry's authorities before the
   * body is kept. A store that adopts what it is handed is a store an editor
   * can fill.
   */
  async adoptEnvelope(envelope) {
    assertEnvelope(envelope, { requireHash: true });
    assertFieldGuard(envelope.body);
    assertRequiredFields(envelope.body);
    const ownerKey = await publicKeyFromCertificate(this.authorities.owner.cert_pem);
    const paKey = await publicKeyFromCertificate(this.authorities.pa.cert_pem);
    if (!(await verifyBody(envelope.body, envelope.owner_sig, ownerKey))) {
      throw new DenyError('ERR_OWNER_SIG_INVALID', 'a policy in force: owner signature does not verify over the body');
    }
    if (!(await verifyBody(envelope.body, envelope.pa_sig, paKey))) {
      throw new DenyError('ERR_PA_SIG_INVALID', 'a policy in force: Policy Authority signature does not verify over the body');
    }
    this.policies.set(envelope.body.subject, envelope.body);
  }

  /**
   * §10.2 — a spawn request, evaluated by the Registry in the draft's order:
   *
   *   §19.2  freshness and the nonce, which is spent by being PRESENTED
   *   1      Check 1 from the parent's Agent Template extension (§10.1)
   *   2      ownership: the child's organization is the parent's, or a grant
   *          under §13.2 names the parent's organization as Grantee
   *   3      the child is a SpawnTargets entry of the policy in force for the
   *          parent, retrieved through the parent's policy_ref (§11.4)
   *   4      scope containment (§10.3)
   *   5      the count this Registry holds is below MaxChildren, and the child
   *          template has no live certificate already (§12.1)
   *   6      issuance with the Agent Spawn extension (§10.5)
   *
   * Every request becomes a §10.4 audit entry, accepted or refused.
   *
   * @param {object} opts
   * @param {{body: object, owner_sig: string, pa_sig: string}} opts.attested  the child template
   * @param {object} opts.parent        the PARENT's Agent Template members, from its certificate
   * @param {string} [opts.requestedAt] the request timestamp (RFC 3339, Z)
   * @param {string} [opts.nonce]       the request nonce (base64, ≥128 bits)
   * @param {Date}   [opts.now]         the Registry's clock
   * @param {CryptoKeyPair} [opts.subjectKeys]
   * @param {object} [opts.grant]       the §3.1 grant envelope, for a cross-organizational spawn
   */
  async spawn({ attested, parent, requestedAt = null, nonce = null, now = this.now, subjectKeys = null, grant = null }) {
    const body = Registry.conformanceGate(attested?.body);
    const parentTemplate = Registry.conformanceGate(parent);
    const at = requestedAt ?? now.toISOString();
    const n = nonce ?? newNonce();
    validateTimestamp(at, 'spawned_at');
    validateNonce(n, 'spawn_nonce');

    // §19.2 — a nonce is spent by being presented, not by being accepted. It
    // is recorded here, before any step below is evaluated, so a request
    // refused at any step has still consumed it and a retry must bring a
    // fresh one. Recording only accepted nonces would let a refused request
    // be replayed until something changed and it was accepted.
    if (this.seenNonces.has(n)) {
      throw new DenyError('ERR_NONCE_REUSED', 'this Registry has already seen a request with this nonce');
    }
    this.seenNonces.add(n);

    const crossOrg = body.org_id !== parentTemplate.org_id;
    const requested = Array.isArray(body.allowed_scopes) ? [...body.allowed_scopes] : [];
    let grantId = null;
    const record = (outcome, reason = null) => this.audit.append(spawnEntry({
      spawningAgentId: parentTemplate.subject, childTemplateId: body.subject,
      requestedScopes: requested, spawnNonce: n, grantId, outcome, reason,
    }), now);

    try {
      // §19.2 — more than sixty seconds from this clock, either direction, is
      // refused. The measured offset goes in the detail so the boundary is
      // visible rather than "roughly a minute".
      const offsetMs = new Date(at).getTime() - now.getTime();
      if (Math.abs(offsetMs) > FRESHNESS_WINDOW_MS) {
        const s = (Math.abs(offsetMs) / 1000).toFixed(1);
        throw new DenyError('ERR_SPAWN_STALE',
          `request timestamp is ${s} s in the ${offsetMs < 0 ? 'past' : 'future'}; the window is 60 s`);
      }

      // Step 1 — §10.1 Check 1, from the parent's certificate, never from the request.
      assertCanSpawn(parentTemplate, body.subject);

      // Step 2 — registered (this Registry attested it: the gate above), and
      // owned by the parent's organization or granted to it (§13).
      if (crossOrg) {
        if (!grant) {
          throw new DenyError('ERR_GRANT_MISSING',
            `${body.org_id} has issued no grant to ${parentTemplate.org_id} — no implicit trust exists between organizations`);
        }
        const under = (this.grantSpawns.get(grant?.body?.grant_id) ?? 0) + 1;
        const g = await validateGrant({
          grant, childTemplate: body, parentTemplate,
          ownerCertPem: this.authorities.owner.cert_pem, paCertPem: this.authorities.pa.cert_pem,
          now, spawnsUnderGrant: under,
        });
        grantId = g.grant_id;
      }

      // Step 3 — the policy in force for the parent, through its policy_ref.
      const policy = this.policyInForce(parentTemplate.policy_ref);
      if (!policy) {
        throw new DenyError('ERR_SPAWN_NOT_IN_POLICY',
          `no policy is in force for ${parentTemplate.subject.slice(0, 8)}… — no policy grants no spawn targets`);
      }
      const targets = Array.isArray(policy.spawn_targets) ? policy.spawn_targets : [];
      if (!targets.includes(body.subject)) {
        throw new DenyError('ERR_SPAWN_NOT_IN_POLICY',
          `the policy in force (version ${policy.version}) grants ${targets.length} spawn target(s), and the child is not among them — CanSpawn is the ceiling, SpawnTargets is what is currently authorized within it`);
      }

      // Step 4 — §10.3: child scopes within the parent's. A child issued with
      // no scopes at all is refused HERE too, not only later at the pipeline's
      // stage 8 — the Registry should not mint what the relying party will
      // then refuse.
      validateScopeSet(body.allowed_scopes, 'allowed_scopes');
      if (body.allowed_scopes.length === 0) {
        throw new DenyError('ERR_EMPTY_SCOPES', 'a child template must declare at least one scope');
      }
      const held = new Set(parentTemplate.allowed_scopes);
      const excess = body.allowed_scopes.filter((s) => !held.has(s));
      if (excess.length) {
        throw new DenyError('ERR_SCOPE_ESCALATION',
          `child would hold [${excess.join(', ')}], which the parent does not`);
      }

      // Step 5 — the count this Registry holds, compared atomically with
      // recording the child (a page is single-threaded; a deployment locks),
      // and one live certificate per template (§12.1).
      const kids = this.children.get(parentTemplate.subject) ?? new Set();
      if (kids.size >= parentTemplate.max_children) {
        throw new DenyError('ERR_MAX_CHILDREN',
          `the parent has ${kids.size} live child(ren) and its MaxChildren is ${parentTemplate.max_children} — enforced here, by the Registry that holds the count`);
      }
      const liveUntil = this.live.get(body.subject);
      if (liveUntil && liveUntil > now) {
        throw new DenyError('ERR_DUPLICATE_SUBJECT',
          `a certificate for ${body.subject.slice(0, 8)}… is live until ${liveUntil.toISOString()} — a template defines one agent, and one identity holds one certificate (§10.2 step 5)`);
      }

      // Step 6 — issuance, which re-runs the §9.1 gate and re-verifies both
      // attestation signatures; a refusal there is a refusal of this request.
      const spawn = { parent_agent_id: parentTemplate.subject, spawned_at: at, spawn_nonce: n };
      if (grantId) spawn.grant_id = grantId;
      const issued = await this.issue(attested, { subjectKeys, now, spawn, record: false });
      kids.add(body.subject);
      this.children.set(parentTemplate.subject, kids);
      if (grantId) this.grantSpawns.set(grantId, (this.grantSpawns.get(grantId) ?? 0) + 1);
      await record('ALLOWED');
      return issued;
    } catch (e) {
      // §10.4 — a refused request is recorded for the same reason an accepted
      // one is: a sequence of refusals is the evidence of an attempt.
      if (e instanceof DenyError) await record('DENIED', `${e.code}: ${e.detail || e.title}`);
      throw e;
    }
  }
}

/**
 * Mint a complete trust structure: Registry (CA, Owner, PA), a root
 * orchestrator with a policy in force granting it its child, and optionally
 * that child spawned from it.
 *
 * @param {object}   opts
 * @param {object}   opts.parent    the parent's template members (§8.2)
 * @param {object}   [opts.child]   the child's template members
 * @param {Date}     [opts.now]
 * @param {string}   [opts.caCommonName]
 * @param {(step: string, i: number, total: number) => void} [opts.onProgress]
 */
export async function mintChain({ parent, child = null, now = new Date(), onProgress = () => {},
                                  caCommonName = CA_COMMON_NAME }) {
  const total = child ? 5 : 4;
  const registry = await Registry.create({ caCommonName, now, onProgress: (l, i) => onProgress(l, i, total) });

  onProgress(`agent ${parent.subject.slice(0, 8)}`, 4, total);
  const parentAgent = await registry.issue(await registry.attest(parent), { now });
  // §10.2 step 3 needs a policy in force before anything can be spawned. The
  // parent's grants exactly the child it is about to spawn, and nothing else.
  const policies = [await registry.adoptPolicyFor(parent, { spawnTargets: child ? [child.subject] : [], now })];
  const agents = [parentAgent];
  if (child) {
    onProgress(`agent ${child.subject.slice(0, 8)}`, 5, total);
    agents.push(await registry.spawn({ attested: await registry.attest(child), parent, now }));
    policies.push(await registry.adoptPolicyFor(child, { spawnTargets: [], now }));
  }

  const strip = ({ common_name, cert_pem, key_pem, privateKey }) => ({ common_name, cert_pem, key_pem, privateKey });
  return {
    registry,
    ca: strip(registry.ca),
    authorities: { owner: strip(registry.authorities.owner), pa: strip(registry.authorities.pa) },
    agents,
    policies,
  };
}

/**
 * A fresh agent identifier: UUID version 7 (RFC 9562 §5.7), 48 bits of
 * millisecond timestamp and 74 bits from the platform CSPRNG.
 *
 * §7.2 leaves the version to the implementation — SHOULD v4 where creation
 * time should not be inferable, MAY v7 where ordering is wanted. This
 * playground chooses v7 so that identifiers sort in the order they were minted,
 * which makes a chain document readable; the disclosure §19.8 describes is of
 * no consequence for a demo whose certificates expire the next day. Validation
 * accepts any RFC 9562 version, because a spec should not prefer the option
 * that discloses more even where an implementation may.
 */
export function newAgentId() {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  const ms = BigInt(Date.now());
  for (let i = 0; i < 6; i++) bytes[i] = Number((ms >> BigInt(8 * (5 - i))) & 0xffn);
  bytes[6] = (bytes[6] & 0x0f) | 0x70;   // version 7
  bytes[8] = (bytes[8] & 0x3f) | 0x80;   // RFC 9562 variant
  const hex = Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
