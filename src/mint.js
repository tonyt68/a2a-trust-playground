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
 *                      notAfter bound to ttl_seconds), §10.1 Check 1 and §19.2
 *                      freshness and nonce uniqueness at spawn time.
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
import { signBody, verifyBody, publicKeyFromCertificate } from './crypto-sign.js';
import {
  TEMPLATE_EXT_OID, SPAWN_EXT_OID, assertTemplateMembers, parseCertificate, subjectCN, OID, KEY_USAGE,
} from './x509.js';
import { validateTimestamp, validateNonce, validateScopeSet } from './validate-input.js';
import { DenyError } from './errors.js';
import { bytesToBase64 } from './encoding.js';

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
/** §19.2 — sixty seconds, either direction. */
export const FRESHNESS_WINDOW_MS = 60_000;

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

/** @param {number} [bytes] octets of CSPRNG output; §7.1 requires at least eight */
function serialNumber(bytes = 20) {
  const raw = crypto.getRandomValues(new Uint8Array(bytes));
  // DER INTEGER encoding is minimal (X.690 §8.3.2): a leading 0x00 is legal
  // ONLY when the next octet's high bit is set, to keep the value positive.
  // Clearing the top bit outright would spend one bit of entropy and, on the
  // 1-in-256 draw where it lands on 0x00 followed by another octet under
  // 0x80, emit a non-minimal encoding that strict DER parsers refuse.
  if (!(raw[0] & 0x80)) return new asn1js.Integer({ valueHex: raw.buffer });
  const padded = new Uint8Array(bytes + 1);
  padded.set(raw, 1);
  return new asn1js.Integer({ valueHex: padded.buffer });
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
 * @param {number}   [opts.serialBytes]   override the serial length
 * @param {boolean}  [opts.revocationSource]  false omits cRLDistributionPoints
 * @param {boolean}  [opts.criticalExtensions] false marks the profile extensions non-critical
 */
export async function issueCertificate({
  commonName, subjectPublicKey, issuer = null, isCa = false, notBefore, notAfter,
  template = null, spawn = null, keyUsageBits = null, serialBytes = 20,
  revocationSource = true, criticalExtensions = true, selfSignKey = null,
}) {
  const cert = new Certificate();
  cert.version = 2;                       // v3
  cert.serialNumber = serialNumber(serialBytes);

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
 * check this Registry does not need — a real, stateful CA enforces
 * MaxChildren by holding the count, not by re-deriving it here), so the
 * Registry's own gate at issuance and the relying party's check on the
 * resulting certificate cannot silently disagree about what the rule means.
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
 * Holds the CA key, the Owner and Policy Authority keys, and the set of spawn
 * nonces it has issued. The two authorities are minted here because the
 * playground plays every role; in a deployment the Owner's key belongs to the
 * template owner and is never in the Registry's hands.
 */
export class Registry {
  constructor({ commonName, ca, authorities, now }) {
    this.commonName = commonName;
    this.ca = ca;                       // { cert, cert_pem, key_pem, privateKey }
    this.authorities = authorities;     // { owner, pa } each { common_name, cert, cert_pem, key_pem, privateKey }
    this.now = now;
    /** §19.2 — nonces this Registry has accepted. Retained for the life of the tab, which exceeds twice the window. */
    this.seenNonces = new Set();
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
   * re-issue under the anchor the document already trusts. The nonce store
   * starts empty: a rebuilt Registry has forgotten what it issued, which is the
   * failure §19.2's retention rule exists to name.
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
    return new Registry({ commonName: ca.common_name, ca, authorities, now });
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
   */
  async issue(attested, { subjectKeys = null, spawn = null, now = this.now } = {}) {
    if (!attested || typeof attested !== 'object') {
      throw new DenyError('ERR_TEMPLATE_SIGNATURE', 'nothing to issue: no attested template');
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
    const cert = await issueCertificate({
      commonName: body.subject, subjectPublicKey: keys.publicKey, issuer: this.issuer,
      notBefore: now, notAfter: new Date(now.getTime() + body.ttl_seconds * 1000),
      template: body, spawn,
    });
    return {
      agent_id: body.subject,
      cert, cert_pem: await toPem(cert),
      key_pem: await privateKeyToPem(keys.privateKey), privateKey: keys.privateKey,
      template: body, spawn,
    };
  }

  /**
   * §10.2 — a spawn request, evaluated by the Registry. Check 1 against the
   * parent's Agent Template extension (§10.1), the scope check (§10.3), and
   * the freshness window and nonce uniqueness of §19.2. Then issuance with the
   * Agent Spawn extension (§10.5).
   *
   * MaxChildren (step 4) is the Registry's count, not the document's; this
   * Registry keeps none because the page never holds more than one chain.
   *
   * @param {object} opts
   * @param {{body: object, owner_sig: string, pa_sig: string}} opts.attested  the child template
   * @param {object} opts.parent        the PARENT's Agent Template members, from its certificate
   * @param {string} [opts.requestedAt] the request timestamp (RFC 3339, Z)
   * @param {string} [opts.nonce]       the request nonce (base64, ≥128 bits)
   * @param {Date}   [opts.now]         the Registry's clock
   * @param {CryptoKeyPair} [opts.subjectKeys]
   */
  async spawn({ attested, parent, requestedAt = null, nonce = null, now = this.now, subjectKeys = null }) {
    const body = Registry.conformanceGate(attested?.body);
    const parentTemplate = Registry.conformanceGate(parent);
    const at = requestedAt ?? now.toISOString();
    const n = nonce ?? newNonce();
    validateTimestamp(at, 'spawned_at');
    validateNonce(n, 'spawn_nonce');

    // §19.2 — more than sixty seconds from this clock, either direction, is
    // refused. The measured offset goes in the detail so the boundary is
    // visible rather than "roughly a minute".
    const offsetMs = new Date(at).getTime() - now.getTime();
    if (Math.abs(offsetMs) > FRESHNESS_WINDOW_MS) {
      const s = (Math.abs(offsetMs) / 1000).toFixed(1);
      throw new DenyError('ERR_SPAWN_STALE',
        `request timestamp is ${s} s in the ${offsetMs < 0 ? 'past' : 'future'}; the window is 60 s`);
    }
    if (this.seenNonces.has(n)) {
      throw new DenyError('ERR_NONCE_REUSED', 'this Registry has already accepted a request with this nonce');
    }

    // §10.1 Check 1 — from the parent's certificate, never from the request.
    assertCanSpawn(parentTemplate, body.subject);
    // §10.3 — child scopes within the parent's. A child issued with no scopes
    // at all is refused HERE too, not only later at the pipeline's stage 8 —
    // the Registry should not mint what the relying party will then refuse.
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

    // Only now is the nonce spent: `issue()` re-runs the §9.1 gate and
    // re-verifies both attestation signatures, and a request that fails THERE
    // must be retryable under the same nonce — the nonce names the SPAWN
    // REQUEST, and a request the Registry never accepted was never spent.
    const issued = await this.issue(attested, {
      subjectKeys, now,
      spawn: { parent_agent_id: parentTemplate.subject, spawned_at: at, spawn_nonce: n },
    });
    this.seenNonces.add(n);
    return issued;
  }
}

/**
 * Mint a complete trust structure: Registry (CA, Owner, PA), a root
 * orchestrator, and optionally one child spawned from it.
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
  const agents = [parentAgent];
  if (child) {
    onProgress(`agent ${child.subject.slice(0, 8)}`, 5, total);
    agents.push(await registry.spawn({ attested: await registry.attest(child), parent, now }));
  }

  const strip = ({ common_name, cert_pem, key_pem, privateKey }) => ({ common_name, cert_pem, key_pem, privateKey });
  return {
    registry,
    ca: strip(registry.ca),
    authorities: { owner: strip(registry.authorities.owner), pa: strip(registry.authorities.pa) },
    agents,
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

