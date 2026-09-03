/**
 * Dual-signature policy updates — §11, carried in the §3.1 envelope. Stages
 * 4, 5 and 6.
 *
 * ── The mechanism ───────────────────────────────────────────────────────────
 *
 * A policy change carries TWO signatures by TWO independent keys over ONE
 * octet string: the JCS form of `body` (§3.1, §11.6).
 *
 *   owner_sig   the Owner — proves the right to change the policy (§11.3)
 *   pa_sig      the Policy Authority — proves it passed the automated gates
 *
 * Both must verify. One is never sufficient. Neither party can do the other's
 * job. The same body under both signatures is what makes a signature specific
 * to one policy: -02's Owner signature covered the certificate's identity
 * fields instead, so a valid owner_sig was identical for every later policy
 * on that agent and a rogue Policy Authority could reuse it (§11.8, "Replayed
 * Owner signature"). That was this playground's own bug, corrected here.
 *
 * ── The field guard (stage 5) is what makes the split real ─────────────────
 *
 * §11.4 defines the policy document as a COMPLETE set. A "policy update" that
 * carried `can_spawn` or `max_children` would have the Policy Authority signing
 * an identity change while everyone believed it was signing policy. Those live
 * in the certificate (§8.2), change only by re-certification, and are refused
 * here by name. The envelope members are refused inside body for a different
 * reason: a value inside body would be inside its own preimage (§11.6).
 *
 * ── Execution order ─────────────────────────────────────────────────────────
 *
 * Structure before cryptography, then §11.7 step 5 in the draft's order: both
 * signatures, version currency, hash integrity, template bounds. Bounds LAST,
 * after authenticity — so a refusal under §8.3 reports an authentic document
 * whose content is not permitted, which is a different lane from a bad
 * signature and is reported distinctly.
 */

import { ENVELOPE_FIELDS, POLICY_FIELDS, REQUIRED_POLICY_FIELDS, TEMPLATE_FIELDS } from './canonical.js';
import { verifyBody, publicKeyFromCertificate, contentHash } from './crypto-sign.js';
import { parseCertificate, subjectCN, spkiHex } from './x509.js';
import {
  validateUuid, validateText, validateScopeSet, validateTimestamp, assertFlatObject,
} from './validate-input.js';
import { DenyError } from './errors.js';

/**
 * Fields a policy may never carry, because changing them requires
 * re-certification (§11.1's slow lane), not two signatures. These are the
 * members of the Agent Template extension that §11.4 does not list.
 */
export const IMMUTABLE_CERT_FIELDS = new Set(
  TEMPLATE_FIELDS.filter((f) => !POLICY_FIELDS.includes(f)),
);

/** True when the document carries a policy envelope at all. */
export function isPolicyUpdate(doc) {
  return Boolean(doc) && typeof doc === 'object' && doc.policy !== undefined && doc.policy !== null;
}

/**
 * §3.1 — the envelope: body, owner_sig, pa_sig, and content_hash where §11.6
 * requires one. Any other member is refused. The members are not fields of
 * the document they attest to, so the "undefined field" rule of §11.4 applies
 * to body and not to them.
 */
export function assertEnvelope(envelope, { requireHash }) {
  if (envelope === null || typeof envelope !== 'object' || Array.isArray(envelope)) {
    throw new DenyError('ERR_SCHEMA_VIOLATION', 'policy must be a §3.1 envelope object');
  }
  const stray = Object.keys(envelope).filter((k) => !ENVELOPE_FIELDS.includes(k)).sort();
  if (stray.length) {
    throw new DenyError('ERR_ENVELOPE_MEMBER', `envelope carries ${stray.join(', ')}`);
  }
  if (!('body' in envelope)) throw new DenyError('ERR_SCHEMA_VIOLATION', 'envelope carries no body');
  if (requireHash && !('content_hash' in envelope)) {
    throw new DenyError('ERR_CONTENT_HASH', 'envelope carries no content_hash, which §11.7 requires a stored policy to have');
  }
}

/**
 * Stage 5 — the policy field guard. Whitelist, not blacklist: an unknown field
 * is refused rather than ignored, because a field that survives validation
 * reads as meaningful to whoever consumes the document next.
 */
export function assertFieldGuard(body) {
  if (body === null || typeof body !== 'object' || Array.isArray(body)) {
    throw new DenyError('ERR_SCHEMA_VIOLATION', 'policy body must be an object');
  }
  const keys = Object.keys(body);

  const illegal = keys.filter((k) => IMMUTABLE_CERT_FIELDS.has(k)).sort();
  if (illegal.length) {
    throw new DenyError('ERR_IMMUTABLE_FIELD',
      `cannot modify ${illegal.join(', ')} via a policy — a new certificate is required`);
  }
  const envelopeInside = keys.filter((k) => ENVELOPE_FIELDS.includes(k)).sort();
  if (envelopeInside.length) {
    throw new DenyError('ERR_UNKNOWN_POLICY_FIELD',
      `${envelopeInside.join(', ')} inside body would be inside its own preimage (§11.6)`);
  }
  const unknown = keys.filter((k) => !POLICY_FIELDS.includes(k)).sort();
  if (unknown.length) {
    throw new DenyError('ERR_UNKNOWN_POLICY_FIELD', `unknown policy fields: ${unknown.join(', ')}`);
  }
  assertFlatObject(body, 'policy');
}

/** Stage 6 — required fields (§11.4), then each member's type. */
export function assertRequiredFields(body) {
  const missing = REQUIRED_POLICY_FIELDS.filter((f) => !(f in body));
  if (missing.length) {
    throw new DenyError('ERR_REQUIRED_FIELD', `policy is missing ${missing.join(', ')}`);
  }
  validateUuid(body.subject, 'subject');
  validateText(body.owner, 'owner');
  validateText(body.org_id, 'org_id');
  validateScopeSet(body.scopes, 'scopes');
  if ('spawn_targets' in body) {
    if (!Array.isArray(body.spawn_targets)) {
      throw new DenyError('ERR_SCHEMA_VIOLATION', 'spawn_targets must be an array');
    }
    body.spawn_targets.forEach((id) => validateUuid(id, 'spawn_targets entry'));
  }
  validateTimestamp(body.issued_at, 'issued_at');
  if ('not_after' in body) validateTimestamp(body.not_after, 'not_after');
  if (!Number.isInteger(body.version) || body.version < 1) {
    throw new DenyError('ERR_POLICY_VERSION', 'policy version is REQUIRED and must be a positive integer');
  }
}

/**
 * §8.3 — Dynamic Policy Bounds. The clause the whole two-lane model rests on:
 * a policy MUST NOT grant scopes beyond AllowedScopes nor spawn targets beyond
 * CanSpawn, evaluated by the relying party against the template certificate,
 * independently of signature validity and after it.
 *
 * Without this, two valid signatures are enough to grant anything. The
 * signatures establish WHO authorized a change; they cannot establish that the
 * change was within a ceiling stated in a certificate no signature over the
 * policy covers.
 */
export function assertWithinTemplateBounds(body, template) {
  if (template === null || typeof template !== 'object') {
    throw new DenyError('ERR_POLICY_EXCEEDS_TEMPLATE',
      'the template certificate is required to bound a dynamic policy');
  }
  const ceiling = new Set(template.allowed_scopes);
  const excess = body.scopes.filter((s) => !ceiling.has(s));
  if (excess.length > 0) {
    throw new DenyError('ERR_POLICY_EXCEEDS_TEMPLATE',
      `policy grants [${excess.join(', ')}] beyond template AllowedScopes [${template.allowed_scopes.join(', ')}]`);
  }
  if ('spawn_targets' in body) {
    const permitted = new Set(template.can_spawn);
    const added = body.spawn_targets.filter((id) => !permitted.has(id));
    if (added.length > 0) {
      throw new DenyError('ERR_SPAWN_EXCEEDS_TEMPLATE',
        `policy adds spawn targets [${added.join(', ')}] beyond template CanSpawn`);
    }
  }
}

/**
 * §11.2 — Ownership. Owner and OrgID in the policy MUST match the template
 * certificate; §11.4 makes Subject match too. A valid Owner signature proves a
 * key was used; binding the submitted owner to the template's Owner is what
 * makes it specific to this agent.
 */
export function assertOwnership(body, template) {
  if (body.subject !== template.subject) {
    throw new DenyError('ERR_SUBJECT_UNKNOWN', 'policy subject does not name the agent whose template bounds it');
  }
  if (body.owner !== template.owner) {
    throw new DenyError('ERR_OWNER_MISMATCH',
      'policy owner does not match the template Owner established at signing time');
  }
  if (body.org_id !== template.org_id) {
    throw new DenyError('ERR_ORG_MISMATCH', 'policy OrgID does not match the template OrgID');
  }
}

/**
 * §11.4 and §11.6 — version currency, content-hash integrity, and the policy's
 * lifetime relative to the certificate it governs.
 *
 * The content hash is a DERIVED value: recomputed from body and compared; the
 * envelope's copy is never an input to any decision.
 */
export async function assertPolicyIntegrity(body, {
  currentVersion = null, storedHash = undefined, certNotAfter, now,
}) {
  const version = body.version;
  if (!Number.isInteger(version) || version < 1) {
    throw new DenyError('ERR_POLICY_VERSION', 'policy version is REQUIRED and must be a positive integer');
  }
  if (currentVersion !== null && version <= currentVersion) {
    throw new DenyError('ERR_POLICY_VERSION',
      `policy version ${version} does not supersede the version in force, ${currentVersion}`);
  }

  if (storedHash !== undefined) {
    const expected = await contentHash(body);
    if (storedHash !== expected) {
      throw new DenyError('ERR_CONTENT_HASH', 'stored content hash does not match the policy body');
    }
  }

  // Never valid beyond the certificate's notAfter; NotAfter can only shorten.
  const certEnd = certNotAfter.getTime();
  let effectiveEnd = certEnd;
  if ('not_after' in body) {
    const na = new Date(body.not_after).getTime();
    if (na > certEnd) {
      throw new DenyError('ERR_POLICY_EXPIRED',
        `policy NotAfter ${body.not_after} is later than the certificate's notAfter ${certNotAfter.toISOString()}`);
    }
    effectiveEnd = na;
  }
  if (now.getTime() > effectiveEnd) {
    throw new DenyError('ERR_POLICY_EXPIRED',
      `policy is presented after ${new Date(effectiveEnd).toISOString()}`);
  }
}

/**
 * Stages 4-6 over a document's policy envelope.
 *
 * @param {object}  input
 * @param {object}  input.document      the full document
 * @param {Map<string, {template: object, notAfter: Date}>} input.templates
 *                                       every agent in the chain, by subject — read from certificates
 * @param {string}  input.ownerCertPem  Owner certificate, already validated to the anchor (§9.2)
 * @param {string}  input.paCertPem     Policy Authority certificate, likewise
 * @param {Date}    input.now
 * @param {(n: number, detail: string) => void} [input.onStage]
 * @returns {Promise<{applicable: boolean, detail: string, subject: string|null}>}
 */
export async function validatePolicyUpdate({
  document, templates, ownerCertPem, paCertPem, now = new Date(), onStage = () => {},
}) {
  if (!isPolicyUpdate(document)) {
    return { applicable: false, detail: 'not a policy update', subject: null };
  }
  const envelope = document.policy;
  assertEnvelope(envelope, { requireHash: true });
  const body = envelope.body;
  const ownerSig = envelope.owner_sig;
  const paSig = envelope.pa_sig;

  // ── Presence, fail-closed. Absent is refused before malformed is examined,
  //    so "you sent one signature" is never reported as "your signature is bad".
  if (!ownerSig && !paSig) {
    throw new DenyError('ERR_SINGLE_SIGNATURE', 'a policy update requires both owner_sig and pa_sig');
  }
  if (!ownerSig) throw new DenyError('ERR_OWNER_SIG_MISSING', 'the envelope carries no owner_sig');
  if (!paSig) throw new DenyError('ERR_PA_SIG_MISSING', 'the envelope carries no pa_sig');

  // ── Stage 5, then stage 6 — structure before cryptography.
  assertFieldGuard(body);
  onStage(5, 'policy carries only §11.4 fields — nothing immutable, nothing outside the table');
  assertRequiredFields(body);
  onStage(6, 'subject, owner, org_id, scopes, version and issued_at are present and well-formed');

  // ── §11.4 — the policy governs one agent, whose template is in its certificate.
  const entry = templates.get(body.subject);
  if (!entry) {
    throw new DenyError('ERR_SUBJECT_UNKNOWN', 'policy subject is not an agent in this chain');
  }
  const { template, notAfter } = entry;
  assertOwnership(body, template);

  // ── §9.2 — the Owner certificate's subject binds the owner string to a key.
  const ownerCert = parseCertificate(ownerCertPem);
  if (subjectCN(ownerCert) !== template.owner) {
    throw new DenyError('ERR_OWNER_CERT_MISMATCH',
      `the Owner certificate names "${subjectCN(ownerCert)}", the template owner is "${template.owner}"`);
  }
  // ── §3.1 — two roles satisfied by one key is one role. Compared as keys,
  //    because PSS and ECDSA are randomized and equal signature octets would
  //    never be observed even from a single key.
  if (spkiHex(ownerCert) === spkiHex(parseCertificate(paCertPem))) {
    throw new DenyError('ERR_SINGLE_SIGNATURE', 'Owner and Policy Authority present the same public key');
  }

  // ── Stage 4 — both signatures over the JCS form of body (§3.1, §11.6).
  const ownerKey = await publicKeyFromCertificate(ownerCertPem);
  if (!(await verifyBody(body, ownerSig, ownerKey))) {
    throw new DenyError('ERR_OWNER_SIG_INVALID', 'owner signature does not verify over the policy body');
  }
  const paKey = await publicKeyFromCertificate(paCertPem);
  if (!(await verifyBody(body, paSig, paKey))) {
    throw new DenyError('ERR_PA_SIG_INVALID', 'Policy Authority signature does not verify over the policy body');
  }
  onStage(4, 'Owner and Policy Authority signatures both verify over the same body');

  // ── §11.7 step 5, in order: version currency, hash, then bounds LAST.
  await assertPolicyIntegrity(body, {
    currentVersion: document.current_policy_version ?? null,
    storedHash: envelope.content_hash,
    certNotAfter: notAfter,
    now,
  });
  assertWithinTemplateBounds(body, template);

  return {
    applicable: true,
    detail: `policy v${body.version} for ${body.subject.slice(0, 8)}… dual-signed, current, hash intact, within bounds`,
    subject: body.subject,
  };
}
