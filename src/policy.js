/**
 * Dual-signature policy updates (§9.3) — stages 4, 5 and 6.
 *
 * Ported from ietf-a2a-trust-poc:
 *   services/mcp_server/policy_validator.py    validate_policy_update()
 *   services/mcp_server/policy_field_guard.py  PolicyFieldGuard
 *
 * ── The mechanism, and why it is the draft's differentiator ────────────────
 *
 * A policy update carries TWO signatures over TWO different field sets, made by
 * TWO independent keys:
 *
 *   Phase 1  owner_sig = RSA-SHA256(canonical(IDENTITY fields of the EXISTING cert))
 *            The Owner attests that identity has not moved. Note what is signed:
 *            the *existing certificate's* identity, not the incoming update. A
 *            valid owner_sig therefore says "the agent I am speaking about is
 *            still the agent you already know".
 *
 *   Phase 2  pa_sig    = RSA-SHA256(canonical(POLICY fields of the UPDATE))
 *            The Policy Authority authorises this specific change.
 *
 * Both must verify. One is never sufficient. Neither party can do the other's
 * job: the Owner cannot widen a scope without the PA, and the PA cannot alter
 * identity without the Owner. Four-eyes applied to identity mutation.
 *
 * The field guard (stage 5) is what makes that split real rather than nominal.
 * Without it, a "policy update" could simply include `can_spawn` or
 * `max_children` and the PA would be signing an identity change while everyone
 * believed it was signing policy. So those fields live in IDENTITY_FIELDS, are
 * refused in any update, and require a new certificate to change (§7.1, §8.1).
 *
 * ── Execution order ────────────────────────────────────────────────────────
 *
 * DESIGN.md numbers these 4 (dual signature), 5 (field guard), 6 (required
 * fields) for display. They EXECUTE in the reference implementation's order:
 * signature presence, then field guard, then required fields, then the two
 * cryptographic phases. That order is observable — a document that violates the
 * field guard AND carries a bad signature must report the field-guard failure,
 * because that is what policy_validator.py reports, and round-trip parity means
 * agreeing on which refusal comes first, not merely on refusing.
 */

import { extractIdentityFields, extractPolicyFields, canonicalize } from './canonical.js';
import { verifyCanonical, publicKeyFromCertificate } from './crypto-sign.js';
import { DenyError } from './errors.js';

/**
 * Fields a policy update may never carry, because changing them requires
 * re-certification (§9.1's slow lane), not two signatures.
 *
 * `org_id` used to be here and no longer is, and the distinction is worth
 * stating because it looks like a loosening and is the opposite. Under -02
 * §9.4 the policy document carries Subject, Owner and OrgID as ASSERTIONS of
 * which agent, owner and organisation the policy is for — they are checked for
 * equality against the template by `assertOwnership` and refused when they
 * disagree. They are not modifications of the certificate.
 *
 * Under -01 they could not appear in the policy at all, which meant §9.2's
 * "requester OrgID matches certificate OrgID" had nothing to compare and
 * collapsed to "the template has an OrgID". Carrying them and checking them is
 * strictly stronger than refusing to carry them.
 */
export const IMMUTABLE_CERT_FIELDS = new Set([
  'cert_serial', 'cert_issuer', 'cert_subject', 'cert_public_key',
  'cert_not_before', 'cert_not_after', 'cert_fingerprint', 'cert_chain',
  'agent_id', 'agent_uuid',
  'allowed_scopes', // the CEILING lives in the certificate; a policy sets `scopes` beneath it
  'can_spawn',      // permitted child UUIDs — new certificate required (§7.1, §8.1)
  'max_children',   // structural spawn bound — new certificate required
]);

/**
 * The complete dynamic policy document, per `-02` §9.4.
 *
 * `-01` never defined this set. It required the policy to be signed, hashed,
 * stored and integrity-checked without saying what it contains, so each
 * implementer invented a set — and different invented sets produce different
 * signatures for the same policy, which is the interoperability failure §9.3
 * exists to prevent.
 *
 * §9.4 now defines the set as COMPLETE: an unrecognised field is refused rather
 * than carried along, because a field that survives validation reads as
 * meaningful to whoever consumes the document next.
 *
 * `version` is inside this set, which is the change that closes an exploitable
 * replay — see POLICY_FIELDS in canonical.js. `content_hash` is not, because a
 * hash cannot be part of its own preimage; it travels on the envelope with the
 * two signatures.
 */
export const MODIFIABLE_POLICY_FIELDS = new Set([
  'subject', 'owner', 'org_id', 'scopes', 'spawn_targets',
  'version', 'issued_at', 'not_after',
]);

/** §9.4 — REQUIRED fields. `spawn_targets` and `not_after` are OPTIONAL. */
export const REQUIRED_POLICY_FIELDS = Object.freeze([
  'subject', 'owner', 'org_id', 'scopes', 'version', 'issued_at',
]);

/** True when the document is a policy update at all. Mirrors the PoC's guard clause. */
export function isPolicyUpdate(doc) {
  return Boolean(doc) && typeof doc === 'object' && 'policy_update' in doc;
}

/**
 * Stage 5 — the policy field guard.
 *
 * Whitelist, not blacklist: an unknown field is refused rather than ignored.
 * Ignoring it would mean the signed canonical form and the applied document
 * could differ, which is the gap a field guard exists to close.
 */
export function assertFieldGuard(policyDoc) {
  if (policyDoc === null || typeof policyDoc !== 'object' || Array.isArray(policyDoc)) {
    throw new DenyError('ERR_SCHEMA_VIOLATION', 'policy_doc must be an object');
  }

  const keys = Object.keys(policyDoc);

  const illegal = keys.filter((k) => IMMUTABLE_CERT_FIELDS.has(k)).sort();
  if (illegal.length) {
    throw new DenyError('ERR_IMMUTABLE_FIELD',
      `cannot modify ${illegal.join(', ')} via a policy update — a new certificate is required`);
  }

  const unknown = keys.filter((k) => !MODIFIABLE_POLICY_FIELDS.has(k) && k !== 'policy_update').sort();
  if (unknown.length) {
    throw new DenyError('ERR_UNKNOWN_POLICY_FIELD', `unknown policy fields: ${unknown.join(', ')}`);
  }
}

/**
 * §7.2 — Dynamic Policy Bounds. The clause the whole two-lane model rests on:
 *
 *   "Dynamic policies MUST be bounded by the static template fields. A dynamic
 *    policy MUST NOT grant scopes beyond AllowedScopes. A dynamic policy MUST
 *    NOT add spawn targets beyond CanSpawn."
 *
 * Without this, two valid signatures are enough to grant anything. The dual
 * signature proves WHO authorised a change and that it passed the gates; it says
 * nothing about whether the change stays inside the certificate's ceiling. §9.1
 * is explicit that the fast lane governs "WHAT the agent can do WITHIN THE
 * BOUNDS of the template certificate" — so the ceiling is enforced here,
 * independently of who signed.
 *
 * This is the difference between a policy layer and a second way to issue
 * authority. Changing the ceiling requires a new certificate (§9.1: "Changes
 * require full re-certification"), which is a different signer and a different
 * audit trail.
 */
export function assertWithinTemplateBounds(policyDoc, template) {
  if (template === null || typeof template !== 'object') {
    throw new DenyError('ERR_POLICY_EXCEEDS_TEMPLATE',
      'the static template is required to bound a dynamic policy');
  }

  // AllowedScopes — the template's value is the maximum, never a default.
  if ('scopes' in policyDoc) {
    const ceiling = template.allowed_scopes;
    if (!Array.isArray(ceiling)) {
      throw new DenyError('ERR_POLICY_EXCEEDS_TEMPLATE',
        'template declares no AllowedScopes to bound the policy against');
    }
    const permitted = new Set(ceiling);
    const excess = policyDoc.scopes.filter((s) => !permitted.has(s));
    if (excess.length > 0) {
      throw new DenyError('ERR_POLICY_EXCEEDS_TEMPLATE',
        `policy grants [${excess.join(', ')}] beyond template AllowedScopes [${ceiling.join(', ')}]`);
    }
  }

  // CanSpawn — the field guard already refuses can_spawn outright, which is the
  // stricter reading of §9.1 ("changes require full re-certification"). This
  // stays as defence in depth: if the guard is ever relaxed to allow narrowing,
  // the ceiling is still enforced rather than silently lost.
  // §9.4 names this `spawn_targets` in the policy; `can_spawn` remains the
  // certificate's ceiling. Two names on purpose — the grant and the bound are
  // different things, and sharing one name is what let -01 blur them.
  if ('spawn_targets' in policyDoc) {
    const ceiling = new Set(Array.isArray(template.can_spawn) ? template.can_spawn : []);
    const added = policyDoc.spawn_targets.filter((id) => !ceiling.has(id));
    if (added.length > 0) {
      throw new DenyError('ERR_SPAWN_EXCEEDS_TEMPLATE',
        `policy adds spawn targets [${added.join(', ')}] beyond template CanSpawn`);
    }
  }
}

/**
 * §9.2 — Ownership.
 *
 *   "Template ownership MUST be established at certificate signing time and
 *    embedded in the Owner and OrgID fields. Only the verified owner of the
 *    organization that signed the template MAY submit policy changes."
 *
 * A valid Owner signature proves a key was used. It does not prove that key
 * belongs to THIS template's owner — the same Owner Authority may hold policy
 * rights over many templates. Binding the submitted `owner` to the template's
 * own Owner field is what makes the signature specific to this agent.
 */
export function assertOwnership(policyDoc, template) {
  const templateOwner = template?.owner;
  if (!templateOwner) {
    throw new DenyError('ERR_OWNER_MISMATCH', 'template declares no Owner (§7.1 REQUIRED)');
  }
  if (policyDoc.owner !== templateOwner) {
    throw new DenyError('ERR_OWNER_MISMATCH',
      'policy owner does not match the template Owner established at signing time');
  }
  if (!template.org_id) {
    throw new DenyError('ERR_ORG_MISMATCH',
      'template declares no OrgID — ownership cannot be established (§7.1, §9.2)');
  }
  // §9.4 puts OrgID inside the policy document, so §9.2's "requester OrgID
  // matches certificate OrgID" is now a check this function can actually make.
  // Under -01 the field could not appear in the policy at all, which left the
  // clause with nothing to compare and reduced it to "the template has one".
  if (policyDoc.org_id !== template.org_id) {
    throw new DenyError('ERR_ORG_MISMATCH',
      'policy OrgID does not match the template OrgID (§9.2)');
  }
  // §9.6 — the signature binds the policy to a subject, so a policy signed for
  // one agent cannot be presented for another.
  if (policyDoc.subject !== undefined && template.subject !== undefined
      && policyDoc.subject !== template.subject) {
    throw new DenyError('ERR_OWNER_MISMATCH',
      'policy subject does not name the agent the template governs (§9.4)');
  }
}

/**
 * §9.4 steps 4 and 5 — a stored policy carries a version, a timestamp and a
 * content hash; a runtime agent revalidates version currency and hash integrity
 * alongside the signatures.
 *
 * The content hash is SHA-256 over the canonical policy fields, matching the
 * reference implementation's conformance vectors TV-23 and TV-24.
 */
export async function policyContentHash(policyDoc) {
  const canonical = canonicalize(extractPolicyFields(policyDoc));
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonical));
  return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * §9.4 step 5 — version currency and hash integrity, read from the storage
 * envelope rather than from the policy document itself.
 */
export async function assertPolicyIntegrity(policyDoc, {
  currentVersion = null, contentHash = undefined,
} = {}) {
  // -02 §9.6: Version lives INSIDE the signed policy document. Reading it from
  // the envelope, as -01's text invited, is what made the replay possible — the
  // number could be rewritten without invalidating a signature.
  const version = policyDoc?.version;
  // A policy update MUST move the version forward; replaying an older signed
  // policy is otherwise indistinguishable from applying a new one, because its
  // signatures still verify.
  //
  // Version is REQUIRED by §9.4, so an absent one is refused rather than
  // skipped. The previous `if (version !== undefined)` guard was a fail-open on
  // a required field: a document simply omitting the version passed the entire
  // replay-prevention check by not carrying the thing being checked.
  if (!Number.isInteger(version) || version < 1) {
    throw new DenyError('ERR_POLICY_VERSION',
      'policy version is REQUIRED and must be a positive integer (§9.4)');
  }
  if (currentVersion !== null && version <= currentVersion) {
    throw new DenyError('ERR_POLICY_VERSION',
      `policy version ${version} does not supersede the stored version ${currentVersion}`);
  }

  if (contentHash !== undefined) {
    const expected = await policyContentHash(policyDoc);
    if (contentHash !== expected) {
      throw new DenyError('ERR_CONTENT_HASH',
        'stored content hash does not match the policy document');
    }
  }
}

/** Stage 6 — required-field validation (§9.3). */
export function assertRequiredFields(policyDoc) {
  const missing = REQUIRED_POLICY_FIELDS.filter((f) => !(f in policyDoc));
  if (missing.length) {
    throw new DenyError('ERR_REQUIRED_FIELD',
      `policy update is missing ${missing.join(', ')}`);
  }
}

/**
 * Stages 4-6 in the reference implementation's execution order.
 *
 * @param {object}  input
 * @param {object}  input.document      the full event document
 * @param {string}  input.ownerCertPem  Owner Authority certificate
 * @param {string}  input.paCertPem     Policy Authority certificate
 * @returns {Promise<{applicable: boolean, detail: string, signed: object}>}
 *          `applicable:false` means the document is not a policy update, which
 *          is a PASS — the PoC returns "Not a policy update" and continues.
 */
export async function validatePolicyUpdate({ document, ownerCertPem, paCertPem, onStage = () => {} }) {
  if (!isPolicyUpdate(document)) {
    return { applicable: false, detail: 'not a policy update', signed: null };
  }

  const policyDoc = document.policy_doc;
  const ownerSig = document.owner_sig;
  const paSig = document.pa_sig;

  // ── Presence, fail-closed. Absent is refused before malformed is examined,
  //    so "you sent one signature" is never reported as "your signature is bad".
  if (!policyDoc) {
    throw new DenyError('ERR_SCHEMA_VIOLATION', 'policy_doc is missing');
  }
  if (!ownerSig && !paSig) {
    throw new DenyError('ERR_SINGLE_SIGNATURE', 'a policy update requires both owner_sig and pa_sig');
  }
  if (!ownerSig) {
    throw new DenyError('ERR_OWNER_SIG_MISSING', 'Phase 1 cannot proceed without owner_sig');
  }
  if (!paSig) {
    throw new DenyError('ERR_PA_SIG_MISSING', 'Phase 2 cannot proceed without pa_sig');
  }

  // ── Stage 5, then stage 6 — structure before cryptography. Verifying a
  //    signature over a document that should never have been accepted tells you
  //    nothing useful, and costs a keypair import to find out.
  assertFieldGuard(policyDoc);
  onStage(5, 'policy update touches no immutable certificate field');
  assertRequiredFields(policyDoc);
  onStage(6, 'owner and created_at are present');

  // ── §9.2 — only the template's verified owner may submit a change. Checked
  //    before the signatures, because a signature from the wrong owner is a
  //    different failure than a bad signature from the right one.
  const template = document.existing_cert;
  if (!template || typeof template !== 'object' || Array.isArray(template)) {
    throw new DenyError('ERR_OWNER_SIG_INVALID',
      'existing_cert is required — it is both the Phase 1 signing input and the §7.2 ceiling');
  }
  assertOwnership(policyDoc, template);


  // ── Phase 1 — owner_sig covers the EXISTING certificate's identity fields.
  const existingCert = template;
  if (!existingCert || typeof existingCert !== 'object') {
    throw new DenyError('ERR_OWNER_SIG_INVALID',
      'existing_cert is required to verify the owner signature over identity fields');
  }
  const identity = extractIdentityFields(existingCert);
  if (Object.keys(identity).length === 0) {
    throw new DenyError('ERR_OWNER_SIG_INVALID', 'existing_cert carries no identity fields to verify');
  }
  const identityCanonical = canonicalize(identity);
  const ownerKey = await publicKeyFromCertificate(ownerCertPem);
  if (!(await verifyCanonical(identityCanonical, ownerSig, ownerKey))) {
    throw new DenyError('ERR_OWNER_SIG_INVALID',
      'owner signature does not cover the certificate identity fields');
  }

  // ── Phase 2 — pa_sig covers the POLICY fields of the update.
  const policy = extractPolicyFields(policyDoc);
  const policyCanonical = canonicalize(policy);
  const paKey = await publicKeyFromCertificate(paCertPem);
  if (!(await verifyCanonical(policyCanonical, paSig, paKey))) {
    throw new DenyError('ERR_PA_SIG_INVALID',
      'Policy Authority signature does not cover the policy fields');
  }

  onStage(4, 'identity verified (Phase 1) and policy authorised (Phase 2)');

  // ── §9.4 step 5 lists the runtime order explicitly: "both signatures, version
  //    currency, hash integrity, and template bounds compliance". Bounds come
  //    LAST, after authenticity is established. That ordering is the draft's,
  //    not a preference — and it says something stronger than the reverse would:
  //    this update is authentically signed by the right parties AND still
  //    exceeds the ceiling.
  await assertPolicyIntegrity(policyDoc, {
    currentVersion: document.current_policy_version ?? null,
    contentHash: document.policy_content_hash,
  });
  assertWithinTemplateBounds(policyDoc, template);

  // A single key holding both roles defeats the point of requiring two. The
  // reference implementation catches this structurally by loading owner and PA
  // certificates from separate paths; here both are supplied by the visitor, so
  // it is checked explicitly.
  if (ownerSig === paSig) {
    throw new DenyError('ERR_SINGLE_SIGNATURE',
      'owner_sig and pa_sig are identical — one key cannot satisfy both roles');
  }

  return {
    applicable: true,
    detail: 'identity verified (Phase 1) and policy authorised (Phase 2)',
    signed: {
      identity_fields: Object.keys(identity).sort(),
      policy_fields: Object.keys(policy).sort(),
      identity_canonical: identityCanonical,
      policy_canonical: policyCanonical,
    },
  };
}
