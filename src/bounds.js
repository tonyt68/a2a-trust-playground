/**
 * Revocation (§14), the two-check spawn rule (§10.1), the MaxChildren
 * consistency check (§10.2), scope containment (§10.3) and cross-organizational
 * grants (§13) — stages 3, 7 and 8.
 *
 * ── Where authorisation actually lives ─────────────────────────────────────
 *
 * In the certificate, since -03. §8.2 carries the template's static fields in
 * the Agent Template extension, signed by the CA; §10.5 carries the parent link
 * in the Agent Spawn extension, likewise. So every bound consulted here was
 * read out of a certificate that has already verified to the anchor, never out
 * of a document the agent assembled. The chain document restates identifiers
 * and carries the request; it asserts no authority.
 *
 *   allowed_scopes   what this agent may hold                — ceiling for §11
 *   can_spawn        which children it may instantiate       — §10.1 Check 1
 *   permitted_operations  whether it may spawn at all        — §10.1 Check 1
 *   max_children     how many at once; the Registry enforces — §10.2, consistency here
 *
 * ── Fail-closed is a real rule here, not a slogan ──────────────────────────
 *
 * An unreadable CRL is not an empty CRL. A missing grant is not permission.
 * Refusals name what was absent so the pipeline is diagnostic, not merely
 * correct.
 */

import { DenyError } from './errors.js';
import {
  validateScopeSet, validateUuid, validateText, validateInteger, validateTimestamp,
  assertFlatObject, FRESHNESS_WINDOW_MS,
} from './validate-input.js';
import { GRANT_FIELDS, ENVELOPE_FIELDS } from './canonical.js';
import { publicKeyFromCertificate, verifyBody } from './crypto-sign.js';
import { parseCertificate, subjectCN, spkiHex } from './x509.js';

/**
 * Stage 3 — revocation (§14) and the Registry's DISABLED state (§12.4).
 *
 * `crl.revoked` models the CA's revocation state. `crl.disabled` models the
 * Registry's DISABLED list, which §12.4 says is NOT a CRL entry: it is reported
 * by the Registry in Check 2 of §10.1. The page plays the Registry, so it
 * consults that list here; the refusal says which of the two it was.
 */
export function assertNotRevoked({ agentId, crl }) {
  // Fail closed: an unreadable CRL is not an empty CRL.
  if (crl === null || typeof crl !== 'object' || Array.isArray(crl)) {
    throw new DenyError('ERR_AGENT_REVOKED', 'revocation list is unreadable — failing closed');
  }
  const revoked = crl.revoked ?? [];
  const disabled = crl.disabled ?? [];
  if (!Array.isArray(revoked) || !Array.isArray(disabled)) {
    throw new DenyError('ERR_AGENT_REVOKED', 'revocation list is malformed — failing closed');
  }
  if (revoked.includes(agentId)) {
    throw new DenyError('ERR_AGENT_REVOKED', 'certificate is on the revocation list');
  }
  if (disabled.includes(agentId)) {
    throw new DenyError('ERR_AGENT_DISABLED',
      'template is DISABLED at the Registry (§12.4) — not a revocation; no new spawns are accepted from it');
  }
}

/**
 * Stage 7 — §10.1 Check 1, read from the PARENT's Agent Template extension:
 * the parent holds `spawn`, and the child is in its CanSpawn list. Check 2 (the
 * child is registered, CA-signed, not revoked, not DISABLED, and owned by the
 * right organization) is stages 2 and 3 applied to the child, plus the grant
 * check below.
 *
 * The sibling count is a CONSISTENCY check on the document (§10.2). The
 * Registry holds the count MaxChildren is compared against and enforces it
 * atomically at spawn time; a stateless page cannot, and the draft forbids
 * presenting a document-local count as enforcement.
 */
export function assertSpawnPermitted({ parentTemplate, childId, siblings = 0 }) {
  validateUuid(childId, 'child agent_id');
  if (!parentTemplate.permitted_operations.includes('spawn')) {
    throw new DenyError('ERR_SPAWN_NOT_PERMITTED',
      `parent PermittedOperations is [${parentTemplate.permitted_operations.join(', ')}] — spawn is not among them`);
  }
  if (!parentTemplate.can_spawn.includes(childId)) {
    throw new DenyError('ERR_CHILD_NOT_WHITELISTED',
      'child is not in the parent CanSpawn list — a new certificate is required to add it');
  }
  // A zero cap means no children, not unlimited.
  if (siblings + 1 > parentTemplate.max_children) {
    throw new DenyError('ERR_MAX_CHILDREN',
      `the document names ${siblings + 1} child(ren) of a parent whose MaxChildren is ${parentTemplate.max_children}`);
  }
}

/**
 * §10.2 step 3 — the child is a SpawnTargets entry of the policy in force for
 * the spawning agent. The Registry evaluates this when it issues, against the
 * policy it retrieves through policy_ref; a chain document carries the
 * policies it says were in force, and this is the same consistency reading
 * §10.2 gives MaxChildren: the document must agree with the cap the Registry
 * enforced. An absent policy grants nothing (§11.4), and no policy in force is
 * a refusal under §15.1, not a pass.
 *
 * @param {object} opts
 * @param {object|null} opts.policy  the parent's in-force policy body, or null when none is
 * @param {string} opts.childId
 * @param {string} [opts.parentId]   for the detail only
 */
export function assertSpawnInPolicy({ policy, childId, parentId = null }) {
  validateUuid(childId, 'child agent_id');
  const who = parentId ? ` for ${parentId.slice(0, 8)}…` : '';
  if (policy === null || typeof policy !== 'object') {
    throw new DenyError('ERR_SPAWN_NOT_IN_POLICY',
      `no policy is in force${who} — step 3 of §10.2 cannot have passed, and no policy grants no spawn targets`);
  }
  const targets = Array.isArray(policy.spawn_targets) ? policy.spawn_targets : [];
  if (!targets.includes(childId)) {
    throw new DenyError('ERR_SPAWN_NOT_IN_POLICY',
      `the policy in force${who} (version ${policy.version}) grants ${targets.length} spawn target(s), and the child is not among them`);
  }
}

/**
 * Stage 8 — scope containment (§10.3), fail-closed.
 *
 * Set containment over opaque tokens: `requested ⊆ allowed`. No wildcards, no
 * prefix matching, no hierarchy, no case folding — §10.3 forbids all four.
 * Comparison is on the parsed set; the order on the wire is left alone.
 *
 * A request for no scopes is refused: the empty set is a subset of every set,
 * so it satisfies the test vacuously while declaring no intent for it to bound.
 */
export function assertScopeSubset(requested, allowed, { label = 'requested' } = {}) {
  validateScopeSet(requested, `${label} scopes`);
  validateScopeSet(allowed, 'allowed_scopes');

  if (requested.length === 0) {
    throw new DenyError('ERR_EMPTY_SCOPES', 'an agent must declare the scopes it requests');
  }

  const permitted = new Set(allowed);
  const excess = requested.filter((s) => !permitted.has(s));
  if (excess.length > 0) {
    throw new DenyError('ERR_SCOPE_ESCALATION',
      `${label} [${excess.join(', ')}] not subset of [${allowed.join(', ')}]`);
  }
  return true;
}

/**
 * Cross-organizational grant (§13.2), as a §3.1 envelope. Evaluated when a
 * child's template is owned by an organization other than its parent's.
 *
 * Everything below is a MUST of §13.1-§13.3 except the last, which is the
 * same document-consistency reading of MaxSpawns that §10.2 gives MaxChildren:
 * the Grantor's Registry enforces the cap; the document is checked for
 * coherence with it.
 *
 * @param {object} opts
 * @param {object} opts.grant           the envelope from the document
 * @param {object} opts.childTemplate   the template being granted (from the child's certificate)
 * @param {object} opts.parentTemplate  the spawning agent's template (from its certificate)
 * @param {string} opts.ownerCertPem    the grantor's Owner certificate, already validated to the anchor
 * @param {string} opts.paCertPem       the grantor's Policy Authority certificate, likewise
 * @param {Date}   opts.now
 * @param {number} [opts.spawnsUnderGrant]  children this document names under the grant
 */
export async function validateGrant({
  grant, childTemplate, parentTemplate, ownerCertPem, paCertPem, now, spawnsUnderGrant = 1,
}) {
  if (grant === null || typeof grant !== 'object' || Array.isArray(grant)) {
    throw new DenyError('ERR_GRANT_INVALID', 'grant is not an envelope');
  }
  const stray = Object.keys(grant).filter((k) => !ENVELOPE_FIELDS.includes(k)).sort();
  if (stray.length) {
    throw new DenyError('ERR_ENVELOPE_MEMBER', `grant envelope carries ${stray.join(', ')}`);
  }
  if ('content_hash' in grant) {
    throw new DenyError('ERR_ENVELOPE_MEMBER',
      'grant envelope carries content_hash, which §11.6 requires of a policy and not of a grant');
  }
  const body = grant.body;
  if (body === null || typeof body !== 'object' || Array.isArray(body)) {
    throw new DenyError('ERR_GRANT_INVALID', 'grant body is missing');
  }
  assertFlatObject(body, 'grant');
  const keys = Object.keys(body);
  const missing = GRANT_FIELDS.filter((f) => !keys.includes(f));
  if (missing.length) throw new DenyError('ERR_GRANT_INVALID', `grant omits ${missing.join(', ')}`);
  const extra = keys.filter((k) => !GRANT_FIELDS.includes(k)).sort();
  if (extra.length) throw new DenyError('ERR_GRANT_INVALID', `grant carries ${extra.join(', ')}, which Table 11 does not define`);

  try {
    validateUuid(body.grant_id, 'grant_id');
    validateText(body.grantor, 'grantor');
    validateText(body.grantee, 'grantee');
    validateUuid(body.template, 'template');
    validateScopeSet(body.allowed_scopes, 'allowed_scopes');
    validateTimestamp(body.issued_at, 'issued_at');
    validateInteger(body.ttl_seconds, 'ttl_seconds', 1, 10 * 365 * 86400);
    validateInteger(body.max_spawns, 'max_spawns', 0, 1_000_000);
  } catch (e) {
    if (e instanceof DenyError && e.code !== 'ERR_FIELD_CHARSET' && e.code !== 'ERR_FIELD_RANGE'
        && e.code !== 'ERR_SCHEMA_VIOLATION' && e.code !== 'ERR_AGENT_ID_FORMAT') throw e;
    throw new DenyError('ERR_GRANT_INVALID', e.detail || e.message);
  }

  // Addressed to the right parties: the grantor owns the template, the grantee
  // is the spawning agent's organization, and the template is the one spawned.
  if (body.template !== childTemplate.subject) {
    throw new DenyError('ERR_GRANT_INVALID', 'grant names a template other than the one being spawned');
  }
  if (body.grantor !== childTemplate.org_id) {
    throw new DenyError('ERR_GRANT_INVALID',
      `grantor "${body.grantor}" is not the organization that owns the template ("${childTemplate.org_id}")`);
  }
  if (body.grantee !== parentTemplate.org_id) {
    throw new DenyError('ERR_GRANT_INVALID',
      `grantee "${body.grantee}" is not the spawning agent's organization ("${parentTemplate.org_id}")`);
  }

  // Time: expired at IssuedAt + TTL; dated in the future by more than the window.
  const issued = new Date(body.issued_at).getTime();
  if (issued > now.getTime() + FRESHNESS_WINDOW_MS) {
    throw new DenyError('ERR_GRANT_EXPIRED', 'grant is dated later than this clock by more than the freshness window');
  }
  const expiry = issued + body.ttl_seconds * 1000;
  if (now.getTime() > expiry) {
    throw new DenyError('ERR_GRANT_EXPIRED', `grant expired at ${new Date(expiry).toISOString()}`);
  }

  // Bounded by the template it grants.
  const ceiling = new Set(childTemplate.allowed_scopes);
  const excess = body.allowed_scopes.filter((s) => !ceiling.has(s));
  if (excess.length) {
    throw new DenyError('ERR_GRANT_EXCEEDS_TEMPLATE',
      `grant allows [${excess.join(', ')}] beyond the template's AllowedScopes`);
  }

  // Signed by the grantor's Owner and Policy Authority (§13.2), whose
  // certificates the relying party has validated to its anchor (§13.3), over
  // the JCS form of the body (§3.1), by two distinct keys.
  if (!grant.owner_sig || !grant.pa_sig) {
    throw new DenyError('ERR_GRANT_INVALID',
      `grant carries ${grant.owner_sig ? 'no Policy Authority' : 'no Owner'} signature`);
  }
  const ownerCert = parseCertificate(ownerCertPem);
  if (subjectCN(ownerCert) !== childTemplate.owner) {
    throw new DenyError('ERR_OWNER_CERT_MISMATCH',
      'the Owner certificate does not name the owner of the granted template');
  }
  if (spkiHex(ownerCert) === spkiHex(parseCertificate(paCertPem))) {
    throw new DenyError('ERR_SINGLE_SIGNATURE', 'Owner and Policy Authority present the same public key');
  }
  const ownerKey = await publicKeyFromCertificate(ownerCertPem);
  const paKey = await publicKeyFromCertificate(paCertPem);
  if (!(await verifyBody(body, grant.owner_sig, ownerKey))) {
    throw new DenyError('ERR_GRANT_INVALID', 'Owner signature does not verify over the grant');
  }
  if (!(await verifyBody(body, grant.pa_sig, paKey))) {
    throw new DenyError('ERR_GRANT_INVALID', 'Policy Authority signature does not verify over the grant');
  }

  if (spawnsUnderGrant > body.max_spawns) {
    throw new DenyError('ERR_MAX_SPAWNS',
      `the document names ${spawnsUnderGrant} agent(s) under a grant whose MaxSpawns is ${body.max_spawns}`);
  }
  return body;
}
