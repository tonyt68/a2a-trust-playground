/**
 * Revocation and authorization bounds — stages 3, 7 and 8.
 *
 * Ported from ietf-a2a-trust-poc:
 *   services/mcp_server/cert_manager.py            check_crl()            -> stage 3
 *   services/mcp_server/policy_authority_chain.py  chain of custody       -> stage 3
 *   services/mcp_server/cert_validator.py          parse_auth_bounds()    -> stage 7
 *                                                  validate_spawn_check1()
 *                                                  validate_max_children()
 *                                                  validate_scope_subset() -> stage 8
 *
 * ── Where authorisation actually lives ─────────────────────────────────────
 *
 * Not in the certificate. The certificate says *who* (§6); this document says
 * *may they* (§7). Three fields carry it, and they are not interchangeable:
 *
 *   allowed_scopes   what this agent may do            — MUTABLE via §9.3
 *   can_spawn        which children it may instantiate — IMMUTABLE, new cert
 *   max_children     how many it may have at once      — IMMUTABLE, new cert
 *
 * The two immutable ones are the structural bounds. A policy update cannot widen
 * them (stage 5 refuses), so an agent's blast radius is fixed at issuance and can
 * only grow by the CA issuing a new certificate — a decision with a different
 * signer and a different audit trail than a policy change.
 *
 * ── Fail-closed is a real rule here, not a slogan ──────────────────────────
 *
 * `service.py` denies when bounds are absent or unparseable rather than treating
 * a missing field as an empty permission set. Both refuse the request, so the
 * difference looks academic — until the metadata is malformed for a reason the
 * visitor should see. Reporting "bounds unparseable" rather than "scope not
 * permitted" is what makes the pipeline diagnostic instead of merely correct.
 */

import { DenyError } from './errors.js';
import { validateScopeSet, validateUuid4, validateInteger, MAX_CHILDREN } from './validate-input.js';

/**
 * Stage 3 — revocation and chain of custody (§12).
 *
 * The reference implementation keeps the CRL on disk and checks three things:
 * revoked, disabled, and TTL expiry. In-memory here, same three checks. §12.3
 * requires TTL expiry to be automatic rather than a manual revocation step, so
 * an elapsed `expires_at` is a revocation whether or not anyone listed it.
 *
 * @param {object} opts
 * @param {string} opts.agentId
 * @param {{revoked?: string[], disabled?: string[]}} opts.crl
 * @param {object} opts.metadata
 * @param {Date}   [opts.now]
 */
export function assertNotRevoked({ agentId, crl, metadata, now = new Date() }) {
  // Fail closed: an unreadable CRL is not an empty CRL. cert_manager.check_crl
  // returns False (deny) when the list cannot be loaded, and so does this.
  if (crl === null || typeof crl !== 'object' || Array.isArray(crl)) {
    throw new DenyError('ERR_AGENT_REVOKED', 'revocation list is unreadable — failing closed');
  }

  const revoked = crl.revoked ?? [];
  const disabled = crl.disabled ?? [];
  if (!Array.isArray(revoked) || !Array.isArray(disabled)) {
    throw new DenyError('ERR_AGENT_REVOKED', 'revocation list is malformed — failing closed');
  }

  if (revoked.includes(agentId)) {
    throw new DenyError('ERR_AGENT_REVOKED', 'agent is on the revocation list');
  }
  if (disabled.includes(agentId)) {
    throw new DenyError('ERR_AGENT_REVOKED', 'agent is disabled');
  }

  const expiresAt = metadata?.expires_at;
  if (expiresAt) {
    const t = Date.parse(expiresAt);
    if (Number.isNaN(t)) {
      throw new DenyError('ERR_TTL_EXPIRED', 'expires_at is unparseable — failing closed');
    }
    if (now.getTime() > t) {
      throw new DenyError('ERR_TTL_EXPIRED', `agent TTL elapsed at ${new Date(t).toISOString()}`);
    }
  }
}

/**
 * Stage 2's state check (§10.4), kept here with the other metadata-driven rules.
 * The lifecycle is ACTIVE -> DISABLED -> DELETED and only ACTIVE is authorised.
 */
export const AGENT_STATES = Object.freeze(['ACTIVE', 'DISABLED', 'DELETED']);

export function assertActive(metadata) {
  const state = metadata?.state;
  if (state === undefined) {
    // The reference treats a missing state as ACTIVE. This does not: a document
    // that omits its own lifecycle field is malformed, and defaulting it to the
    // one permissive value is the shape of a fail-open bug.
    throw new DenyError('ERR_AGENT_DISABLED', 'metadata does not declare a state');
  }
  if (!AGENT_STATES.includes(state)) {
    throw new DenyError('ERR_AGENT_DISABLED', `unknown state — expected one of ${AGENT_STATES.join(', ')}`);
  }
  if (state !== 'ACTIVE') {
    throw new DenyError('ERR_AGENT_DISABLED', `agent state is ${state}`);
  }
}

/**
 * The §7.1 static fields, plus the operational fields setup_keys.py emits.
 *
 * A whitelist, because DESIGN.md's input contract says unknown keys are
 * REJECTED, not ignored. Found by the red-team pass: a document carrying
 * `"admin": true` or `"rebac_override": true` in agent metadata validated
 * cleanly. Those keys are inert today — nothing reads them — which is exactly
 * why silently accepting them is the wrong behaviour: the next field added to
 * this schema would be silently ignored on a document that predates it, and a
 * reader of the JSON would reasonably assume a key that survives validation
 * means something.
 */
export const KNOWN_METADATA_FIELDS = new Set([
  // §7.1 static fields, all REQUIRED
  'subject', 'agent_id', 'agent_uuid', 'issuer', 'owner', 'org_id', 'permitted_operations',
  'allowed_scopes', 'can_spawn', 'max_children', 'policy_ref',
  'ttl_seconds',
  // operational
  'template_version', 'state', 'created_at', 'expires_at', 'cert_path', 'key_path',
  'parent_agent_id', 'authorization_bounds', 'updated_at', 'description', 'tags',
  // cert-derived identity fields the reference implementation recognises
  'cert_serial', 'cert_issuer', 'cert_subject', 'cert_public_key',
  'cert_not_before', 'cert_not_after', 'cert_fingerprint', 'cert_chain',
]);

export function assertKnownMetadataFields(metadata) {
  const unknown = Object.keys(metadata)
    .filter((k) => !KNOWN_METADATA_FIELDS.has(k)).sort();
  if (unknown.length) {
    throw new DenyError('ERR_SCHEMA_VIOLATION',
      `metadata contains unknown field(s): ${unknown.join(', ')}`);
  }
}

/**
 * `cert_path` and `key_path` name files, and this document is meant to be
 * RECONSTITUTED — the round-trip harness writes a directory from it, and so
 * would any other consumer.
 *
 * In the browser they are inert strings. That is exactly the trap: nothing here
 * dereferences them, so nothing here noticed that
 * `cert_path: "../../../../etc/passwd"` validated cleanly and was then handed on
 * in the export as though it had been checked. A field that survives validation
 * reads as validated to whoever consumes it next.
 *
 * So they are pinned to the shape setup_keys.py emits — `certs/{uuid4}.crt` —
 * and nothing else. No traversal, no absolute paths, no alternate directory.
 */
const CERT_PATH = /^certs\/[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.crt$/;
const KEY_PATH = /^certs\/[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.key$/;

export function assertSafePaths(metadata) {
  for (const [field, pattern] of [['cert_path', CERT_PATH], ['key_path', KEY_PATH]]) {
    const value = metadata[field];
    if (value === undefined) continue;
    if (typeof value !== 'string' || !pattern.test(value)) {
      throw new DenyError('ERR_SCHEMA_VIOLATION',
        `${field} must be exactly certs/{agent-uuid}.${field === 'cert_path' ? 'crt' : 'key'}`);
    }
    // Belt and braces: the anchored regex cannot match these, but a future edit
    // to it might, and this is the check whose absence caused the finding.
    if (value.includes('..') || value.includes('//') || value.startsWith('/')) {
      throw new DenyError('ERR_SCHEMA_VIOLATION', `${field} contains a path traversal sequence`);
    }
  }
}

/**
 * Stage 7 — parse and validate the authorization bounds (§7).
 *
 * `authorization_bounds` is a deliberate duplicate of three top-level fields;
 * `service.py` reads the nested copy and `setup_keys.py` emits both. Where they
 * disagree this refuses rather than picking a winner — a document whose two
 * copies of `max_children` differ has no single answer to "how many children",
 * and silently preferring one is how a bound gets bypassed.
 */
export function parseAuthorizationBounds(metadata) {
  if (metadata === null || typeof metadata !== 'object' || Array.isArray(metadata)) {
    throw new DenyError('ERR_BOUNDS_UNPARSEABLE', 'metadata is not an object');
  }

  const nested = metadata.authorization_bounds;
  if (nested !== undefined && (nested === null || typeof nested !== 'object' || Array.isArray(nested))) {
    throw new DenyError('ERR_BOUNDS_UNPARSEABLE', 'authorization_bounds is not an object');
  }

  const bounds = {};
  for (const field of ['allowed_scopes', 'can_spawn', 'max_children']) {
    const top = metadata[field];
    const dup = nested?.[field];
    if (top === undefined && dup === undefined) {
      throw new DenyError('ERR_BOUNDS_UNPARSEABLE', `${field} is absent`);
    }
    if (top !== undefined && dup !== undefined
        && JSON.stringify(top) !== JSON.stringify(dup)) {
      throw new DenyError('ERR_BOUNDS_UNPARSEABLE',
        `${field} disagrees between the top level and authorization_bounds`);
    }
    bounds[field] = top !== undefined ? top : dup;
  }

  validateScopeSet(bounds.allowed_scopes, 'allowed_scopes');
  if (!Array.isArray(bounds.can_spawn)) {
    throw new DenyError('ERR_BOUNDS_UNPARSEABLE', 'can_spawn must be an array');
  }
  bounds.can_spawn.forEach((id) => validateUuid4(id, 'can_spawn entry'));
  if (new Set(bounds.can_spawn).size !== bounds.can_spawn.length) {
    throw new DenyError('ERR_BOUNDS_UNPARSEABLE', 'can_spawn contains duplicates');
  }
  validateInteger(bounds.max_children, 'max_children', 0, MAX_CHILDREN);

  // ttl_seconds is a §7.1 REQUIRED field and was going unvalidated: a document
  // carrying `1e999` serialises to `null` and sailed through. A required field
  // that nothing checks is a required field in name only.
  validateInteger(metadata.ttl_seconds, 'ttl_seconds', 1, 60 * 60 * 24 * 365);

  assertKnownMetadataFields(metadata);
  assertSafePaths(metadata);

  return bounds;
}

/**
 * Stage 7 — the two-check spawn rule (§8.1).
 *
 * The draft is explicit that CanSpawn alone is insufficient but MUST pass first,
 * and that a registry lookup alone is also insufficient. Check 1 is static and
 * lives here; check 2 (the child is registered, CA-signed, ACTIVE) is stage 2
 * applied to the child, which the pipeline runs for every node in the chain.
 */
export function assertMaySpawn({ parentBounds, childId, currentChildren = 0 }) {
  validateUuid4(childId, 'child agent_id');

  if (!parentBounds.can_spawn.includes(childId)) {
    throw new DenyError('ERR_CHILD_NOT_WHITELISTED',
      'child is not in the parent can_spawn whitelist — a new certificate is required to add it');
  }

  // cert_validator.validate_max_children only enforces when max_children > 0,
  // which reads a zero cap as "unlimited". That is backwards for a structural
  // bound: 0 means no children, and this refuses accordingly.
  if (currentChildren >= parentBounds.max_children) {
    throw new DenyError('ERR_MAX_CHILDREN',
      `max_children is ${parentBounds.max_children} and the parent already has ${currentChildren}`);
  }
}

/**
 * Stage 8 — scope containment (§8.3), fail-closed.
 *
 * Plain subset over sets of strings: `requested ⊆ allowed`. No wildcards, no
 * prefix matching, no hierarchy. `write:events` does not imply `read:events`
 * and `admin:*` means nothing — a scope is an opaque token, and any cleverness
 * here becomes an escalation path.
 *
 * Empty requested scopes are refused (§16.1): an agent must declare intent, and
 * an empty set would otherwise vacuously satisfy the subset test.
 */
export function assertScopeSubset(requested, allowed) {
  validateScopeSet(requested, 'requested_scopes');
  validateScopeSet(allowed, 'allowed_scopes');

  if (requested.length === 0) {
    throw new DenyError('ERR_EMPTY_SCOPES', 'an agent must declare the scopes it requests');
  }

  const permitted = new Set(allowed);
  const excess = requested.filter((s) => !permitted.has(s));
  if (excess.length > 0) {
    throw new DenyError('ERR_SCOPE_ESCALATION',
      `requested [${excess.join(', ')}] not subset of [${allowed.join(', ')}]`);
  }
  return true;
}

/**
 * §8.3 delegation: a child's scopes must be a subset of the parent's. Refusal
 * happens HERE, at issuance, rather than at verification — the escalation is
 * prevented before a certificate exists, which is the act the playground leads
 * with because it is the part most people have never seen.
 */
export function assertDelegationPermitted({ parentScopes, childScopes }) {
  return assertScopeSubset(childScopes, parentScopes);
}
