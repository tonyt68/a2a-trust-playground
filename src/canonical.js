/**
 * Canonical JSON — RFC 8785 (JSON Canonicalization Scheme).
 *
 * `draft-tonyai-a2a-trust-03` §3 makes every document it defines a JSON object
 * serialized with JCS, and §11.5 makes that the single canonical form for
 * signatures and for audit entries alike. Wherever this playground needs
 * bytes to sign, hash, or compare, they come from `canonicalize`.
 *
 * ── What JCS actually requires, and why this file is short ──────────────────
 *
 * JCS is close to what JavaScript already does:
 *
 *   - Property names sort by UTF-16 code unit — JavaScript's native string
 *     ordering.
 *   - Strings are raw UTF-8 with only the JSON-mandated escapes, which is what
 *     `JSON.stringify` emits. No \uXXXX for non-ASCII.
 *   - Numbers use ECMAScript `Number::toString`, again `JSON.stringify`.
 *
 * So the work is recursive key sorting; the leaf encoding is delegated to
 * `JSON.stringify`, which is specified to do the right thing rather than
 * approximating it.
 *
 * ── The four documents, as field sets ───────────────────────────────────────
 *
 * §3.2 gives every display name one wire name. The sets below are the complete
 * member lists of the four documents; each is used by a validator to refuse a
 * member outside it (§8.2, §10.5, §11.4, §13.2 all say "exactly the following").
 * None of them is a filter applied before signing: a body is signed whole,
 * after the validator has established that it contains only these members.
 * Filtering-then-signing was the -02 design and it left the signed octets and
 * the validated document free to differ.
 */

/** Depth cap — fail closed rather than blow the stack on hostile nesting. */
const MAX_DEPTH = 64;

/** §8.2 Table 5 — the Agent Template extension. All REQUIRED. */
export const TEMPLATE_FIELDS = Object.freeze([
  'subject', 'owner', 'org_id', 'permitted_operations', 'allowed_scopes',
  'can_spawn', 'max_children', 'policy_ref', 'ttl_seconds',
]);

/** §10.5 Table 7 — the Agent Spawn extension: the three members REQUIRED whenever it is present... */
export const SPAWN_FIELDS = Object.freeze(['parent_agent_id', 'spawned_at', 'spawn_nonce']);
/** ...and the one present exactly when the spawn was cross-organizational (§10.5, §13.4). */
export const SPAWN_OPTIONAL_FIELDS = Object.freeze(['grant_id']);

/**
 * §10.4 Table 6 — the audit log entry for a spawn event. `previous_hash` and
 * `entry_hash` are members of the entry, not chain metadata around it: §19.7
 * hashes every member but entry_hash, previous_hash included.
 */
export const AUDIT_SPAWN_FIELDS = Object.freeze([
  'spawning_agent_id', 'child_template_id', 'requested_scopes', 'granted_scopes', 'spawn_nonce',
  'timestamp', 'outcome', 'previous_hash', 'entry_hash',
]);
/** Present under a condition: grant_id when spawned under a grant, reason when DENIED. */
export const AUDIT_SPAWN_OPTIONAL_FIELDS = Object.freeze(['grant_id', 'reason']);

/** §11.4 Table 8 — the dynamic policy document. */
export const POLICY_FIELDS = Object.freeze([
  'subject', 'owner', 'org_id', 'scopes', 'spawn_targets', 'version', 'issued_at', 'not_after',
]);
export const REQUIRED_POLICY_FIELDS = Object.freeze([
  'subject', 'owner', 'org_id', 'scopes', 'version', 'issued_at',
]);

/** §13.2 Table 11 — the cross-organizational grant. All REQUIRED. */
export const GRANT_FIELDS = Object.freeze([
  'grant_id', 'grantor', 'grantee', 'template', 'allowed_scopes', 'issued_at', 'ttl_seconds', 'max_spawns',
]);

/** §3.1 Table 1 — the envelope. `content_hash` is present only where §11.6 requires it. */
export const ENVELOPE_FIELDS = Object.freeze(['body', 'owner_sig', 'pa_sig', 'content_hash']);

/**
 * RFC 8785 canonical serialization.
 *
 * The single canonical form required by §11.5, used for both signatures (§3.1)
 * and hashes (§11.6, §19.7).
 */
export function canonicalize(value) {
  return write(value, 0, new Set());
}

function write(value, depth, seen) {
  if (depth > MAX_DEPTH) {
    throw new CanonicalError(`nesting deeper than ${MAX_DEPTH} levels`);
  }

  if (value === null) return 'null';
  if (value === true) return 'true';
  if (value === false) return 'false';

  const t = typeof value;
  if (t === 'string') return JSON.stringify(value);
  if (t === 'number') return writeNumber(value);

  if (t === 'object') {
    if (seen.has(value)) throw new CanonicalError('circular reference');
    seen.add(value);
    try {
      return Array.isArray(value)
        ? writeArray(value, depth, seen)
        : writeObject(value, depth, seen);
    } finally {
      seen.delete(value);
    }
  }

  // undefined, function, symbol, bigint have no JSON representation. JCS does
  // not define them, so they are refused rather than silently dropped the way
  // JSON.stringify would drop them from an object.
  throw new CanonicalError(`value of type ${t} is not serializable`);
}

function writeArray(arr, depth, seen) {
  // Element order is significant and is never sorted — a scope list is ordered
  // data on the wire (§10.3), and reordering it changes the signature. JCS sorts
  // object PROPERTIES, never array elements.
  return `[${arr.map((v) => write(v, depth + 1, seen)).join(',')}]`;
}

function writeObject(obj, depth, seen) {
  // Object.entries returns own enumerable string-keyed pairs without going
  // through property lookup, so a JSON-parsed "__proto__" key is read as the
  // plain own property it is. Rejecting such keys is the validator's job, not
  // the serializer's — here it must round-trip faithfully.
  const entries = Object.entries(obj);
  for (const [k] of entries) {
    if (typeof k !== 'string') throw new CanonicalError('non-string object key');
  }

  // RFC 8785 §3.2.3: sort by UTF-16 code unit, which is exactly what a default
  // JavaScript string comparison does. A code-point comparator would be WRONG
  // here — it disagrees with JS ordering above the BMP, which is the case JCS
  // pins to the JS behaviour.
  entries.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));

  const parts = entries.map(
    ([k, v]) => `${JSON.stringify(k)}:${write(v, depth + 1, seen)}`,
  );
  return `{${parts.join(',')}}`;
}

function writeNumber(n) {
  if (!Number.isFinite(n)) {
    // RFC 8785 §3.2.2.3 excludes NaN and Infinity; they are not JSON either.
    throw new CanonicalError(`non-finite number: ${n}`);
  }
  if (!Number.isInteger(n)) {
    // JCS defines float serialization fully, but §3 declares every numeric
    // member of this profile an integer. Refusing a float keeps the surface
    // small rather than exercising a code path no conforming document reaches.
    throw new CanonicalError(`non-integer number: ${n}`);
  }
  // JCS §3.2.2.3 requires ECMAScript Number::toString, and -0 serializes as 0.
  return Object.is(n, -0) ? '0' : String(n);
}

export class CanonicalError extends Error {
  constructor(message) {
    super(message);
    this.name = 'CanonicalError';
  }
}
