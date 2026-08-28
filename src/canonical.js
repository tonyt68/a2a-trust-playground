/**
 * Canonical JSON — RFC 8785 (JSON Canonicalization Scheme).
 *
 * `draft-tonyai-a2a-trust-02` §9.5 requires that wherever the document needs a
 * canonical form — a policy document, any field subset of one, or an audit log
 * entry — that form is the JCS serialization of RFC 8785.
 *
 * ── Why this replaced a hand-written serializer ─────────────────────────────
 *
 * `-01` specified no canonicalization at all. A signature is over bytes, and
 * nothing in the text said how those bytes are produced, so the only way to
 * implement §9.3 was to read the reference implementation's Python and
 * reproduce `json.dumps(sort_keys=True, separators=(',', ':'))` exactly —
 * including `ensure_ascii=True` escaping and Python's code-point key ordering,
 * neither of which JavaScript does natively. That is not a specification; it is
 * one codebase's behaviour, and a second implementer could not have derived it.
 *
 * JCS is a published RFC solving precisely this problem, and the -02 text cites
 * it rather than describing a bespoke scheme.
 *
 * ── What JCS actually requires, and why this file is short ──────────────────
 *
 * JCS is close to what JavaScript already does, which is the happy accident
 * that makes this simpler than what it replaced:
 *
 *   - Property names sort by UTF-16 code unit — JavaScript's native string
 *     ordering. The custom code-point comparator the Python parity demanded is
 *     gone entirely.
 *   - Strings are raw UTF-8 with only the JSON-mandated escapes, which is what
 *     `JSON.stringify` emits. No \uXXXX for non-ASCII.
 *   - Numbers use ECMAScript `Number::toString`, again `JSON.stringify`.
 *
 * So the work is recursive key sorting; the leaf encoding is delegated to
 * `JSON.stringify`, which is specified to do the right thing rather than
 * approximating it. The escaping table and the code-point comparator that
 * existed only to imitate Python are deleted, not ported.
 *
 * ── One canonical form, not two ─────────────────────────────────────────────
 *
 * The previous implementation carried TWO serializations — compact for
 * signatures, spaced for audit block hashes — because the reference
 * implementation called `json.dumps` two different ways in two different files.
 * §9.5 now specifies a single canonical form for both, on the reasoning that an
 * implementation carrying two will eventually apply the wrong one, and that
 * failure presents as a signature or integrity error with no indication that
 * serialization was the cause.
 *
 * There is deliberately no `canonicalCompact` / `canonicalSpaced` pair here any
 * more. One function, one answer.
 */

/** Depth cap — fail closed rather than blow the stack on hostile nesting. */
const MAX_DEPTH = 64;

/**
 * Identity fields covered by `owner_sig` (§9.3 phase 1).
 *
 * These describe WHO the agent is, and are immutable without re-certification
 * (§9.1). `subject`, `agent_id` and `agent_uuid` are all present because §7.1
 * carries the identity three times and a signature that binds only one of them
 * leaves the others free to disagree.
 */
export const IDENTITY_FIELDS = new Set([
  'agent_id', 'agent_uuid', 'org_id', 'subject', 'issuer',
  'owner', 'cert_serial', 'cert_subject', 'cert_issuer',
  'cert_public_key', 'cert_not_before', 'cert_not_after',
  'cert_fingerprint', 'cert_chain', 'template_version',
  'can_spawn',      // permitted child agent UUIDs — immutable, new cert required (§8.1)
  'max_children',   // structural spawn bound — immutable
]);

/**
 * Policy document fields, per `-02` §9.4.
 *
 * This is the complete set the draft defines, and it is deliberately NOT the
 * set the previous implementation signed. Two differences matter:
 *
 *   `version` and `subject` are now INSIDE the signed set. Their absence was an
 *   exploitable replay: §9.4 lists the version as something stored alongside the
 *   signature and never required the signature to cover it, so an attacker
 *   holding no key could take a superseded but validly signed policy, increment
 *   the version, and have it accepted. Both signatures verified, the content
 *   hash matched, and the version read as current.
 *
 *   `description`, `tags` and `conditions` are gone. They were carried because
 *   the reference implementation carried them, not because the draft required
 *   them, and §9.4 now defines the field set as complete — an unrecognised field
 *   is refused rather than signed along.
 */
export const POLICY_FIELDS = new Set([
  'subject',        // §9.4 — binds the policy to the agent it governs
  'owner',          // §9.2 — MUST match the template's Owner
  'org_id',         // §9.2 — MUST match the template's OrgID
  'scopes',         // §7.2 — bounded by AllowedScopes
  'spawn_targets',  // §7.2 — bounded by CanSpawn; OPTIONAL
  'version',        // §9.4 — replay prevention; MUST be signed
  'issued_at',      // §9.4 — RFC 3339
  'not_after',      // §9.4 — OPTIONAL; MUST NOT exceed the template TTL
]);

function pick(doc, allowed) {
  if (doc === null || typeof doc !== 'object' || Array.isArray(doc)) return {};
  const out = {};
  for (const [k, v] of Object.entries(doc)) {
    if (allowed.has(k)) out[k] = v;
  }
  return out;
}

export function extractIdentityFields(doc) {
  return pick(doc, IDENTITY_FIELDS);
}

export function extractPolicyFields(doc) {
  return pick(doc, POLICY_FIELDS);
}

/**
 * RFC 8785 canonical serialization.
 *
 * The single canonical form required by §9.5, used for both signatures (§9.3)
 * and hashes (§9.6, §16.6).
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
  // data, and reordering it changes the signature. JCS sorts object PROPERTIES,
  // never array elements.
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
  // JavaScript string comparison does. The custom code-point comparator that
  // Python parity required is not merely unnecessary here — it would be WRONG,
  // because it disagrees with JS ordering above the BMP, which is the case JCS
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
    // JCS defines float serialization fully, but every numeric field in this
    // profile (max_children, ttl_seconds, version) is an integer. Refusing a
    // float keeps the surface small rather than exercising a code path no
    // conforming document reaches.
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
