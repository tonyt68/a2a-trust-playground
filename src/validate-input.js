/**
 * Input validation contract — fail closed, no exceptions.
 *
 * This is a public page where strangers paste certificates and JSON into an
 * editor and press Verify. Everything here treats its argument as hostile. The
 * global rule from DESIGN.md: any validation failure is a DENY with an error
 * code — never a silently coerced value, never a partial parse, never a thrown
 * exception reaching the user.
 *
 * Two rules that are easy to get subtly wrong, so they are stated once here:
 *
 *   Reject, do not sanitize. A value that fails is refused whole. Stripping bad
 *   characters and continuing would mean the document that gets signed is not
 *   the document the visitor submitted, which breaks round-trip parity and hides
 *   the refusal the page exists to demonstrate.
 *
 *   Every regex is anchored and bounded. No nested quantifiers, no unbounded
 *   repetition of a group that can also match empty — that is the ReDoS shape.
 *   Bounds are explicit `{n,m}` so worst-case work is a function of the size cap,
 *   not of attacker-chosen structure.
 */

import { DenyError } from './errors.js';

// ── Caps ────────────────────────────────────────────────────────────────────
/** Checked BEFORE JSON.parse — a parser is a poor place to discover a 40MB string. */
export const MAX_DOCUMENT_BYTES = 256 * 1024;
export const MAX_PEM_BYTES      = 16 * 1024;
export const MAX_SCOPE_LENGTH   = 64;
export const MAX_SCOPES         = 32;
export const MAX_TEXT_LENGTH    = 128;
export const MAX_CHILDREN       = 1000;
export const MAX_NESTING_DEPTH  = 32;

/** Keys that are refused anywhere in a pasted document — prototype pollution. */
export const FORBIDDEN_KEYS = Object.freeze(['__proto__', 'constructor', 'prototype']);

// ── Regexes — all anchored, all bounded ─────────────────────────────────────
/** Strict UUID4: version nibble is 4, variant nibble is 8/9/a/b. Lowercase only. */
const UUID4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SCOPE = /^[a-z0-9:_-]{1,64}$/;
const TEXT  = /^[A-Za-z0-9 @._:+-]{1,128}$/;
/** ISO-8601 instant. Offset is required — a naive timestamp has no single meaning. */
const ISO   = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$/;
const PEM   = /^-----BEGIN ([A-Z][A-Z ]{0,40})-----\n([A-Za-z0-9+/=\n]{1,20000})-----END ([A-Z][A-Z ]{0,40})-----\n?$/;
const B64   = /^[A-Za-z0-9+/]{4,}={0,2}$/;

const MIN_TIME = Date.UTC(2000, 0, 1);
const MAX_TIME = Date.UTC(2100, 0, 1);

const MONTH_LENGTHS = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

/** Proleptic Gregorian leap rule — the one the ISO-8601 calendar uses. */
function isLeapYear(y) {
  return (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0;
}

function daysInMonth(y, m) {
  return m === 2 && isLeapYear(y) ? 29 : MONTH_LENGTHS[m - 1];
}

// ── Primitives ──────────────────────────────────────────────────────────────

/** @returns {string} the validated UUID4 */
export function validateUuid4(value, field = 'agent_id') {
  if (typeof value !== 'string' || !UUID4.test(value)) {
    throw new DenyError('ERR_AGENT_ID_FORMAT', `${field} must be a lowercase UUID4`);
  }
  return value;
}

export function validateScope(value) {
  if (typeof value !== 'string' || !SCOPE.test(value)) {
    throw new DenyError('ERR_FIELD_CHARSET',
      `scope must match [a-z0-9:_-] and be 1-${MAX_SCOPE_LENGTH} characters`);
  }
  return value;
}

/** Scope sets are sets: duplicates are a malformed document, not a nuance to absorb. */
export function validateScopeSet(value, field = 'allowed_scopes') {
  if (!Array.isArray(value)) {
    throw new DenyError('ERR_SCHEMA_VIOLATION', `${field} must be an array`);
  }
  if (value.length > MAX_SCOPES) {
    throw new DenyError('ERR_FIELD_RANGE', `${field} exceeds ${MAX_SCOPES} entries`);
  }
  value.forEach(validateScope);
  if (new Set(value).size !== value.length) {
    throw new DenyError('ERR_SCHEMA_VIOLATION', `${field} contains duplicates`);
  }
  return value;
}

export function validateText(value, field) {
  if (typeof value !== 'string' || !TEXT.test(value)) {
    throw new DenyError('ERR_FIELD_CHARSET',
      `${field} must be 1-${MAX_TEXT_LENGTH} characters from the allowed set`);
  }
  return value;
}

/** Integer only. NaN, Infinity and floats are refused, never coerced. */
export function validateInteger(value, field, min = 0, max = MAX_CHILDREN) {
  if (typeof value !== 'number' || !Number.isInteger(value)) {
    throw new DenyError('ERR_FIELD_RANGE', `${field} must be an integer`);
  }
  if (value < min || value > max) {
    throw new DenyError('ERR_FIELD_RANGE', `${field} must be between ${min} and ${max}`);
  }
  return value;
}

/**
 * Strict ISO-8601 with a required offset, then a real calendar check.
 * `new Date(str)` is deliberately not the gate: it accepts "2026-02-31" and
 * shrugs at "next tuesday", and either would put an unchecked string into a
 * signed document.
 */
export function validateTimestamp(value, field = 'created_at') {
  if (typeof value !== 'string') {
    throw new DenyError('ERR_TIMESTAMP_FORMAT', `${field} must be a string`);
  }
  const m = ISO.exec(value);
  if (!m) {
    throw new DenyError('ERR_TIMESTAMP_FORMAT', `${field} must be an ISO-8601 instant with an offset`);
  }
  const [, y, mo, d, h, mi, s] = m;

  // Check the calendar from the components, not from a parsed Date. Date.parse
  // silently rolls 2026-02-31 forward to 2026-03-03 rather than rejecting it, so
  // asking the Date what it became answers the wrong question. Doing it on the
  // components is also timezone-independent, which comparing UTC fields is not.
  if (+mo < 1 || +mo > 12 || +d < 1 || +d > daysInMonth(+y, +mo)
      || +h > 23 || +mi > 59) {
    throw new DenyError('ERR_TIMESTAMP_FORMAT', `${field} is not a real date`);
  }
  // ISO-8601 permits :60 for a leap second, but no JS engine can represent one —
  // Date.parse returns NaN. Accepting the string would mean signing a timestamp
  // that nothing downstream can read back, so it is refused here with a reason
  // rather than surfacing later as "not a real instant".
  if (+s > 59) {
    throw new DenyError('ERR_TIMESTAMP_FORMAT', `${field} uses a leap second, which is not representable`);
  }

  const t = Date.parse(value);
  if (Number.isNaN(t)) {
    throw new DenyError('ERR_TIMESTAMP_FORMAT', `${field} is not a real instant`);
  }
  if (t < MIN_TIME || t > MAX_TIME) {
    throw new DenyError('ERR_TIMESTAMP_FORMAT', `${field} is outside the supported range`);
  }
  return value;
}

// ── Documents ───────────────────────────────────────────────────────────────

/** Recursively refuse the prototype-pollution keys, at any depth. */
export function assertNoForbiddenKeys(value, depth = 0, path = '$') {
  if (depth > MAX_NESTING_DEPTH) {
    throw new DenyError('ERR_SCHEMA_VIOLATION', `document nests deeper than ${MAX_NESTING_DEPTH}`);
  }
  if (Array.isArray(value)) {
    value.forEach((v, i) => assertNoForbiddenKeys(v, depth + 1, `${path}[${i}]`));
    return value;
  }
  if (value === null || typeof value !== 'object') return value;
  for (const [k, v] of Object.entries(value)) {
    if (FORBIDDEN_KEYS.includes(k)) {
      throw new DenyError('ERR_PROTOTYPE_POLLUTION', `${path}.${k} is not an allowed key`);
    }
    assertNoForbiddenKeys(v, depth + 1, `${path}.${k}`);
  }
  return value;
}

/**
 * The complete set of top-level document keys.
 *
 * Metadata has had a whitelist since the first red-team pass, and `-02` §9.4
 * gives the policy document one. The envelope had neither, which meant a
 * document could carry any top-level key at all and validate — including keys
 * that USED to be meaningful.
 *
 * That is how three adversarial probes went green during the -02 migration:
 * they mutated `policy_version`, which -02 moved inside the signed policy
 * document. The field is now read by nothing, so writing garbage to it did
 * nothing, and doing nothing was reported as acceptance.
 *
 * A key that survives validation reads as meaningful to whoever handles the
 * document next, and a key that was meaningful in a previous revision is the
 * worst case: it looks like configuration that is being honoured.
 */
export const KNOWN_DOCUMENT_FIELDS = new Set([
  // input
  'chain', 'authorities', 'crl', 'audit',
  // §9.4 policy update and its storage envelope
  'policy_update', 'policy_doc', 'existing_cert',
  'owner_sig', 'pa_sig', 'current_policy_version', 'policy_content_hash',
  // output, present when a validated document is pasted back in
  'verdict', 'banner', 'error_code', 'draft', 'draft_section', 'stages', 'walk',
  'not_applicable', 'generated_at', 'playground_version', 'demo_only',
]);

export function assertKnownDocumentFields(doc) {
  const unknown = Object.keys(doc)
    .filter((k) => !KNOWN_DOCUMENT_FIELDS.has(k)).sort();
  if (unknown.length) {
    throw new DenyError('ERR_SCHEMA_VIOLATION',
      `document contains unknown field(s): ${unknown.join(', ')}`);
  }
}

/**
 * Size cap first, then parse, then structural checks. The order matters: the cap
 * exists so a hostile document is refused before a parser allocates for it.
 */
export function parseDocument(text) {
  if (typeof text !== 'string') {
    throw new DenyError('ERR_MALFORMED_JSON', 'document must be text');
  }
  const bytes = new TextEncoder().encode(text).length;
  if (bytes > MAX_DOCUMENT_BYTES) {
    throw new DenyError('ERR_DOCUMENT_TOO_LARGE',
      `${bytes} bytes exceeds the ${MAX_DOCUMENT_BYTES} byte cap`);
  }
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    // The parser's message can echo document content; it never reaches the page.
    throw new DenyError('ERR_MALFORMED_JSON', 'document is not valid JSON');
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new DenyError('ERR_SCHEMA_VIOLATION', 'document must be a JSON object');
  }
  const doc = assertNoForbiddenKeys(parsed);
  assertKnownDocumentFields(doc);
  return doc;
}

/**
 * One PEM block, strictly. Best-effort recovery is refused on purpose: a
 * certificate that only *mostly* parses is exactly the input a validator should
 * reject rather than guess at.
 */
export function validatePem(text, expectedLabel = null) {
  if (typeof text !== 'string') {
    throw new DenyError('ERR_MALFORMED_PEM', 'PEM must be text');
  }
  const bytes = new TextEncoder().encode(text).length;
  if (bytes > MAX_PEM_BYTES) {
    throw new DenyError('ERR_MALFORMED_PEM', `PEM exceeds the ${MAX_PEM_BYTES} byte cap`);
  }
  const normalized = text.replace(/\r\n/g, '\n').trim() + '\n';
  const m = PEM.exec(normalized);
  if (!m) throw new DenyError('ERR_MALFORMED_PEM', 'not a single well-formed PEM block');

  const [, beginLabel, body, endLabel] = m;
  if (beginLabel !== endLabel) {
    throw new DenyError('ERR_MALFORMED_PEM', 'BEGIN and END labels differ');
  }
  if (expectedLabel && beginLabel !== expectedLabel) {
    throw new DenyError('ERR_MALFORMED_PEM', `expected a ${expectedLabel} block`);
  }
  const b64 = body.replace(/\n/g, '');
  if (!B64.test(b64) || b64.length % 4 !== 0) {
    throw new DenyError('ERR_MALFORMED_PEM', 'body is not strict base64');
  }
  let der;
  try {
    der = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  } catch {
    throw new DenyError('ERR_MALFORMED_PEM', 'body is not decodable base64');
  }
  if (der.length === 0) throw new DenyError('ERR_MALFORMED_PEM', 'PEM body is empty');
  return { label: beginLabel, der };
}
