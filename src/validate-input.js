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
 *
 * ── Where -03 §3 moved the line ─────────────────────────────────────────────
 *
 * Three rules that used to be this file's own hardening are now normative:
 *
 *   - A duplicate member name MUST be refused, and the requirement is on the
 *     PARSER. `JSON.parse` keeps the last of two duplicates and reports success,
 *     which is precisely the behaviour §3 says does not satisfy it. So this file
 *     carries its own recursive-descent parser (`parseJsonStrict`). Not a
 *     reviver — duplicates are collapsed before a reviver ever runs. Not a regex
 *     over the raw text — it cannot track object scope, so `{"a":{"x":1},
 *     "b":{"x":1}}` reports a false duplicate.
 *   - Timestamps carry the Z designator and nothing else. `+00:00` names the
 *     same instant with different octets, and a signature is over octets.
 *   - The objects this profile defines are FLAT: strings, integers, arrays of
 *     strings. A parser that accepts only those shapes has no depth to exhaust.
 */

import { DenyError } from './errors.js';

// ── Caps ────────────────────────────────────────────────────────────────────
/** Checked BEFORE parsing — a parser is a poor place to discover a 40MB string. */
export const MAX_DOCUMENT_BYTES = 256 * 1024;
/**
 * Above the §8.2 extension limit on purpose: a certificate carrying a 16384-octet
 * Agent Template extension is about 22 KiB of PEM, and the draft's own limit
 * must be the one that refuses it, not this cap.
 */
export const MAX_PEM_BYTES      = 32 * 1024;
export const MAX_SCOPE_LENGTH   = 64;
export const MAX_SCOPES         = 32;
export const MAX_TEXT_LENGTH    = 128;
export const MAX_CHILDREN       = 1000;
export const MAX_NESTING_DEPTH  = 32;
/** §9.3 — ttl_seconds MUST NOT exceed seven days. */
export const MAX_TTL_SECONDS    = 604800;
/** §19.2 — a nonce is at least 128 bits of CSPRNG output. */
export const MIN_NONCE_BYTES    = 16;
/**
 * §19.2 — sixty seconds, either direction. Lives here rather than in mint.js
 * because both the Registry (mint.js) and the grant validator (bounds.js)
 * apply it, and bounds.js must not import the issuer.
 */
export const FRESHNESS_WINDOW_MS = 60_000;

/** Keys that are refused anywhere in a pasted document — prototype pollution. */
export const FORBIDDEN_KEYS = Object.freeze(['__proto__', 'constructor', 'prototype']);

// ── Regexes — all anchored, all bounded ─────────────────────────────────────
/**
 * §7.2 — the canonical lowercase textual form of RFC 9562, any version. The
 * version nibble is 1-8 and the variant nibble 8/9/a/b. Uppercase is refused
 * rather than folded: the identifier is compared byte-for-byte in several
 * places, and folding in one of them and not another is how two implementations
 * disagree about one document.
 */
const UUID  = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
/** §10.3 — 1 to 64 octets of lowercase ASCII letters, digits, colon, underscore, hyphen. */
const SCOPE = /^[a-z0-9:_-]{1,64}$/;
const TEXT  = /^[A-Za-z0-9@._:+/-][A-Za-z0-9 @._:+/-]{0,127}$/;
/** §3 — RFC 3339 in UTC with the Z designator. No offset, no lowercase z. */
const ISO   = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d{1,9})?Z$/;
/** The body bound tracks MAX_PEM_BYTES: 32 KiB of text, and the byte cap is checked first. */
const PEM   = /^-----BEGIN ([A-Z][A-Z ]{0,40})-----\n([A-Za-z0-9+/=\n]{1,33000})-----END ([A-Z][A-Z ]{0,40})-----\n?$/;
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

/** @returns {string} the validated identifier */
export function validateUuid(value, field = 'agent_id') {
  if (typeof value !== 'string' || !UUID.test(value)) {
    throw new DenyError('ERR_AGENT_ID_FORMAT', `${field} must be a lowercase RFC 9562 UUID`);
  }
  return value;
}

export function validateScope(value) {
  if (typeof value !== 'string' || !SCOPE.test(value)) {
    throw new DenyError('ERR_SCOPE_SYNTAX',
      `scope must be 1-${MAX_SCOPE_LENGTH} octets of [a-z0-9:_-]`);
  }
  return value;
}

/**
 * §10.3 — a collection of scopes is a set. Duplicates are a malformed document,
 * not a nuance to absorb; order is preserved because JCS preserves array order
 * and the octets a signature covers depend on it.
 */
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
/**
 * A path-shaped reference such as `policy-store/{uuid}/current` (§8.2). Same
 * charset as TEXT, and no traversal: no `..` segment, no empty segment, no
 * leading slash. The value is CA-signed into a certificate and later resolved
 * by whoever stores policies, so it must not be able to name a parent.
 */
export function validateReference(value, field) {
  validateText(value, field);
  const segments = value.split('/');
  if (value.startsWith('/') || segments.some((seg) => seg === '' || seg === '..' || seg === '.')) {
    throw new DenyError('ERR_FIELD_CHARSET',
      `${field} must be a relative reference with no empty, "." or ".." segments`);
  }
  return value;
}

export function validateInteger(value, field, min = 0, max = MAX_CHILDREN) {
  if (typeof value !== 'number' || !Number.isInteger(value)) {
    throw new DenyError('ERR_FIELD_RANGE', `${field} must be an integer`);
  }
  if (value < min || value > max) {
    throw new DenyError('ERR_FIELD_RANGE', `${field} must be between ${min} and ${max}`);
  }
  return value;
}

/** §9.3 — a duration in seconds, at least one, at most seven days. */
export function validateTtl(value, field = 'ttl_seconds') {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 1) {
    throw new DenyError('ERR_FIELD_RANGE', `${field} must be a positive integer`);
  }
  if (value > MAX_TTL_SECONDS) {
    throw new DenyError('ERR_TTL_TOO_LONG',
      `${field} is ${value}; the maximum is ${MAX_TTL_SECONDS} (seven days)`);
  }
  return value;
}

/**
 * §3 — RFC 3339, UTC, Z designator, then a real calendar check.
 * `new Date(str)` is deliberately not the gate: it accepts "2026-02-31" and
 * shrugs at "next tuesday", and either would put an unchecked string into a
 * signed document.
 */
export function validateTimestamp(value, field = 'issued_at') {
  if (typeof value !== 'string') {
    throw new DenyError('ERR_TIMESTAMP_FORMAT', `${field} must be a string`);
  }
  const m = ISO.exec(value);
  if (!m) {
    throw new DenyError('ERR_TIMESTAMP_FORMAT',
      `${field} must be an RFC 3339 instant in UTC with the Z designator`);
  }
  const [, y, mo, d, h, mi, s] = m;

  // Check the calendar from the components, not from a parsed Date. Date.parse
  // silently rolls 2026-02-31 forward to 2026-03-03 rather than rejecting it, so
  // asking the Date what it became answers the wrong question.
  if (+mo < 1 || +mo > 12 || +d < 1 || +d > daysInMonth(+y, +mo)
      || +h > 23 || +mi > 59) {
    throw new DenyError('ERR_TIMESTAMP_FORMAT', `${field} is not a real date`);
  }
  // ISO-8601 permits :60 for a leap second, but no JS engine can represent one —
  // Date.parse returns NaN. Accepting the string would mean signing a timestamp
  // that nothing downstream can read back.
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

/** Strict standard base64 with padding. Returns the decoded bytes. */
export function decodeBase64Strict(value, field) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(value) || value.length % 4 !== 0) {
    throw new DenyError('ERR_SCHEMA_VIOLATION', `${field} is not valid base64`);
  }
  try {
    return Uint8Array.from(atob(value), (c) => c.charCodeAt(0));
  } catch {
    throw new DenyError('ERR_SCHEMA_VIOLATION', `${field} could not be decoded`);
  }
}

/** §19.2 — base64 of at least 128 bits. */
export function validateNonce(value, field = 'spawn_nonce') {
  const bytes = decodeBase64Strict(value, field);
  if (bytes.length < MIN_NONCE_BYTES) {
    throw new DenyError('ERR_SCHEMA_VIOLATION',
      `${field} carries ${bytes.length * 8} bits; at least 128 are required`);
  }
  return value;
}

/**
 * §3 — the objects this profile defines are flat. Members are strings,
 * integers, or arrays of strings, and nothing else. Refused BEFORE any member
 * logic looks at the object, so nothing downstream ever sees a shape it did
 * not expect.
 */
export function assertFlatObject(obj, label) {
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) {
    throw new DenyError('ERR_OBJECT_NOT_FLAT', `${label} is not a JSON object`);
  }
  for (const [k, v] of Object.entries(obj)) {
    if (typeof v === 'string') continue;
    if (typeof v === 'number' && Number.isInteger(v)) continue;
    if (Array.isArray(v) && v.every((e) => typeof e === 'string')) continue;
    const kind = v === null ? 'null' : Array.isArray(v) ? 'an array of non-strings'
      : typeof v === 'number' ? 'a non-integer number' : `a ${typeof v}`;
    throw new DenyError('ERR_OBJECT_NOT_FLAT', `${label}.${k} is ${kind}`);
  }
  return obj;
}

// ── Strict JSON parser ──────────────────────────────────────────────────────

/** Thrown for syntax; callers map it to ERR_MALFORMED_JSON without the message. */
export class JsonSyntaxError extends Error {
  constructor(message, at) {
    super(message);
    this.name = 'JsonSyntaxError';
    this.at = at;
  }
}

const WS = new Set([' ', '\t', '\n', '\r']);
const ESCAPES = { '"': '"', '\\': '\\', '/': '/', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' };

/**
 * RFC 8259 recursive-descent parser with two properties JSON.parse lacks:
 *
 *   - a duplicate member name in one object is refused (§3), and
 *   - nesting past MAX_NESTING_DEPTH is refused rather than exhausting the stack.
 *
 * Own properties are created with defineProperty, so a member named
 * `__proto__` becomes an ordinary own key (which the forbidden-key guard then
 * refuses) rather than reassigning the object's prototype.
 *
 * Accepts exactly what JSON.parse accepts otherwise: the top level may be any
 * value, numbers follow the RFC grammar, strings carry the RFC escapes, and
 * unescaped control characters are refused.
 */
export function parseJsonStrict(text) {
  let i = 0;
  const n = text.length;

  const fail = (msg) => { throw new JsonSyntaxError(msg, i); };
  const skipWs = () => { while (i < n && WS.has(text[i])) i++; };

  const parseString = () => {
    // text[i] === '"'
    i++;
    let out = '';
    let start = i;
    for (;;) {
      if (i >= n) fail('unterminated string');
      const c = text[i];
      if (c === '"') { out += text.slice(start, i); i++; return out; }
      if (c === '\\') {
        out += text.slice(start, i);
        i++;
        if (i >= n) fail('unterminated escape');
        const e = text[i];
        if (e === 'u') {
          const hex = text.slice(i + 1, i + 5);
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) fail('bad unicode escape');
          out += String.fromCharCode(parseInt(hex, 16));
          i += 5;
        } else if (e in ESCAPES) {
          out += ESCAPES[e];
          i++;
        } else {
          fail('bad escape');
        }
        start = i;
        continue;
      }
      if (c < ' ') fail('control character in string');
      i++;
    }
  };

  const parseNumber = () => {
    const start = i;
    if (text[i] === '-') i++;
    if (text[i] === '0') { i++; }
    else if (text[i] >= '1' && text[i] <= '9') { while (text[i] >= '0' && text[i] <= '9') i++; }
    else fail('bad number');
    if (text[i] === '.') {
      i++;
      if (!(text[i] >= '0' && text[i] <= '9')) fail('bad fraction');
      while (text[i] >= '0' && text[i] <= '9') i++;
    }
    if (text[i] === 'e' || text[i] === 'E') {
      i++;
      if (text[i] === '+' || text[i] === '-') i++;
      if (!(text[i] >= '0' && text[i] <= '9')) fail('bad exponent');
      while (text[i] >= '0' && text[i] <= '9') i++;
    }
    return Number(text.slice(start, i));
  };

  const parseValue = (depth) => {
    if (depth > MAX_NESTING_DEPTH) {
      throw new DenyError('ERR_SCHEMA_VIOLATION', `document nests deeper than ${MAX_NESTING_DEPTH}`);
    }
    skipWs();
    if (i >= n) fail('unexpected end');
    const c = text[i];
    if (c === '{') {
      i++;
      const obj = {};
      const seen = new Set();
      skipWs();
      if (text[i] === '}') { i++; return obj; }
      for (;;) {
        skipWs();
        if (text[i] !== '"') fail('expected member name');
        const key = parseString();
        // §3 — the requirement is on the parser. Refused here, at the point the
        // second occurrence is read, before either value could win.
        if (seen.has(key)) {
          throw new DenyError('ERR_DUPLICATE_MEMBER', `member "${safeKey(key)}" appears twice in one object`);
        }
        seen.add(key);
        skipWs();
        if (text[i] !== ':') fail('expected colon');
        i++;
        const value = parseValue(depth + 1);
        Object.defineProperty(obj, key, { value, enumerable: true, writable: true, configurable: true });
        skipWs();
        if (text[i] === ',') { i++; continue; }
        if (text[i] === '}') { i++; return obj; }
        fail('expected comma or close brace');
      }
    }
    if (c === '[') {
      i++;
      const arr = [];
      skipWs();
      if (text[i] === ']') { i++; return arr; }
      for (;;) {
        arr.push(parseValue(depth + 1));
        skipWs();
        if (text[i] === ',') { i++; continue; }
        if (text[i] === ']') { i++; return arr; }
        fail('expected comma or close bracket');
      }
    }
    if (c === '"') return parseString();
    if (c === '-' || (c >= '0' && c <= '9')) return parseNumber();
    if (text.startsWith('true', i)) { i += 4; return true; }
    if (text.startsWith('false', i)) { i += 5; return false; }
    if (text.startsWith('null', i)) { i += 4; return null; }
    fail('unexpected token');
  };

  const value = parseValue(0);
  skipWs();
  if (i < n) fail('trailing content');
  return value;
}

/** A member name goes into a detail string the page renders; keep it short and printable. */
function safeKey(key) {
  const printable = key.replace(/[^\x20-\x7e]/g, '?');
  return printable.length > 40 ? `${printable.slice(0, 40)}…` : printable;
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
 * A key that survives validation reads as meaningful to whoever handles the
 * document next, and a key that was meaningful in a previous revision is the
 * worst case: it looks like configuration that is being honoured. Three
 * adversarial probes went green during the -02 migration by writing to a
 * field nothing read any more. So the envelope is a whitelist.
 */
export const KNOWN_DOCUMENT_FIELDS = new Set([
  // input
  'chain', 'authorities', 'crl', 'audit',
  // §3.1 envelopes: the dynamic policy (§11.4) and the cross-org grant (§13.2)
  'policy', 'grant',
  // The policies the Registry holds IN FORCE, one envelope per subject — what
  // §10.2 step 3 is evaluated against, retrieved through policy_ref. `policy`
  // above is an UPDATE being presented; these are the store it updates.
  'policies',
  // Registry context the page carries so replay can be demonstrated (§11.4)
  'current_policy_version',
  // output, present when a validated document is pasted back in
  'verdict', 'banner', 'error_code', 'draft', 'draft_section', 'stages', 'walk',
  'advisories', 'not_applicable', 'generated_at', 'playground_version', 'demo_only',
]);

/**
 * Whitelist, not blacklist: a member the profile does not define is refused,
 * never ignored. The offending names go through `safeKey` because the detail
 * is rendered on the page.
 */
export function assertKnownKeys(obj, known, label) {
  const unknown = Object.keys(obj ?? {}).filter((k) => !known.has(k)).sort();
  if (unknown.length) {
    throw new DenyError('ERR_SCHEMA_VIOLATION',
      `${label} carries unknown field(s): ${unknown.map(safeKey).join(', ')}`);
  }
}

export function assertKnownDocumentFields(doc) {
  assertKnownKeys(doc, KNOWN_DOCUMENT_FIELDS, 'document');
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
    parsed = parseJsonStrict(text);
  } catch (e) {
    if (e instanceof DenyError) throw e;   // duplicate member, depth
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
