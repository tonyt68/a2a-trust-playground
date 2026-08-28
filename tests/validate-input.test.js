/**
 * Acceptance criterion 11: malformed UUIDs, oversized JSON, __proto__ keys, XSS
 * payloads in every text field, and malformed PEM must each produce a clean DENY
 * with an error code — never a raw exception, never a coerced value.
 *
 * The assertion in `denies()` is deliberately strict about the *type* thrown. A
 * TypeError escaping validation would reach the page as an unhandled error, and
 * on a page whose entire argument is that it enforces boundaries, that is not a
 * bug — it is a refutation.
 */
import { describe, it, expect } from 'vitest';
import { DenyError } from '../src/errors.js';
import * as v from '../src/validate-input.js';

/** Assert the call denies with a specific code, and that nothing else escapes. */
function denies(code, fn) {
  let thrown;
  try { fn(); } catch (e) { thrown = e; }
  expect(thrown, 'expected a DenyError, nothing was thrown').toBeDefined();
  expect(thrown, `threw ${thrown?.constructor?.name}: ${thrown?.message}`).toBeInstanceOf(DenyError);
  expect(thrown.code).toBe(code);
  expect(thrown.detail).toBeTypeOf('string');
}

const XSS = [
  '<script>alert(1)</script>',
  '"><img src=x onerror=alert(1)>',
  'javascript:alert(1)',
  '<svg/onload=alert(1)>',
  "'; DROP TABLE agents;--",
  '${7*7}',
  '{{constructor.constructor("alert(1)")()}}',
  '../../../../etc/passwd',
  'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
];

describe('agent_id — strict UUID4 (stage 1)', () => {
  it('accepts a real UUID4', () => {
    expect(v.validateUuid4('8f14e45f-ceea-467a-9c0f-7ad0f1b0d5aa'))
      .toBe('8f14e45f-ceea-467a-9c0f-7ad0f1b0d5aa');
  });

  const rejects = {
    'agent-a (the PoC human-readable form)': 'agent-a',
    'uppercase': '8F14E45F-CEEA-467A-9C0F-7AD0F1B0D5AA',
    'UUID1 (version nibble 1)': '8f14e45f-ceea-167a-9c0f-7ad0f1b0d5aa',
    'bad variant nibble': '8f14e45f-ceea-467a-1c0f-7ad0f1b0d5aa',
    'too short': '8f14e45f-ceea-467a-9c0f-7ad0f1b0d5a',
    'trailing newline (unanchored regexes pass this)': '8f14e45f-ceea-467a-9c0f-7ad0f1b0d5aa\n',
    'leading space': ' 8f14e45f-ceea-467a-9c0f-7ad0f1b0d5aa',
    'trailing space': '8f14e45f-ceea-467a-9c0f-7ad0f1b0d5aa ',
    'path traversal': '../../../etc/passwd',
    'empty': '',
    'number': 123,
    'null': null,
    'object': {},
  };
  for (const [name, val] of Object.entries(rejects)) {
    it(`rejects ${name}`, () => denies('ERR_AGENT_ID_FORMAT', () => v.validateUuid4(val)));
  }

  it('rejects every XSS payload', () => {
    for (const p of XSS) denies('ERR_AGENT_ID_FORMAT', () => v.validateUuid4(p));
  });
});

describe('scopes — charset and cardinality', () => {
  it('accepts the draft scopes', () => {
    expect(v.validateScopeSet(['read:events', 'write:events'])).toHaveLength(2);
  });
  it('rejects an over-long scope', () =>
    denies('ERR_FIELD_CHARSET', () => v.validateScope('a'.repeat(65))));
  it('rejects uppercase', () => denies('ERR_FIELD_CHARSET', () => v.validateScope('Read:Events')));
  it('rejects a wildcard', () => denies('ERR_FIELD_CHARSET', () => v.validateScope('*')));
  it('rejects more than 32 scopes', () =>
    denies('ERR_FIELD_RANGE', () => v.validateScopeSet(Array.from({ length: 33 }, (_, i) => `s${i}`))));
  it('rejects duplicates rather than de-duplicating', () =>
    denies('ERR_SCHEMA_VIOLATION', () => v.validateScopeSet(['read:events', 'read:events'])));
  it('rejects a non-array', () =>
    denies('ERR_SCHEMA_VIOLATION', () => v.validateScopeSet('read:events')));
  it('rejects every XSS payload', () => {
    for (const p of XSS) denies('ERR_FIELD_CHARSET', () => v.validateScope(p));
  });
});

describe('free text — rejected, never sanitized', () => {
  it('accepts an ordinary owner value', () =>
    expect(v.validateText('owner@example.com', 'owner')).toBe('owner@example.com'));
  it('rejects over-long text', () =>
    denies('ERR_FIELD_CHARSET', () => v.validateText('a'.repeat(129), 'owner')));
  it('rejects every XSS payload, returning nothing partial', () => {
    for (const p of XSS) denies('ERR_FIELD_CHARSET', () => v.validateText(p, 'owner'));
  });
});

describe('numbers — no coercion', () => {
  it('accepts an in-range integer', () => expect(v.validateInteger(5, 'max_children')).toBe(5));
  it('accepts zero', () => expect(v.validateInteger(0, 'max_children')).toBe(0));
  for (const [name, val] of Object.entries({
    NaN, Infinity, '-Infinity': -Infinity, float: 1.5,
    'numeric string': '5', boolean: true, null: null,
  })) {
    it(`rejects ${name}`, () => denies('ERR_FIELD_RANGE', () => v.validateInteger(val, 'max_children')));
  }
  it('rejects out of range', () => {
    denies('ERR_FIELD_RANGE', () => v.validateInteger(-1, 'max_children'));
    denies('ERR_FIELD_RANGE', () => v.validateInteger(1001, 'max_children'));
  });
});

describe('timestamps — strict ISO-8601, no Date coercion', () => {
  it('accepts offset and Z forms', () => {
    expect(v.validateTimestamp('2026-08-28T12:00:00+00:00')).toBeTruthy();
    expect(v.validateTimestamp('2026-08-28T12:00:00.123456Z')).toBeTruthy();
  });
  for (const [name, val] of Object.entries({
    'naive (no offset)': '2026-08-28T12:00:00',
    'date only': '2026-08-28',
    'free text that Date accepts': 'next tuesday',
    'impossible calendar day': '2026-02-31T00:00:00Z',
    'month 13': '2026-13-01T00:00:00Z',
    'hour 25': '2026-08-28T25:00:00Z',
    'year 1899 (out of range)': '1899-01-01T00:00:00Z',
    'epoch number': 1756382400,
  })) {
    it(`rejects ${name}`, () => denies('ERR_TIMESTAMP_FORMAT', () => v.validateTimestamp(val)));
  }
});

describe('document parsing — cap, then parse, then structure', () => {
  it('accepts a document whose keys are all recognised', () =>
    expect(v.parseDocument('{"chain":[],"crl":{},"audit":{}}'))
      .toEqual({ chain: [], crl: {}, audit: {} }));

  it('refuses an unrecognised top-level key', () => {
    // Metadata and policy_doc have had whitelists since earlier passes; the
    // envelope had none. A key that survives validation reads as meaningful to
    // whoever handles the document next, and a key that WAS meaningful in an
    // older revision is the worst case — it looks like configuration still
    // being honoured. Found when three adversarial probes targeting -01's
    // `policy_version` went green by writing to a field nothing reads.
    expect(() => v.parseDocument('{"chain":[],"policy_version":9}'))
      .toThrow(v.DenyError ?? Error);
  });

  it('rejects an oversized document BEFORE parsing', () => {
    const huge = JSON.stringify({ pad: 'x'.repeat(v.MAX_DOCUMENT_BYTES + 100) });
    denies('ERR_DOCUMENT_TOO_LARGE', () => v.parseDocument(huge));
  });

  it('rejects malformed JSON without leaking the parser message', () => {
    let thrown;
    try { v.parseDocument('{"a":'); } catch (e) { thrown = e; }
    expect(thrown.code).toBe('ERR_MALFORMED_JSON');
    expect(thrown.message).not.toMatch(/position|token|Unexpected/i);
  });

  it('rejects a JSON array or scalar at the root', () => {
    denies('ERR_SCHEMA_VIOLATION', () => v.parseDocument('[1,2]'));
    denies('ERR_SCHEMA_VIOLATION', () => v.parseDocument('"hello"'));
    denies('ERR_SCHEMA_VIOLATION', () => v.parseDocument('null'));
  });

  for (const key of v.FORBIDDEN_KEYS) {
    it(`rejects a top-level "${key}" key`, () =>
      denies('ERR_PROTOTYPE_POLLUTION', () => v.parseDocument(`{"${key}":{"polluted":true}}`)));
    it(`rejects a nested "${key}" key`, () =>
      denies('ERR_PROTOTYPE_POLLUTION', () =>
        v.parseDocument(`{"chain":[{"meta":{"${key}":{"polluted":true}}}]}`)));
  }

  it('does not pollute Object.prototype even while rejecting', () => {
    try { v.parseDocument('{"__proto__":{"polluted":true}}'); } catch { /* expected */ }
    expect({}.polluted).toBeUndefined();
    expect(Object.prototype.polluted).toBeUndefined();
  });

  it('rejects nesting past the depth cap instead of overflowing', () => {
    let s = '1';
    for (let i = 0; i < 200; i++) s = `{"n":${s}}`;
    denies('ERR_SCHEMA_VIOLATION', () => v.parseDocument(s));
  });
});

describe('PEM — strict, never best-effort', () => {
  const good = '-----BEGIN CERTIFICATE-----\nTUlJQg==\n-----END CERTIFICATE-----\n';
  it('accepts a well-formed block', () => {
    const { label, der } = v.validatePem(good, 'CERTIFICATE');
    expect(label).toBe('CERTIFICATE');
    expect(der.length).toBeGreaterThan(0);
  });
  for (const [name, val] of Object.entries({
    'missing END': '-----BEGIN CERTIFICATE-----\nTUlJQg==\n',
    'mismatched labels': '-----BEGIN CERTIFICATE-----\nTUlJQg==\n-----END PRIVATE KEY-----\n',
    'non-base64 body': '-----BEGIN CERTIFICATE-----\n!!!not base64!!!\n-----END CERTIFICATE-----\n',
    'empty body': '-----BEGIN CERTIFICATE-----\n\n-----END CERTIFICATE-----\n',
    'two blocks in one': good + good,
    'no PEM at all': 'just some text',
  })) {
    it(`rejects ${name}`, () => denies('ERR_MALFORMED_PEM', () => v.validatePem(val)));
  }
  it('rejects an oversized PEM', () =>
    denies('ERR_MALFORMED_PEM', () => v.validatePem('x'.repeat(v.MAX_PEM_BYTES + 1))));
  it('rejects the wrong label when one is expected', () =>
    denies('ERR_MALFORMED_PEM', () => v.validatePem(good, 'PRIVATE KEY')));
});

describe('timestamps — leap-year boundaries (the days-in-month check)', () => {
  it('accepts 2024-02-29 (leap year)', () =>
    expect(v.validateTimestamp('2024-02-29T00:00:00Z')).toBeTruthy());
  it('rejects 2026-02-29 (not a leap year)', () =>
    denies('ERR_TIMESTAMP_FORMAT', () => v.validateTimestamp('2026-02-29T00:00:00Z')));
  it('accepts 2000-02-29 (divisible by 400)', () =>
    expect(v.validateTimestamp('2000-02-29T00:00:00Z')).toBeTruthy());
  it('rejects 2100-02-29 (divisible by 100, not 400)', () =>
    denies('ERR_TIMESTAMP_FORMAT', () => v.validateTimestamp('2100-02-29T00:00:00Z')));
  it('rejects a 31st in a 30-day month', () =>
    denies('ERR_TIMESTAMP_FORMAT', () => v.validateTimestamp('2026-04-31T00:00:00Z')));
  it('rejects a leap second — ISO-8601 allows :60, no JS engine can parse it', () =>
    denies('ERR_TIMESTAMP_FORMAT', () => v.validateTimestamp('2026-06-30T23:59:60Z')));
});
