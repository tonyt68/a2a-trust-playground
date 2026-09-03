/**
 * The input contract, exercised at its edges.
 *
 * Every regex here is anchored and bounded; every failure is a DenyError with a
 * code; nothing is coerced. -03 §3 turned three of this file's own hardening
 * rules into normative ones — duplicate members refused BY THE PARSER, Z-only
 * timestamps, flat objects — so those are tested as clauses, not as taste.
 */
import { describe, it, expect } from 'vitest';
import * as v from '../src/validate-input.js';
import { DenyError } from '../src/errors.js';

const denies = (code, fn) => {
  let caught = null;
  try { fn(); } catch (e) { caught = e; }
  expect(caught, 'expected a refusal').toBeInstanceOf(DenyError);
  expect(caught.code).toBe(code);
};

const XSS = ['<script>alert(1)</script>', '"><img src=x onerror=alert(1)>', 'javascript:alert(1)',
  '{{constructor.constructor("return this")()}}', ' ', 'a\nb'];

describe('agent identifiers — RFC 9562, any version, lowercase (§7.2)', () => {
  it('accepts a v4 and a v7', () => {
    expect(v.validateUuid('8f14e45f-ceea-467a-9c0f-7ad0f1b0d5aa')).toBe('8f14e45f-ceea-467a-9c0f-7ad0f1b0d5aa');
    expect(v.validateUuid('019b3c8e-2f10-7a4b-9c6d-3e5f7a9b1c2d')).toBe('019b3c8e-2f10-7a4b-9c6d-3e5f7a9b1c2d');
  });
  for (const [name, val] of Object.entries({
    'uppercase — refused, never case-folded': '8F14E45F-CEEA-467A-9C0F-7AD0F1B0D5AA',
    'version nibble 0': '8f14e45f-ceea-067a-9c0f-7ad0f1b0d5aa',
    'version nibble 9': '8f14e45f-ceea-967a-9c0f-7ad0f1b0d5aa',
    'wrong variant': '8f14e45f-ceea-467a-1c0f-7ad0f1b0d5aa',
    'braces': '{8f14e45f-ceea-467a-9c0f-7ad0f1b0d5aa}',
    'urn prefix': 'urn:uuid:8f14e45f-ceea-467a-9c0f-7ad0f1b0d5aa',
    'too short': '8f14e45f-ceea-467a-9c0f-7ad0f1b0d5a',
    'trailing newline': '8f14e45f-ceea-467a-9c0f-7ad0f1b0d5aa\n',
    'number': 42, 'null': null, 'array': ['8f14e45f-ceea-467a-9c0f-7ad0f1b0d5aa'],
  })) {
    it(`rejects ${name}`, () => denies('ERR_AGENT_ID_FORMAT', () => v.validateUuid(val)));
  }
  it('rejects every XSS payload', () => {
    for (const p of XSS) denies('ERR_AGENT_ID_FORMAT', () => v.validateUuid(p));
  });
});

describe('scopes — §10.3 syntax and set semantics', () => {
  it('accepts the draft scopes', () => {
    expect(v.validateScopeSet(['read:events', 'write:events'])).toEqual(['read:events', 'write:events']);
    expect(v.validateScope('secrets:vault-a:read')).toBe('secrets:vault-a:read');
  });
  it('rejects an over-long scope', () => denies('ERR_SCOPE_SYNTAX', () => v.validateScope('a'.repeat(65))));
  it('rejects uppercase — no case folding', () => denies('ERR_SCOPE_SYNTAX', () => v.validateScope('Read:Events')));
  it('rejects a wildcard — admin:* names nothing', () => denies('ERR_SCOPE_SYNTAX', () => v.validateScope('admin:*')));
  it('rejects a confusable — Cyrillic е', () => denies('ERR_SCOPE_SYNTAX', () => v.validateScope('rеad:events')));
  it('rejects more than 32 scopes', () =>
    denies('ERR_FIELD_RANGE', () => v.validateScopeSet(Array.from({ length: 33 }, (_, i) => `s${i}`))));
  it('rejects duplicates rather than de-duplicating', () =>
    denies('ERR_SCHEMA_VIOLATION', () => v.validateScopeSet(['a', 'a'])));
  it('accepts an empty collection — emptiness is refused where it matters, at the request', () =>
    expect(v.validateScopeSet([])).toEqual([]));
  it('rejects a non-array', () => denies('ERR_SCHEMA_VIOLATION', () => v.validateScopeSet('read:events')));
  it('rejects every XSS payload', () => { for (const p of XSS) denies('ERR_SCOPE_SYNTAX', () => v.validateScope(p)); });
});

describe('free text — rejected, never sanitized', () => {
  it('accepts ordinary owner, org and policy_ref values', () => {
    expect(v.validateText('owner-authority', 'owner')).toBe('owner-authority');
    expect(v.validateText('policy-store/8f14e45f-ceea-467a-9c0f-7ad0f1b0d5aa/current', 'policy_ref')).toBeTruthy();
  });
  it('rejects over-long text', () => denies('ERR_FIELD_CHARSET', () => v.validateText('a'.repeat(129), 'owner')));
  it('rejects every XSS payload, returning nothing partial', () => {
    for (const p of XSS) denies('ERR_FIELD_CHARSET', () => v.validateText(p, 'owner'));
  });
});

describe('validateReference — the shape §8.2 gives policy_ref, and no traversal', () => {
  it('accepts an ordinary path-shaped reference', () =>
    expect(v.validateReference('policy-store/8f14e45f-ceea-467a-9c0f-7ad0f1b0d5aa/current', 'policy_ref'))
      .toBeTruthy());
  it('refuses a leading slash, and empty, "." or ".." segments — this value is CA-signed into a certificate', () => {
    for (const bad of ['/etc/passwd', '../../../etc/shadow', 'a//b', 'a/./b', 'a/../b', 'a/b/..', '']) {
      denies('ERR_FIELD_CHARSET', () => v.validateReference(bad, 'policy_ref'));
    }
  });
});

describe('numbers — no coercion', () => {
  it('accepts an in-range integer and zero', () => {
    expect(v.validateInteger(5, 'max_children')).toBe(5);
    expect(v.validateInteger(0, 'max_children')).toBe(0);
  });
  for (const [name, val] of Object.entries({
    'a numeric string': '5', 'a float': 1.5, 'NaN': NaN, 'Infinity': Infinity, 'null': null, 'a boolean': true,
  })) {
    it(`rejects ${name}`, () => denies('ERR_FIELD_RANGE', () => v.validateInteger(val, 'max_children')));
  }
  it('rejects out of range', () => {
    denies('ERR_FIELD_RANGE', () => v.validateInteger(-1, 'max_children'));
    denies('ERR_FIELD_RANGE', () => v.validateInteger(1001, 'max_children'));
  });
});

describe('ttl_seconds — §9.3 caps it at seven days', () => {
  it('accepts one second and exactly 604800', () => {
    expect(v.validateTtl(1)).toBe(1);
    expect(v.validateTtl(604800)).toBe(604800);
  });
  it('refuses 604801 with its own clause', () => denies('ERR_TTL_TOO_LONG', () => v.validateTtl(604801)));
  it('refuses zero, negatives, floats and non-numbers', () => {
    for (const x of [0, -1, 1.5, '86400', null]) denies('ERR_FIELD_RANGE', () => v.validateTtl(x));
  });
});

describe('timestamps — RFC 3339, UTC, Z designator only (§3)', () => {
  it('accepts the Z form, with and without fractional seconds', () => {
    expect(v.validateTimestamp('2026-09-03T12:00:00Z')).toBeTruthy();
    expect(v.validateTimestamp('2026-09-03T12:00:00.123Z')).toBeTruthy();
    expect(v.validateTimestamp('2026-09-03T12:00:00.123456789Z')).toBeTruthy();
  });
  for (const [name, val] of Object.entries({
    'a +00:00 offset — the same instant with different octets': '2026-09-03T12:00:00+00:00',
    'a -05:00 offset': '2026-09-03T12:00:00-05:00',
    'a lowercase z': '2026-09-03T12:00:00z',
    'no designator': '2026-09-03T12:00:00',
    'a space separator': '2026-09-03 12:00:00Z',
    'a date only': '2026-09-03',
    'a month 13': '2026-13-03T12:00:00Z',
    'a day 0': '2026-09-00T12:00:00Z',
    'hour 24': '2026-09-03T24:00:00Z',
    'a year before 2000': '1999-12-31T23:59:59Z',
    'a year after 2100': '2101-01-01T00:00:00Z',
    'a number': 1756900000000,
    'nonsense': 'next tuesday',
  })) {
    it(`rejects ${name}`, () => denies('ERR_TIMESTAMP_FORMAT', () => v.validateTimestamp(val)));
  }
  it('accepts 2024-02-29 (leap year)', () => expect(v.validateTimestamp('2024-02-29T00:00:00Z')).toBeTruthy());
  it('rejects 2026-02-29 (not a leap year)', () => denies('ERR_TIMESTAMP_FORMAT', () => v.validateTimestamp('2026-02-29T00:00:00Z')));
  it('accepts 2000-02-29 (divisible by 400)', () => expect(v.validateTimestamp('2000-02-29T00:00:00Z')).toBeTruthy());
  it('rejects 2100-02-29 (divisible by 100, not 400)', () => denies('ERR_TIMESTAMP_FORMAT', () => v.validateTimestamp('2100-02-29T00:00:00Z')));
  it('rejects a 31st in a 30-day month', () => denies('ERR_TIMESTAMP_FORMAT', () => v.validateTimestamp('2026-04-31T00:00:00Z')));
  it('rejects a leap second — ISO-8601 allows :60, no JS engine can parse it', () =>
    denies('ERR_TIMESTAMP_FORMAT', () => v.validateTimestamp('2026-06-30T23:59:60Z')));
});

describe('nonces — §19.2, base64 of at least 128 bits', () => {
  it('accepts 16 and 32 random bytes', () => {
    expect(v.validateNonce(Buffer.alloc(16, 7).toString('base64'))).toBeTruthy();
    expect(v.validateNonce(Buffer.alloc(32, 7).toString('base64'))).toBeTruthy();
  });
  it('refuses 15 bytes', () => denies('ERR_SCHEMA_VIOLATION', () => v.validateNonce(Buffer.alloc(15, 7).toString('base64'))));
  it('refuses non-base64 and url-safe base64', () => {
    denies('ERR_SCHEMA_VIOLATION', () => v.validateNonce('not base64!'));
    denies('ERR_SCHEMA_VIOLATION', () => v.validateNonce('AAAAAAAAAAAAAAAAAAAAA-'));
  });
});

describe('flat objects — §3', () => {
  it('accepts strings, integers and arrays of strings', () => {
    expect(() => v.assertFlatObject({ a: 'x', b: 1, c: ['y', 'z'], d: [] }, 't')).not.toThrow();
  });
  for (const [name, val] of Object.entries({
    'a nested object': { a: { b: 1 } }, 'an array of numbers': { a: [1] }, 'an array of objects': { a: [{}] },
    'null': { a: null }, 'a boolean': { a: true }, 'a float': { a: 1.5 },
  })) {
    it(`refuses ${name}`, () => denies('ERR_OBJECT_NOT_FLAT', () => v.assertFlatObject(val, 't')));
  }
  it('refuses a non-object', () => denies('ERR_OBJECT_NOT_FLAT', () => v.assertFlatObject([], 't')));
});

describe('the strict parser — §3 puts the duplicate rule on the PARSER', () => {
  it('refuses a duplicate member at the top level', () =>
    denies('ERR_DUPLICATE_MEMBER', () => v.parseJsonStrict('{"a":1,"a":2}')));
  it('refuses a duplicate member at depth', () =>
    denies('ERR_DUPLICATE_MEMBER', () => v.parseJsonStrict('{"x":{"scopes":["a"],"scopes":["b"]}}')));
  it('ACCEPTS the same name in two different objects — the false positive a regex would raise', () => {
    expect(v.parseJsonStrict('{"a":{"x":1},"b":{"x":1}}')).toEqual({ a: { x: 1 }, b: { x: 1 } });
  });
  it('JSON.parse would have kept the last one and reported success', () => {
    expect(JSON.parse('{"a":1,"a":2}')).toEqual({ a: 2 });   // the behaviour §3 forbids
  });
  it('agrees with JSON.parse on everything that is not a duplicate', () => {
    const corpus = [
      '{"s":"caf\\u00e9 \\ud83d\\udd10 \\" \\\\ \\/ \\b\\f\\n\\r\\t","n":[-0,1.5e3,0,-17,1E-2],"t":[true,false,null],"e":{},"l":[]}',
      '  [ 1 , "two" , {"three":3} ]  ',
      '"just a string"', '12', 'true', 'null',
      JSON.stringify({ cert_pem: '-----BEGIN X-----\nAAAA\n-----END X-----\n', k: ' é', n: [1, 2, { a: [] }] }, null, 2),
    ];
    for (const text of corpus) expect(JSON.stringify(v.parseJsonStrict(text))).toBe(JSON.stringify(JSON.parse(text)));
  });
  for (const [name, text] of Object.entries({
    'trailing content': '{"a":1}x', 'a leading zero': '{"a":01}',
    'a bare control character': `{"a":"${String.fromCharCode(1)}"}`,
    'a leading dot': '{"a":.5}', 'a trailing comma': '[1,]', 'empty input': '', 'a truncated literal': 'nul',
    'single quotes': "{'a':1}", 'an unterminated string': '{"a":"x', 'a bad escape': '{"\\q":1}',
    'a bad unicode escape': '{"a":"\\u12"}', 'NaN': '{"a":NaN}', 'a comment': '{"a":1}//x',
  })) {
    it(`rejects ${name} as a syntax error`, () => {
      expect(() => v.parseJsonStrict(text)).toThrow(v.JsonSyntaxError);
    });
  }
  it('creates __proto__ as an OWN key, not as the prototype', () => {
    const o = v.parseJsonStrict('{"__proto__":{"polluted":1}}');
    expect(Object.getOwnPropertyNames(o)).toEqual(['__proto__']);
    expect(Object.getPrototypeOf(o)).toBe(Object.prototype);
    expect({}.polluted).toBeUndefined();
  });
  it('refuses nesting past the cap instead of exhausting the stack', () =>
    denies('ERR_SCHEMA_VIOLATION', () => v.parseJsonStrict('{"n":'.repeat(40) + '1' + '}'.repeat(40))));
});

describe('document parsing — cap, then parse, then structure', () => {
  it('accepts a document whose keys are all recognised', () =>
    expect(v.parseDocument('{"chain":[],"crl":{},"audit":{},"policy":{},"grant":{},"current_policy_version":1}')).toBeTruthy());
  it('refuses an unrecognised top-level key', () =>
    denies('ERR_SCHEMA_VIOLATION', () => v.parseDocument('{"chain":[],"rebac_override":true}')));
  it('refuses the -02 envelope keys — a field that was meaningful once is the worst kind of survivor', () => {
    for (const k of ['policy_doc', 'existing_cert', 'owner_sig', 'pa_sig', 'policy_content_hash', 'policy_update']) {
      denies('ERR_SCHEMA_VIOLATION', () => v.parseDocument(`{"chain":[],"${k}":1}`));
    }
  });
  it('rejects an oversized document BEFORE parsing', () => {
    const big = `{"chain":"${'x'.repeat(v.MAX_DOCUMENT_BYTES)}"}`;
    denies('ERR_DOCUMENT_TOO_LARGE', () => v.parseDocument(big));
  });
  it('rejects malformed JSON without leaking the parser message', () => {
    let caught;
    try { v.parseDocument('{"chain": [ {{{'); } catch (e) { caught = e; }
    expect(caught.code).toBe('ERR_MALFORMED_JSON');
    expect(caught.message).not.toMatch(/position|token|Unexpected/);
  });
  it('rejects a duplicate member with the §3 code, not as a syntax error', () =>
    denies('ERR_DUPLICATE_MEMBER', () => v.parseDocument('{"chain":[],"chain":[]}')));
  it('rejects a JSON array or scalar at the root', () => {
    denies('ERR_SCHEMA_VIOLATION', () => v.parseDocument('[1]'));
    denies('ERR_SCHEMA_VIOLATION', () => v.parseDocument('"x"'));
  });
  for (const key of v.FORBIDDEN_KEYS) {
    it(`rejects a top-level "${key}" key`, () =>
      denies('ERR_PROTOTYPE_POLLUTION', () => v.parseDocument(`{"${key}":{}}`)));
    it(`rejects a nested "${key}" key`, () =>
      denies('ERR_PROTOTYPE_POLLUTION', () => v.parseDocument(`{"chain":[{"${key}":{}}]}`)));
  }
  it('does not pollute Object.prototype even while rejecting', () => {
    try { v.parseDocument('{"__proto__":{"polluted":true}}'); } catch { /* expected */ }
    expect({}.polluted).toBeUndefined();
  });
  it('rejects nesting past the depth cap instead of overflowing', () => {
    const deep = `{"chain":${'['.repeat(v.MAX_NESTING_DEPTH + 2)}${']'.repeat(v.MAX_NESTING_DEPTH + 2)}}`;
    denies('ERR_SCHEMA_VIOLATION', () => v.parseDocument(deep));
  });
});

describe('PEM — strict, never best-effort', () => {
  const body = Buffer.from('hello world, this is DER-ish').toString('base64');
  const good = `-----BEGIN CERTIFICATE-----\n${body}\n-----END CERTIFICATE-----\n`;
  it('accepts a well-formed block', () => {
    const { label, der } = v.validatePem(good);
    expect(label).toBe('CERTIFICATE');
    expect(der.length).toBeGreaterThan(0);
  });
  for (const [name, val] of Object.entries({
    'two blocks': good + good, 'mismatched labels': good.replace('END CERTIFICATE', 'END X'),
    'no header': body, 'a lowercase label': good.replace(/CERTIFICATE/g, 'certificate'),
    'non-base64 body': good.replace(body, 'not*base64'), 'an empty body': '-----BEGIN CERTIFICATE-----\n\n-----END CERTIFICATE-----\n',
    'a number': 42,
  })) {
    it(`rejects ${name}`, () => denies('ERR_MALFORMED_PEM', () => v.validatePem(val)));
  }
  it('rejects an oversized PEM', () =>
    denies('ERR_MALFORMED_PEM', () => v.validatePem(`-----BEGIN CERTIFICATE-----\n${'A'.repeat(v.MAX_PEM_BYTES)}\n-----END CERTIFICATE-----\n`)));
  it('rejects the wrong label when one is expected', () =>
    denies('ERR_MALFORMED_PEM', () => v.validatePem(good, 'PRIVATE KEY')));
});

describe('parser and document guards the corpus does not reach', () => {
  it('a lone minus is a bad number, and a list without commas is a syntax error', () => {
    expect(() => v.parseJsonStrict('-')).toThrow(v.JsonSyntaxError);
    expect(() => v.parseJsonStrict('[1 2]')).toThrow(v.JsonSyntaxError);
  });
  it('assertNoForbiddenKeys caps nesting on its own, not only through the parser', () => {
    let nested = [];
    for (let i = 0; i < v.MAX_NESTING_DEPTH + 2; i++) nested = [nested];
    denies('ERR_SCHEMA_VIOLATION', () => v.assertNoForbiddenKeys(nested));
  });
  it('parseDocument refuses anything that is not text', () => {
    for (const notText of [42, null, undefined, {}, ['{}'], new TextEncoder().encode('{}')]) {
      denies('ERR_MALFORMED_JSON', () => v.parseDocument(notText));
    }
  });
});
