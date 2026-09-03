/**
 * The error catalogue is the one record the page, the banner, the walk and the
 * exported JSON all read. These tests pin its shape and DenyError's contract.
 */
import { describe, it, expect } from 'vitest';
import { ERRORS, ERROR_CODES, DenyError } from '../src/errors.js';

describe('the catalogue', () => {
  it('every code names itself, a stage 0–9, a title, and a clause or an explicit null', () => {
    for (const code of ERROR_CODES) {
      const spec = ERRORS[code];
      expect(spec.code).toBe(code);
      expect(Number.isInteger(spec.stage) && spec.stage >= 0 && spec.stage <= 9).toBe(true);
      expect(typeof spec.title === 'string' && spec.title.length > 0).toBe(true);
      expect(spec.section === null || /^\d+(\.\d+)*$/.test(spec.section)).toBe(true);
    }
  });
  it('codes are unique and the record is frozen', () => {
    expect(new Set(ERROR_CODES).size).toBe(ERROR_CODES.length);
    expect(Object.isFrozen(ERRORS)).toBe(true);
    expect(Object.isFrozen(ERRORS.ERR_INTERNAL)).toBe(true);
  });
});

describe('DenyError', () => {
  it('refuses an unknown code rather than minting one', () => {
    expect(() => new DenyError('ERR_MADE_UP')).toThrow(/unknown error code/);
  });
  it('carries clause, stage, title, detail and banner', () => {
    const e = new DenyError('ERR_SCOPE_ESCALATION', 'child asked for admin:all');
    expect(e).toBeInstanceOf(Error);
    expect(e.name).toBe('DenyError');
    expect(e.section).toBe('10.3');
    expect(e.stage).toBe(8);
    expect(e.message).toBe(`${e.title}: child asked for admin:all`);
    expect(e.banner).toBe('ERR_SCOPE_ESCALATION · §10.3');
  });
  it('a code with no clause banners as the code alone, and a missing detail is the title', () => {
    const e = new DenyError('ERR_MALFORMED_JSON');
    expect(e.banner).toBe('ERR_MALFORMED_JSON');
    expect(e.message).toBe(e.title);
  });
  it('serialises to the stages[] shape — code, section, detail — and nothing else', () => {
    expect(JSON.parse(JSON.stringify(new DenyError('ERR_INTERNAL', 'why')))).toEqual({
      code: 'ERR_INTERNAL', section: '15.1', detail: 'why',
    });
  });
});
