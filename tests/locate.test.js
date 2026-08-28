/**
 * Mapping a refusal to a line in the editor — the gutter marker DESIGN.md asks
 * for, and the input to the scroll-and-highlight borrowed from the code
 * reviewer UI.
 */
import { describe, it, expect } from 'vitest';
import { locatePath, locateValue, locateFailure, lineRange, parsePath } from '../src/locate.js';

const DOC = {
  chain: [
    { role: 'ca', metadata: { subject: 'CA' } },
    { role: 'agent', metadata: { agent_id: 'a-1', allowed_scopes: ['read:events', 'write:events'] } },
    { role: 'agent', metadata: { agent_id: 'b-2', allowed_scopes: ['admin:all'] }, requested_scopes: ['admin:all'] },
  ],
  policy_doc: { allowed_scopes: ['read:events'], owner: 'owner@example.com' },
  crl: { revoked: [], disabled: [] },
};
const TEXT = JSON.stringify(DOC, null, 2);
const lineAt = (n) => TEXT.split('\n')[n - 1];

describe('parsePath', () => {
  it('splits keys and array indices', () => {
    expect(parsePath('chain[2].metadata.allowed_scopes'))
      .toEqual(['chain', 2, 'metadata', 'allowed_scopes']);
    expect(parsePath('crl.revoked')).toEqual(['crl', 'revoked']);
    expect(parsePath('chain[0]')).toEqual(['chain', 0]);
  });
  it('passes arrays through and tolerates junk', () => {
    expect(parsePath(['a', 1])).toEqual(['a', 1]);
    expect(parsePath('')).toEqual([]);
    expect(parsePath(null)).toEqual([]);
  });
});

describe('locatePath', () => {
  it('finds a top-level key', () => {
    expect(lineAt(locatePath(TEXT, 'policy_doc'))).toContain('"policy_doc"');
    expect(lineAt(locatePath(TEXT, 'crl'))).toContain('"crl"');
  });

  it('finds a nested key inside a specific array element', () => {
    // The distinguishing test: chain[1] and chain[2] both have allowed_scopes.
    const l1 = locatePath(TEXT, 'chain[1].metadata.allowed_scopes');
    const l2 = locatePath(TEXT, 'chain[2].metadata.allowed_scopes');
    expect(l1).not.toBe(l2);
    expect(lineAt(l1)).toContain('allowed_scopes');
    expect(lineAt(l2)).toContain('allowed_scopes');
    // chain[2] comes later in the document than chain[1]
    expect(l2).toBeGreaterThan(l1);
  });

  it('distinguishes the same key at different depths', () => {
    const inChain = locatePath(TEXT, 'chain[2].metadata.allowed_scopes');
    const inPolicy = locatePath(TEXT, 'policy_doc.allowed_scopes');
    expect(inChain).not.toBe(inPolicy);
    expect(inPolicy).toBeGreaterThan(inChain);
  });

  it('finds an array element by index', () => {
    expect(lineAt(locatePath(TEXT, 'chain[0]'))).toContain('{');
  });

  it('returns null for a path that is not there', () => {
    expect(locatePath(TEXT, 'chain[9].metadata')).toBeNull();
    expect(locatePath(TEXT, 'nonexistent')).toBeNull();
    expect(locatePath(TEXT, '')).toBeNull();
  });

  it('handles empty arrays without losing its place', () => {
    expect(lineAt(locatePath(TEXT, 'crl.disabled'))).toContain('"disabled"');
  });
});

describe('locateValue', () => {
  it('finds a quoted string value', () => {
    expect(lineAt(locateValue(TEXT, 'owner@example.com'))).toContain('owner@example.com');
  });

  it('does not match a longer scope that merely starts the same', () => {
    const text = JSON.stringify({ a: ['read:events:extra'], b: ['read:events'] }, null, 2);
    expect(lineAt.call(null, 0), 'sanity').toBeUndefined();
    const line = locateValue(text, 'read:events');
    expect(text.split('\n')[line - 1]).toContain('"read:events"');
    expect(text.split('\n')[line - 1]).not.toContain('extra');
  });

  it('returns null when absent', () => {
    expect(locateValue(TEXT, 'nowhere:at:all')).toBeNull();
    expect(locateValue(TEXT, '')).toBeNull();
    expect(locateValue(TEXT, 42)).toBeNull();
  });
});

describe('locateFailure — path first, then values', () => {
  it('prefers the path', () => {
    expect(locateFailure(TEXT, { path: 'policy_doc.owner', values: ['admin:all'] }))
      .toBe(locatePath(TEXT, 'policy_doc.owner'));
  });
  it('falls back to a named value', () => {
    expect(locateFailure(TEXT, { path: 'not.a.path', values: ['admin:all'] }))
      .toBe(locateValue(TEXT, 'admin:all'));
  });
  it('returns null rather than guessing', () => {
    expect(locateFailure(TEXT, { path: 'nope', values: ['also-nope'] })).toBeNull();
    expect(locateFailure(TEXT, {})).toBeNull();
  });
});

describe('lineRange — offsets for setSelectionRange', () => {
  it('selects exactly the line', () => {
    const n = locatePath(TEXT, 'policy_doc');
    const { start, end } = lineRange(TEXT, n);
    expect(TEXT.slice(start, end)).toBe(lineAt(n));
  });
  it('handles the first and last lines', () => {
    expect(TEXT.slice(...Object.values(lineRange(TEXT, 1)))).toBe(TEXT.split('\n')[0]);
    const last = TEXT.split('\n').length;
    expect(lineRange(TEXT, last)).not.toBeNull();
  });
  it('returns null out of range', () => {
    expect(lineRange(TEXT, 0)).toBeNull();
    expect(lineRange(TEXT, 99999)).toBeNull();
  });
});
