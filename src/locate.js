/**
 * Find the line in the editor that a refusal is about.
 *
 * The code reviewer UI this borrows from gets a line number for free — its
 * findings come from a linter that already works in lines. A pipeline refusal
 * knows a JSON path (`chain[2].metadata.allowed_scopes`), not a line, so the
 * mapping has to be built.
 *
 * The approach is deliberately the boring one: walk the pretty-printed text and
 * track a path stack from indentation and keys. It works because the editor's
 * content is always `JSON.stringify(doc, null, 2)` — the page is the only thing
 * that writes it, and re-serialising is exactly what happens after every
 * sabotage. A tolerant parser would be more general and would also be a second
 * JSON implementation to keep correct; this needs to agree with one formatter,
 * not with the grammar.
 *
 * Returns a 1-based line number, or null when the path is not present — the
 * caller then simply does not scroll, which is the right failure mode for a
 * convenience feature.
 */

const INDENT = 2;

/**
 * Parse `chain[2].metadata.allowed_scopes` into ['chain', 2, 'metadata', …].
 * Array indices become numbers so they can be matched positionally.
 */
export function parsePath(path) {
  if (Array.isArray(path)) return path;
  if (typeof path !== 'string' || path.length === 0) return [];
  const segments = [];
  for (const part of path.split('.')) {
    const m = /^([^[\]]*)((?:\[\d+\])*)$/.exec(part);
    if (!m) return [];
    if (m[1]) segments.push(m[1]);
    for (const idx of m[2].matchAll(/\[(\d+)\]/g)) segments.push(Number(idx[1]));
  }
  return segments;
}

/**
 * Locate a JSON path in pretty-printed text.
 *
 * @param {string} text  the editor contents
 * @param {string|Array} path
 * @returns {number|null} 1-based line number
 */
export function locatePath(text, path) {
  const target = parsePath(path);
  if (target.length === 0) return null;

  const lines = text.split('\n');
  // stack[d] is the key or index owning the container opened at depth d.
  const stack = [];
  // Array element counters, keyed by depth.
  const counters = new Map();

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    if (trimmed === '') continue;

    const indent = line.length - line.trimStart().length;
    const depth = Math.floor(indent / INDENT);

    // The root `{` is depth 0 and contributes nothing to a path, so a key at
    // indent 2 (depth 1) is path element 0. Everything below is shifted by one.
    if (depth === 0) continue;
    const slot = depth - 1;

    // Leaving a container: drop anything at or below this slot.
    stack.length = Math.min(stack.length, slot);
    for (const d of [...counters.keys()]) if (d > depth) counters.delete(d);

    const keyMatch = /^"((?:[^"\\]|\\.)*)"\s*:/.exec(trimmed);
    let here;
    if (keyMatch) {
      here = decodeKey(keyMatch[1]);
    } else if (trimmed !== '}' && trimmed !== ']' && trimmed !== '},' && trimmed !== '],') {
      // An array element: its "key" is its position.
      const n = counters.get(depth) ?? 0;
      counters.set(depth, n + 1);
      here = n;
    } else {
      continue;
    }

    stack[slot] = here;
    const path0 = stack.slice(0, slot + 1);

    if (path0.length === target.length && path0.every((v, j) => v === target[j])) {
      return i + 1;
    }
  }
  return null;
}

/**
 * Locate a literal value — the fallback when a refusal names a value rather
 * than a path, e.g. the scope string that overreached.
 *
 * Matched as a quoted JSON string so `read:events` does not also hit
 * `read:events:extra`, and so a value cannot match a key of the same name.
 */
export function locateValue(text, value) {
  if (typeof value !== 'string' || value === '') return null;
  const needle = JSON.stringify(value);
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    let from = 0;
    for (;;) {
      const idx = lines[i].indexOf(needle, from);
      if (idx === -1) break;
      // A quoted string immediately followed by `:` is a key, not a value.
      const after = lines[i].slice(idx + needle.length);
      if (!/^\s*:/.test(after)) return i + 1;
      from = idx + needle.length;
    }
  }
  return null;
}

/**
 * Best effort: try the path, then any values the refusal named.
 * Used by the UI to put a marker in the gutter and scroll the editor.
 */
/**
 * Decode a JSON string body back to its value.
 *
 * The capturing regex accepts `\\.` — backslash followed by ANY character — because
 * it only needs to know where the string ends. JSON is stricter: `\\q` is not a
 * legal escape, so re-wrapping the capture in quotes and parsing it throws.
 *
 * This function is fed the raw contents of the editor, which is the one input the
 * page has, and it runs on the highlight path — so an uncaught throw here takes
 * out the render for a document the validator would otherwise have refused with a
 * clean error. Highlighting is best-effort by nature: a key it cannot decode is a
 * key that will not match a failure path, which costs a highlight, not a verdict.
 */
function decodeKey(body) {
  try {
    return JSON.parse(`"${body}"`);
  } catch {
    return body;
  }
}

export function locateFailure(text, { path = null, values = [] } = {}) {
  if (path) {
    const line = locatePath(text, path);
    if (line !== null) return line;
  }
  for (const v of values) {
    const line = locateValue(text, v);
    if (line !== null) return line;
  }
  return null;
}

/** Character offsets of a 1-based line, for `textarea.setSelectionRange`. */
export function lineRange(text, lineNumber) {
  const lines = text.split('\n');
  if (lineNumber < 1 || lineNumber > lines.length) return null;
  let start = 0;
  for (let i = 0; i < lineNumber - 1; i++) start += lines[i].length + 1;
  return { start, end: start + lines[lineNumber - 1].length };
}
