/**
 * Tamper-evident audit chain — §10.4 (the entry), §19.7 (the hash chain).
 *
 * SHA-256 hash chain: each entry commits to the previous entry's hash, so
 * altering any entry invalidates that entry and every one after it. The
 * verifier reports the break AND names the entry, which is the whole point of
 * the "alter an audit entry" button.
 *
 * ── The entry IS the draft's object, not a wrapper around one ───────────────
 *
 * §10.4 Table 6 defines the audit log entry for a spawn event as a flat JSON
 * object whose members INCLUDE previous_hash and entry_hash. §19.7 then hashes
 * every member but entry_hash. So an entry here is exactly that object: no
 * `index`, no `event` sub-object, nothing the draft does not name. Spawn
 * entries carry the Table 6 members and nothing else; the page's own decisions
 * (issuing a template, adopting a policy, verifying a chain) are recorded in
 * the same chain as flat entries carrying an `action`, which the draft does
 * not govern and does not forbid.
 *
 * §19.7 specifies the preimage: SHA-256 over the canonical form (§11.5, JCS)
 * of every member other than entry_hash. One canonical form, the same
 * `canonicalize` the signatures use. An unspecified preimage is not a detail:
 * two implementations hashing different field sets each read the other's
 * chain as broken.
 */

import { canonicalize, AUDIT_SPAWN_FIELDS, AUDIT_SPAWN_OPTIONAL_FIELDS } from './canonical.js';
import { DenyError } from './errors.js';
import { bytesToHex } from './encoding.js';
import {
  assertFlatObject, validateUuid, validateScopeSet, validateNonce, validateTimestamp,
} from './validate-input.js';

/** §10.4 — the previous_hash of the first entry of a log: sixty-four zero digits. */
export const GENESIS_PREVIOUS_HASH = '0'.repeat(64);

const HEX64 = /^[0-9a-f]{64}$/;
const OUTCOMES = new Set(['ALLOWED', 'DENIED']);

const encoder = new TextEncoder();

/** SHA-256 hex, via Web Crypto — available in browsers and in Node. */
async function sha256Hex(text) {
  const digest = await crypto.subtle.digest('SHA-256', encoder.encode(text));
  return bytesToHex(new Uint8Array(digest));
}

/**
 * The preimage of §19.7: every member of the entry other than entry_hash —
 * previous_hash included — in the single canonical form of §11.5.
 */
export function entryPreimage(entry) {
  const { entry_hash: _omitted, ...rest } = entry;
  return canonicalize(rest);
}

export async function hashEntry(entry) {
  return sha256Hex(entryPreimage(entry));
}

/**
 * §10.4 Table 6 — the members of a spawn event's entry, before the chain adds
 * previous_hash, timestamp and entry_hash. granted_scopes is empty and reason
 * is present exactly when the outcome is DENIED.
 */
export function spawnEntry({
  spawningAgentId, childTemplateId, requestedScopes, grantedScopes = requestedScopes,
  spawnNonce, grantId = null, outcome, reason = null,
}) {
  const denied = outcome === 'DENIED';
  const e = {
    spawning_agent_id: spawningAgentId,
    child_template_id: childTemplateId,
    requested_scopes: [...requestedScopes],
    granted_scopes: denied ? [] : [...grantedScopes],
    spawn_nonce: spawnNonce,
    outcome,
  };
  if (grantId !== null) e.grant_id = grantId;
  if (denied) e.reason = reason ?? 'refused';
  return e;
}

/**
 * §10.4 — an entry that describes a spawn event carries exactly the members of
 * Table 6, subject to its presence rules. Everything is refused whole; a
 * member the table does not list is refused the way every other document's
 * unknown member is.
 */
export function assertSpawnEntry(entry, label = 'audit entry') {
  const keys = Object.keys(entry);
  const missing = AUDIT_SPAWN_FIELDS.filter((f) => !keys.includes(f));
  if (missing.length) {
    throw new DenyError('ERR_AUDIT_ENTRY_INVALID', `${label} omits ${missing.join(', ')}`);
  }
  const allowed = [...AUDIT_SPAWN_FIELDS, ...AUDIT_SPAWN_OPTIONAL_FIELDS];
  const extra = keys.filter((k) => !allowed.includes(k)).sort();
  if (extra.length) {
    throw new DenyError('ERR_AUDIT_ENTRY_INVALID', `${label} carries ${extra.join(', ')}, which Table 6 lists no member for`);
  }
  try {
    validateUuid(entry.spawning_agent_id, 'spawning_agent_id');
    validateUuid(entry.child_template_id, 'child_template_id');
    validateScopeSet(entry.requested_scopes, 'requested_scopes');
    validateScopeSet(entry.granted_scopes, 'granted_scopes');
    validateNonce(entry.spawn_nonce, 'spawn_nonce');
    validateTimestamp(entry.timestamp, 'timestamp');
    if ('grant_id' in entry) validateUuid(entry.grant_id, 'grant_id');
  } catch (e) {
    if (!(e instanceof DenyError)) throw e;
    throw new DenyError('ERR_AUDIT_ENTRY_INVALID', `${label}: ${e.detail || e.message}`);
  }
  if (!OUTCOMES.has(entry.outcome)) {
    throw new DenyError('ERR_AUDIT_ENTRY_INVALID', `${label}: outcome must be ALLOWED or DENIED, exactly`);
  }
  const denied = entry.outcome === 'DENIED';
  if (denied && typeof entry.reason !== 'string') {
    throw new DenyError('ERR_AUDIT_ENTRY_INVALID', `${label}: a DENIED entry carries a reason`);
  }
  if (!denied && 'reason' in entry) {
    throw new DenyError('ERR_AUDIT_ENTRY_INVALID', `${label}: an ALLOWED entry carries no reason`);
  }
  if (denied && entry.granted_scopes.length !== 0) {
    throw new DenyError('ERR_AUDIT_ENTRY_INVALID', `${label}: a DENIED entry grants no scopes`);
  }
  if (!denied && entry.granted_scopes.length === 0) {
    throw new DenyError('ERR_AUDIT_ENTRY_INVALID', `${label}: an ALLOWED spawn issued a certificate holding no scopes`);
  }
  return entry;
}

export class AuditChain {
  /** @param {Array<object>} [entries] existing entries, e.g. from a pasted document */
  constructor(entries = []) {
    this.chain = entries;
  }

  get headHash() {
    return this.chain.length ? this.chain[this.chain.length - 1].entry_hash : null;
  }

  get length() {
    return this.chain.length;
  }

  /**
   * Append one entry. `members` is the flat object the entry records — the
   * Table 6 members for a spawn, an `action` and its particulars for anything
   * else. The chain supplies timestamp (unless the members carry one),
   * previous_hash and entry_hash.
   *
   * `now` is injectable so tests are deterministic and the page can stamp every
   * entry in a single verify run with one consistent instant.
   */
  async append(members, now = new Date()) {
    assertFlatObject(members, 'audit entry');
    for (const k of ['previous_hash', 'entry_hash']) {
      if (k in members) throw new DenyError('ERR_SCHEMA_VIOLATION', `an audit entry's ${k} is set by the chain, not the caller`);
    }
    const entry = {
      ...members,
      timestamp: members.timestamp ?? now.toISOString(),
      previous_hash: this.headHash ?? GENESIS_PREVIOUS_HASH,
      entry_hash: null,
    };
    entry.entry_hash = await hashEntry(entry);
    this.chain.push(entry);
    return entry;
  }

  /**
   * Verify integrity. Returns the index of the FIRST broken entry so the UI can
   * name it — "HASH CHAIN: BROKEN, entry 3" is the screenshot; a bare boolean
   * is not.
   *
   * Two distinct failures are checked, because they mean different things:
   *   - a recomputed hash that no longer matches  -> that entry's CONTENT changed
   *   - a previous_hash that no longer matches    -> an entry was inserted/removed
   */
  async verify() {
    if (this.chain.length === 0) return { valid: true, brokenAt: null, reason: null };

    if (this.chain[0].previous_hash !== GENESIS_PREVIOUS_HASH) {
      return { valid: false, brokenAt: 0, reason: 'genesis entry does not start the chain' };
    }

    for (let i = 0; i < this.chain.length; i++) {
      const entry = this.chain[i];

      let expected;
      try { expected = await hashEntry(entry); } catch {
        return { valid: false, brokenAt: i, reason: `entry ${i} cannot be canonicalized` };
      }
      if (entry.entry_hash !== expected) {
        return { valid: false, brokenAt: i, reason: `entry ${i} content was altered` };
      }

      if (i > 0 && entry.previous_hash !== this.chain[i - 1].entry_hash) {
        return { valid: false, brokenAt: i, reason: `entry ${i} does not link to entry ${i - 1}` };
      }
    }

    return { valid: true, brokenAt: null, reason: null };
  }

  /**
   * §10.4 — every entry is a flat object with the three chain members, and an
   * entry that describes a spawn carries exactly Table 6. Structure, before
   * integrity: a chain of well-formed entries can still be broken, and a
   * chain that verifies can still carry an entry the draft does not define.
   */
  assertEntries() {
    this.chain.forEach((entry, i) => {
      const label = `audit entry ${i}`;
      try { assertFlatObject(entry, label); } catch (e) {
        throw new DenyError('ERR_AUDIT_ENTRY_INVALID', e.detail || `${label} is not a flat object`);
      }
      if (typeof entry.timestamp !== 'string' || !HEX64.test(String(entry.previous_hash)) || !HEX64.test(String(entry.entry_hash))) {
        throw new DenyError('ERR_AUDIT_ENTRY_INVALID', `${label} lacks a timestamp, previous_hash or entry_hash in the required form`);
      }
      if ('spawning_agent_id' in entry || 'child_template_id' in entry) assertSpawnEntry(entry, label);
    });
  }

  /** Shape used by the exported JSON's `audit` key. */
  toJSON() {
    return { entries: this.chain.length, head_hash: this.headHash, chain: this.chain };
  }

  /**
   * Rebuild from a pasted document. Structure is checked here; integrity is not
   * assumed — `verify()` is what decides, and a tampered chain must load cleanly
   * so the page can *show* the break rather than refuse to display it.
   */
  static fromJSON(value) {
    if (value == null) return new AuditChain([]);
    const entries = Array.isArray(value) ? value : value.chain;
    if (!Array.isArray(entries)) {
      throw new DenyError('ERR_SCHEMA_VIOLATION', 'audit chain must be an array of entries');
    }
    for (const e of entries) {
      if (e === null || typeof e !== 'object' || Array.isArray(e)) {
        throw new DenyError('ERR_SCHEMA_VIOLATION', 'each audit entry must be an object');
      }
      for (const k of ['timestamp', 'previous_hash', 'entry_hash']) {
        if (!(k in e)) {
          throw new DenyError('ERR_SCHEMA_VIOLATION', `audit entry is missing "${k}"`);
        }
      }
    }
    return new AuditChain(entries);
  }
}
