/**
 * Tamper-evident audit chain — §19.7.
 *
 * SHA-256 hash chain: each block commits to the previous block's hash, so
 * altering any entry invalidates that block and every block after it. The
 * verifier reports the break AND names the entry, which is the whole point of
 * the "alter an audit entry" button.
 *
 * §19.7 specifies the preimage: SHA-256 over the canonical form (§11.5, JCS)
 * of the entry's fields including the previous entry's hash, and excluding the
 * entry's own hash field. Four fields, one canonical form, the same
 * `canonicalize` the signatures use. An unspecified preimage is not a detail:
 * two implementations hashing different field sets each read the other's
 * chain as broken.
 */

import { canonicalize } from './canonical.js';
import { DenyError } from './errors.js';
import { bytesToHex } from './encoding.js';

/** The previous_hash of the first block. */
export const GENESIS_PREVIOUS_HASH = 'genesis';

const encoder = new TextEncoder();

/** SHA-256 hex, via Web Crypto — available in browsers and in Node. */
async function sha256Hex(text) {
  const digest = await crypto.subtle.digest('SHA-256', encoder.encode(text));
  return bytesToHex(new Uint8Array(digest));
}

/**
 * The preimage of §19.7: the entry's fields, previous hash included, own hash
 * excluded, in the single canonical form of §11.5.
 */
export function blockPreimage(block) {
  return canonicalize({
    index: block.index,
    timestamp: block.timestamp,
    previous_hash: block.previous_hash,
    event: block.event,
  });
}

export async function hashBlock(block) {
  return sha256Hex(blockPreimage(block));
}

export class AuditChain {
  /** @param {Array<object>} [blocks] existing blocks, e.g. from a pasted document */
  constructor(blocks = []) {
    this.chain = blocks;
  }

  get headHash() {
    return this.chain.length ? this.chain[this.chain.length - 1].hash : null;
  }

  get length() {
    return this.chain.length;
  }

  /**
   * Append one decision to the chain.
   * `now` is injectable so tests are deterministic and the page can stamp every
   * block in a single verify run with one consistent instant.
   */
  async append(event, now = new Date()) {
    const block = {
      index: this.chain.length,
      timestamp: now.toISOString(),
      previous_hash: this.headHash ?? GENESIS_PREVIOUS_HASH,
      event,
      hash: null,
    };
    block.hash = await hashBlock(block);
    this.chain.push(block);
    return block;
  }

  /**
   * Verify integrity. Returns the index of the FIRST broken block so the UI can
   * name it — "HASH CHAIN: BROKEN, entry 3" is the screenshot; a bare boolean
   * is not.
   *
   * Two distinct failures are checked, because they mean different things:
   *   - a recomputed hash that no longer matches  -> that block's CONTENT changed
   *   - a previous_hash that no longer matches    -> a block was inserted/removed
   */
  async verify() {
    if (this.chain.length === 0) return { valid: true, brokenAt: null, reason: null };

    if (this.chain[0].previous_hash !== GENESIS_PREVIOUS_HASH) {
      return { valid: false, brokenAt: 0, reason: 'genesis block does not start the chain' };
    }

    for (let i = 0; i < this.chain.length; i++) {
      const block = this.chain[i];

      if (block.index !== i) {
        return { valid: false, brokenAt: i, reason: `entry ${i} has index ${block.index}` };
      }

      const expected = await hashBlock(block);
      if (block.hash !== expected) {
        return { valid: false, brokenAt: i, reason: `entry ${i} content was altered` };
      }

      if (i > 0 && block.previous_hash !== this.chain[i - 1].hash) {
        return { valid: false, brokenAt: i, reason: `entry ${i} does not link to entry ${i - 1}` };
      }
    }

    return { valid: true, brokenAt: null, reason: null };
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
    const blocks = Array.isArray(value) ? value : value.chain;
    if (!Array.isArray(blocks)) {
      throw new DenyError('ERR_SCHEMA_VIOLATION', 'audit chain must be an array of blocks');
    }
    for (const b of blocks) {
      if (b === null || typeof b !== 'object' || Array.isArray(b)) {
        throw new DenyError('ERR_SCHEMA_VIOLATION', 'each audit entry must be an object');
      }
      for (const k of ['index', 'timestamp', 'previous_hash', 'event', 'hash']) {
        if (!(k in b)) {
          throw new DenyError('ERR_SCHEMA_VIOLATION', `audit entry is missing "${k}"`);
        }
      }
    }
    return new AuditChain(blocks);
  }
}
