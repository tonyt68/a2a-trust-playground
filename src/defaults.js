/**
 * The document the page starts from.
 *
 * `Load Defaults` is the most prominent control on the page for a reason: it is
 * the shortest path from landing to watching a refusal. No configuration, no
 * empty state, no minting step to sit through.
 *
 * ── Why the default carries a policy update ────────────────────────────────
 *
 * A bare CA -> A -> B chain exercises six of the nine stages. Stages 4, 5 and 6
 * would report "not a policy update" and pass vacuously, which makes half the
 * dual-signature mechanism — the part §9.3 calls the differentiator — invisible
 * until the visitor constructs one themselves. Nobody does that.
 *
 * So the default ships a complete, valid, dual-signed policy update. Every stage
 * does real work on first load, and four of the eleven sabotage buttons
 * (single-signature, tampered policy, `can_spawn` via update, exceed the
 * template ceiling) have something to break without any setup.
 *
 * ── Nothing is baked. Every visit mints its own keys ───────────────────────
 *
 * Both the keys and the certificates are generated in the visitor's tab on every
 * load. `mint.js` carries the measurement that decided it: the full five-key
 * chain takes ~190ms in Chromium on an M-series Mac, against DESIGN.md's
 * pessimistic "1-3s, show a spinner".
 *
 * At 190ms there was nothing to buy by shipping baked keypairs, and the cost
 * would have been that every visitor shares one published private key. So they
 * are minted instead, and "refresh is the reset" is literally true rather than a
 * figure of speech — no key in this page outlives the tab it was created in.
 *
 * Baking the CERTIFICATES was never viable regardless: they carry a 24-hour
 * validity window (§12.3), so one baked at build time expires the next day and
 * `Reset Certs` would silently stop passing stage 2.
 *
 * (This comment previously described the rejected design as though it had
 * shipped, which would have sent a reader looking for published private keys
 * that do not exist. The build contains no key material at all — the only long
 * base64 blobs in it are the favicon and the shield PNG.)
 */

import { mintChain, newAgentId } from './mint.js';
import { extractIdentityFields, extractPolicyFields, canonicalize } from './canonical.js';
import { signCanonical } from './crypto-sign.js';
import { policyContentHash } from './policy.js';
import { AuditChain } from './audit-chain.js';

/** Scopes used by the default chain. Deliberately two, so a subset is meaningful. */
export const PARENT_SCOPES = Object.freeze(['read:events', 'write:events']);
export const CHILD_SCOPES = Object.freeze(['read:events']);

/**
 * Metadata in the shape `setup_keys.py` emits (§7.1 static fields), with UUID4
 * identities per §6. `authorization_bounds` duplicates three fields because
 * `service.py` reads the nested copy; both are emitted and the pipeline refuses
 * a document where they disagree.
 */
function agentMetadata({ agentId, scopes, canSpawn, maxChildren, parent, now, ttlSeconds = 86400 }) {
  return {
    subject: agentId,
    agent_id: agentId,
    agent_uuid: agentId,
    issuer: 'A2A-Trust-Playground-CA',
    owner: 'owner@example.com',
    org_id: 'playground-org',
    // -02 §7.1: renamed from KeyUsage, which collided with X.509's keyUsage
    // extension once §6.3 began citing that extension normatively.
    permitted_operations: parent ? ['read'] : ['read', 'write', 'spawn', 'delegate'],
    allowed_scopes: [...scopes],
    can_spawn: [...canSpawn],
    max_children: maxChildren,
    policy_ref: `policy-store/${agentId}/current`,
    ttl_seconds: ttlSeconds,
    template_version: '1.0',
    state: 'ACTIVE',
    created_at: now.toISOString(),
    expires_at: new Date(now.getTime() + ttlSeconds * 1000).toISOString(),
    ...(parent ? { parent_agent_id: parent } : {}),
    authorization_bounds: {
      allowed_scopes: [...scopes],
      can_spawn: [...canSpawn],
      max_children: maxChildren,
    },
  };
}

/**
 * A real, hash-linked audit chain for the seeded document.
 *
 * Exported because the `Reset the audit chain` button rebuilds it too, and two
 * copies of this would drift: the seeded chain would verify and the rebuilt one
 * would not, or vice versa, and the difference would only show up as a §16.6
 * failure with no obvious cause.
 *
 * The default previously seeded an EMPTY chain. Stage 9 then passed vacuously,
 * and `Alter an audit entry` had no entry to alter, so it silently did nothing.
 * Same reasoning as the seeded policy update: a stage with nothing to work on is
 * a mechanism the visitor never sees.
 */
export async function seedAuditChain({ parentId, childId, now = new Date() }) {
  const audit = new AuditChain();
  await audit.append({
    action: 'issue_template', decision: 'ALLOWED',
    agent: parentId, detail: 'parent template issued by the registry CA',
  }, new Date(now.getTime() - 120_000));
  await audit.append({
    action: 'spawn_child', decision: 'ALLOWED',
    agent: childId, parent: parentId, detail: 'two-check spawn rule satisfied',
  }, new Date(now.getTime() - 60_000));
  await audit.append({
    action: 'policy_update', decision: 'ALLOWED',
    agent: childId, detail: 'dual-signed policy update accepted, version 2',
  }, new Date(now.getTime() - 30_000));
  return audit;
}

/**
 * Build the seed document: CA, Owner Authority, Policy Authority, Agent A,
 * Agent B, and a dual-signed policy update narrowing B within its ceiling.
 *
 * @param {object} opts
 * @param {Date}   [opts.now]
 * @param {(label: string, i: number, total: number) => void} [opts.onProgress]
 */
export async function buildDefaultDocument({ now = new Date(), onProgress } = {}) {
  const parentId = newAgentId();
  const childId = newAgentId();

  const minted = await mintChain({ agentIds: [parentId, childId], now, onProgress });
  const [parentCert, childCert] = minted.agents;

  const parentMeta = agentMetadata({
    agentId: parentId, scopes: PARENT_SCOPES,
    canSpawn: [childId], maxChildren: 2, parent: null, now,
  });
  const childMeta = agentMetadata({
    agentId: childId, scopes: CHILD_SCOPES,
    canSpawn: [], maxChildren: 0, parent: parentId, now,
  });

  // The policy update narrows the child to a subset of its own ceiling. Valid,
  // and one character away from being refused — editing `read:events` to
  // `admin:all` trips §7.2 rather than §8.3, which is the distinction the two
  // lanes exist to make.
  const policyDoc = {
    subject: childId,
    owner: childMeta.owner,
    org_id: childMeta.org_id,
    scopes: ['read:events'],
    version: 2,
    issued_at: now.toISOString(),
  };

  const ownerKey = minted.authorities.owner.privateKey;
  const paKey = minted.authorities.pa.privateKey;

  const audit = await seedAuditChain({ parentId, childId, now });

  return {
    // ── The chain, walked by stages 1, 2, 3, 7 and 8 ────────────────────────
    chain: [
      {
        role: 'ca',
        cert_pem: minted.ca.cert_pem,
        key_pem: minted.ca.key_pem,
        metadata: { subject: minted.ca.common_name },
      },
      {
        role: 'agent',
        cert_pem: parentCert.cert_pem,
        key_pem: parentCert.key_pem,
        metadata: parentMeta,
      },
      {
        role: 'agent',
        cert_pem: childCert.cert_pem,
        key_pem: childCert.key_pem,
        metadata: childMeta,
        requested_scopes: ['read:events'],
      },
    ],

    // ── The §9.3 signing authorities. Both private keys are handed over on
    //    purpose: the visitor is meant to try signing with one and watch it fail.
    authorities: {
      owner: {
        common_name: minted.authorities.owner.common_name,
        cert_pem: minted.authorities.owner.cert_pem,
        key_pem: minted.authorities.owner.key_pem,
      },
      pa: {
        common_name: minted.authorities.pa.common_name,
        cert_pem: minted.authorities.pa.cert_pem,
        key_pem: minted.authorities.pa.key_pem,
      },
    },

    // ── The policy update, so stages 4-6 do real work on first load ─────────
    policy_update: true,
    policy_doc: policyDoc,
    existing_cert: childMeta,
    // §9.4 storage envelope: siblings of the policy document, never inside it.
    // The reference implementation's field guard rejects unknown keys in
    // policy_doc, and a content hash cannot be part of its own preimage.
    // §9.4 envelope. `version` is NOT here any more — it moved inside the signed
    // policy document (§9.6), which is what closes the replay. What remains on
    // the envelope is the store's current version (context, not payload) and the
    // content hash, which cannot be inside its own preimage.
    current_policy_version: 1,
    policy_content_hash: await policyContentHash(policyDoc),
    owner_sig: await signCanonical(canonicalize(extractIdentityFields(childMeta)), ownerKey),
    pa_sig: await signCanonical(canonicalize(extractPolicyFields(policyDoc)), paKey),

    crl: { revoked: [], disabled: [] },
    audit: audit.toJSON(),
  };
}
