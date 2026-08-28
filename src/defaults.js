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
 * ── Keys are baked, certificates are not ───────────────────────────────────
 *
 * RSA-2048 keygen is the slow part — roughly 1-3s per key in a browser, and this
 * chain needs five. Signing with an existing key is milliseconds.
 *
 * Baking the CERTIFICATES instead would be worse than slow: they carry a 24-hour
 * validity window (§12.3), so a certificate baked at build time expires the day
 * after and `Load Defaults` silently stops passing stage 2. Baking the KEYS and
 * issuing certificates at load time gives an instant default that is always
 * inside its validity window.
 *
 * The keys are demo material by construction — the CA is in no trust store and
 * the name constraint makes it incapable of issuing anything that does not say
 * DEMO ONLY — so publishing them costs nothing. `Mint Fresh` generates new ones
 * for anyone who wants to watch keys being created.
 */

import { mintChain, newAgentId } from './mint.js';
import { extractIdentityFields, extractPolicyFields, canonicalize } from './canonical.js';
import { signCanonical } from './crypto-sign.js';
import { policyContentHash } from './policy.js';

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
    audit: { chain: [] },
  };
}
