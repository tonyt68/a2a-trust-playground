/**
 * The document the page starts from.
 *
 * `Reset Certs` is the most prominent control on the page for a reason: it is
 * the shortest path from landing to watching a refusal. No configuration, no
 * empty state, no minting step to sit through.
 *
 * ── What the seed carries ───────────────────────────────────────────────────
 *
 * A Registry (CA, Owner, Policy Authority), a root orchestrator, one child
 * spawned from it, a dual-signed policy narrowing the child within its own
 * ceiling, an empty CRL, and a three-entry audit chain. Every stage does real
 * work on first load, and the sabotage buttons have something to break.
 *
 * The two agents are in ONE organization, so the default chain needs no
 * cross-organizational grant; the grant path is exercised by the buttons that
 * move the child to a partner organization and then break the grant one way
 * at a time.
 *
 * ── Nothing is baked. Every visit mints its own keys ───────────────────────
 *
 * Keys and certificates are generated in the visitor's tab on every load, in
 * about twenty milliseconds now that the profile is P-256. Nothing in this
 * page outlives the tab it was created in, and the build contains no key
 * material at all.
 */

import { mintChain, newAgentId, OWNER_COMMON_NAME } from './mint.js';
import { signEnvelope } from './crypto-sign.js';
import { AuditChain } from './audit-chain.js';

/** Scopes used by the default chain. Deliberately two, so a subset is meaningful. */
export const PARENT_SCOPES = Object.freeze(['read:events', 'write:events']);
export const CHILD_SCOPES = Object.freeze(['read:events']);
export const ORG_ID = 'playground-org';
/** The seed's TTLs (§9.3: SHOULD NOT exceed one day; §10.3: child SHOULD NOT exceed parent). */
export const PARENT_TTL_SECONDS = 86400;
export const CHILD_TTL_SECONDS = 43200;

/**
 * An Agent Template (§8.2 Table 5) for one agent. `owner` is the Owner
 * certificate's subject, because §9.2 binds the two.
 */
export function templateFor({
  subject, scopes, canSpawn = [], maxChildren = 0, ttlSeconds = CHILD_TTL_SECONDS,
  orgId = ORG_ID, permittedOperations = ['read'], owner = OWNER_COMMON_NAME,
}) {
  return {
    subject,
    owner,
    org_id: orgId,
    permitted_operations: [...permittedOperations],
    allowed_scopes: [...scopes],
    can_spawn: [...canSpawn],
    max_children: maxChildren,
    policy_ref: `policy-store/${subject}/current`,
    ttl_seconds: ttlSeconds,
  };
}

/**
 * A real, hash-linked audit chain for the seeded document. Exported because
 * the `Reset the audit chain` button rebuilds it too, and two copies of this
 * would drift.
 */
export async function seedAuditChain({ parentId, childId, now = new Date() }) {
  const audit = new AuditChain();
  await audit.append({
    action: 'issue_template', decision: 'ALLOWED',
    agent: parentId, detail: 'parent template attested and issued by the Registry',
  }, new Date(now.getTime() - 120_000));
  await audit.append({
    action: 'spawn_child', decision: 'ALLOWED',
    agent: childId, parent: parentId, detail: 'two-check spawn rule satisfied; nonce fresh',
  }, new Date(now.getTime() - 60_000));
  await audit.append({
    action: 'policy_update', decision: 'ALLOWED',
    agent: childId, detail: 'dual-signed policy accepted, version 2',
  }, new Date(now.getTime() - 30_000));
  return audit;
}

/**
 * Build the seed document.
 *
 * @param {object} opts
 * @param {Date}   [opts.now]
 * @param {(label: string, i: number, total: number) => void} [opts.onProgress]
 */
export async function buildDefaultDocument({ now = new Date(), onProgress } = {}) {
  const parentId = newAgentId();
  const childId = newAgentId();

  const parent = templateFor({
    subject: parentId, scopes: PARENT_SCOPES, canSpawn: [childId], maxChildren: 2,
    ttlSeconds: PARENT_TTL_SECONDS, permittedOperations: ['spawn', 'read', 'write'],
  });
  const child = templateFor({
    subject: childId, scopes: CHILD_SCOPES, canSpawn: [], maxChildren: 0,
    ttlSeconds: CHILD_TTL_SECONDS, permittedOperations: ['read'],
  });

  const minted = await mintChain({ parent, child, now, onProgress });
  const [parentCert, childCert] = minted.agents;

  // The policy narrows the child to a subset of its own ceiling. Valid, and
  // one character away from being refused — editing `read:events` to
  // `admin:all` trips §8.3 rather than §10.3, which is the distinction the two
  // lanes exist to make.
  const policyBody = {
    subject: childId,
    owner: child.owner,
    org_id: child.org_id,
    scopes: ['read:events'],
    version: 2,
    issued_at: now.toISOString(),
  };
  const policy = await signEnvelope(policyBody,
    minted.authorities.owner.privateKey, minted.authorities.pa.privateKey, { withHash: true });

  const audit = await seedAuditChain({ parentId, childId, now });

  return {
    // ── The chain. Every bound lives in the certificates; the metadata only
    //    restates identifiers, and every restatement must agree (§7.2, §10.5).
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
        metadata: { agent_id: parentId },
      },
      {
        role: 'agent',
        cert_pem: childCert.cert_pem,
        key_pem: childCert.key_pem,
        metadata: { agent_id: childId, parent_agent_id: parentId },
        requested_scopes: ['read:events'],
      },
    ],

    // ── The §9.2 signing authorities. Both private keys are handed over on
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

    // ── The §3.1 envelope, so stages 4-6 do real work on first load ─────────
    policy,
    // The version the Registry currently holds in force for this subject
    // (§11.4): context the page carries so replay can be demonstrated.
    current_policy_version: 1,

    crl: { revoked: [], disabled: [] },
    audit: audit.toJSON(),
  };
}
