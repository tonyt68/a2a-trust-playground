/**
 * The nine-stage validation pipeline.
 *
 * Ordered; any failure is a DENY and stops the run.
 *
 *   1  agent id format          §7.2
 *   2  X.509 identity           §7, §7.1, §8.2, §10.5, §9.3, §12.1, §12.4
 *   3  revocation               §14
 *   4  dual signature           §3.1, §11.3, §9.2
 *   5  policy field guard       §11.4
 *   6  required fields          §11.4, §11.6
 *   7  spawn rule, policy in force, grants   §10.1, §10.2, §10.5, §13
 *   8  scope containment        §10.3
 *   9  audit entries, chain     §10.4, §19.7
 *
 * ── The stages array IS the decision log ───────────────────────────────────
 *
 * The UI renders `stages`, the JSON export carries `stages`, and both come from
 * this one array — so the log and the export can never disagree.
 *
 * ── Fail-closed means the catch block too ──────────────────────────────────
 *
 * Every stage runs inside a boundary that converts an unexpected throw into
 * ERR_INTERNAL (§15.1). A validator that crashes must DENY, not fall through to
 * a verdict that was initialised optimistically — so `verdict` starts as DENY
 * and is only set to PASS after all nine stages have actually passed.
 *
 * ── Where authority is read from ───────────────────────────────────────────
 *
 * Every bound is read from a certificate extension after that certificate has
 * verified to the anchor (§8.2, §10.5). The chain document contributes the
 * certificates, the identifiers it RESTATES (which must agree with the
 * certificates, §7.2, §10.5), the scopes each agent requests, the revocation
 * state, the audit chain, and the two envelopes. It asserts no authority of
 * its own.
 */

import { DenyError } from './errors.js';
import { validateUuid, assertKnownKeys } from './validate-input.js';
import { validateCertificate, validateAnchor, subjectCN } from './x509.js';
import { validatePolicyUpdate, isPolicyUpdate } from './policy.js';
import {
  assertNotRevoked, assertSpawnPermitted, assertSpawnInPolicy, assertScopeSubset, validateGrant,
} from './bounds.js';
import { AuditChain } from './audit-chain.js';

export const DRAFT = 'draft-tonyai-a2a-trust-03';

/**
 * Things the draft assigns to a party this page is not, named rather than
 * skipped. Everything else in the draft that a relying party does, this page
 * does.
 */
export const NOT_APPLICABLE = Object.freeze([
  { check: 'max_children_enforcement', section: '10.2',
    reason: 'the Registry holds the count and enforces MaxChildren atomically at spawn time — this page\'s Registry does so when it mints, and refuses the sixth step for a template that already has a live certificate; this walk checks the document for consistency with the cap and with the policy in force, and does not present either as enforcement' },
  { check: 'policy_engine_gate', section: '11.7',
    reason: 'step 2 is a policy engine the Policy Authority consults before countersigning; this page verifies the countersignature and the static bounds, not the engine' },
]);

const STAGE_NAMES = Object.freeze({
  1: 'agent_id_format', 2: 'x509_identity', 3: 'revocation',
  4: 'dual_signature', 5: 'policy_field_guard', 6: 'required_fields',
  7: 'spawn_rule', 8: 'scope_subset', 9: 'audit_chain',
});

/** Node and metadata members the chain document may carry. Anything else is refused. */
const KNOWN_NODE_FIELDS = new Set(['role', 'cert_pem', 'key_pem', 'metadata', 'requested_scopes']);
const KNOWN_AGENT_METADATA = new Set(['agent_id', 'parent_agent_id']);
const KNOWN_ANCHOR_METADATA = new Set(['subject']);

/**
 * Record one stage outcome, once. Idempotent by stage number: a DENY always
 * wins over an already-recorded PASS, and an ADVISORY over a PASS, so a
 * refusal or a warning found after an optimistic sub-check is never swallowed.
 */
function record(stages, n, section, result, detail, subject = null) {
  const existing = stages.findIndex((s) => s.n === n);
  if (existing !== -1) {
    const current = stages[existing].result;
    if (result === 'DENY' || (result === 'ADVISORY' && current === 'PASS')) {
      stages[existing] = { n, check: STAGE_NAMES[n], section, result, detail, subject };
    }
    return;
  }
  stages.push({ n, check: STAGE_NAMES[n], section, result, detail, subject });
}

/**
 * Run the pipeline over a document.
 *
 * @param {object} input
 * @param {object} input.document   the editor's contents, already parsed and
 *                                  through the input-validation contract
 * @param {Date}   [input.now]      injectable clock
 * @param {string} [input.version]  build stamp for the export
 * @returns {Promise<object>} the export document; never throws
 */
export async function runPipeline({ document, now = new Date(), version = '1.0.0+dev' }) {
  const stages = [];
  // Pessimistic by construction: only an unbroken run through stage 9 sets PASS.
  let verdict = 'DENY';
  let failure = null;
  /** SHOULD-level findings (§10.3 child TTL). Reported, never a DENY. */
  const advisories = [];
  const crlPresent = document?.crl !== undefined && document?.crl !== null;
  const auditMissing = document?.audit === undefined || document?.audit === null;
  // The refusal for a missing audit log is raised INSIDE the walk, not here:
  // `runPipeline` never throws, it returns a DENY, and the audit chain is what
  // records that refusal.
  const audit = AuditChain.fromJSON(auditMissing ? { chain: [] } : document.audit);
  /** Sub-checks inside the policy group report here as they complete. */
  const completed = [];
  /**
   * The per-subject walk: anchor, each agent, the grant, the delegation, the
   * policy, the audit. `stages` answers "which of the nine checks ran"; `walk`
   * answers "how far down the chain did we get before something refused".
   */
  const walk = [];
  const step = (subject, result, detail) => {
    const at = walk.findIndex((w) => w.subject === subject);
    if (at !== -1) { if (result === 'DENY') walk[at] = { subject, result, detail }; return; }
    walk.push({ subject, result, detail });
  };

  try {
    const chain = Array.isArray(document?.chain) ? document.chain : null;
    if (!chain || chain.length === 0) {
      throw new DenyError('ERR_SCHEMA_VIOLATION', 'document carries no chain');
    }
    for (const node of chain) {
      if (node === null || typeof node !== 'object' || Array.isArray(node)) {
        throw new DenyError('ERR_SCHEMA_VIOLATION', 'every chain node must be an object');
      }
      assertKnownKeys(node, KNOWN_NODE_FIELDS, 'a chain node');
    }

    // EXACTLY one trust anchor. A chain with an ambiguous root has no answer to
    // "who vouched for this", so it is refused rather than resolved.
    const anchors = chain.filter((n) => n.role === 'ca');
    if (anchors.length === 0 || !anchors[0]?.cert_pem) {
      throw new DenyError('ERR_CHAIN_INVALID', 'document carries no trust anchor');
    }
    if (anchors.length > 1) {
      throw new DenyError('ERR_CHAIN_INVALID',
        `document carries ${anchors.length} trust anchors — exactly one is permitted`);
    }
    const anchor = anchors[0];
    assertKnownKeys(anchor.metadata, KNOWN_ANCHOR_METADATA, 'the trust anchor metadata');

    const agents = chain.filter((n) => n.role === 'agent');
    if (agents.length === 0) {
      throw new DenyError('ERR_SCHEMA_VIOLATION', 'document carries no agent nodes');
    }
    // Unknown roles are refused rather than ignored — silently skipping a node
    // means a chain can carry entries nothing ever validates.
    const strays = chain.filter((n) => n?.role !== 'ca' && n?.role !== 'agent');
    if (strays.length) {
      throw new DenyError('ERR_SCHEMA_VIOLATION',
        `chain contains ${strays.length} node(s) with an unrecognised role`);
    }
    for (const node of agents) assertKnownKeys(node.metadata, KNOWN_AGENT_METADATA, 'agent metadata');

    // §12.1 — one identity, one certificate. Two nodes naming one subject are
    // refused BOTH, before either is validated.
    const ids = agents.map((n) => n?.metadata?.agent_id);
    const duplicated = [...new Set(ids.filter((id, i) => id !== undefined && ids.indexOf(id) !== i))];
    if (duplicated.length) {
      const e = new DenyError('ERR_DUPLICATE_SUBJECT',
        `the chain presents more than one certificate for ${duplicated.map((d) => String(d).slice(0, 8)).join(', ')}… — both are refused`);
      // Attributed to the identity that was doubled, so the walk names it.
      const first = agents.find((n) => n?.metadata?.agent_id === duplicated[0]);
      e.subject = first?.metadata?.parent_agent_id ? 'CHILD AGENT' : 'PARENT AGENT';
      step(e.subject, 'DENY', e.detail);
      throw e;
    }

    // §15.1 Fail Closed. An EMPTY crl is fine and means "nothing is revoked".
    // A MISSING one means "we do not know", and the two must not be the same
    // value. Same for the audit chain: absent is not empty.
    if (auditMissing) {
      throw new DenyError('ERR_SCHEMA_VIOLATION',
        'document carries no audit chain — integrity cannot be established (§19.7)');
    }
    if (!crlPresent) {
      throw new DenyError('ERR_SCHEMA_VIOLATION',
        'document carries no crl — revocation status cannot be determined (§15.1)');
    }
    const crl = document.crl;

    // ── The anchor first: everything else is measured against it ───────────
    const caCert = await validateAnchor(anchor.cert_pem, { now });
    // §14 — a CRL naming the ANCHOR voids everything beneath it, so it is
    // checked before any agent. Matched against the CERTIFICATE's own subject
    // CN, never against the document's unverified restatement of it (§7.2) —
    // an attacker cannot dodge a CRL entry by editing `metadata.subject`.
    const anchorSubject = subjectCN(caCert);
    const revokedList = Array.isArray(crl.revoked) ? crl.revoked : [];
    const disabledList = Array.isArray(crl.disabled) ? crl.disabled : [];
    if (anchorSubject && (revokedList.includes(anchorSubject) || disabledList.includes(anchorSubject))) {
      throw new DenyError('ERR_AGENT_REVOKED',
        'the trust anchor is revoked — every certificate beneath it is void (§14)');
    }
    record(stages, 2, '7', 'PASS', 'trust anchor is a self-signed CA: CA:TRUE, keyCertSign, P-256 or stronger', 'TRUST ANCHOR');
    step('TRUST ANCHOR', 'PASS', 'self-signed, in no trust store, name-constrained');

    /** subject -> { template, spawn, notAfter, node, label } — every bound comes from here. */
    const byId = new Map();

    /**
     * Walk the chain SUBJECT BY SUBJECT: each agent's checks run to completion
     * before the next, so a refusal names WHOSE certificate failed.
     */
    const nodeChecks = async (node, label) => {
      const meta = node.metadata ?? {};
      validateUuid(meta.agent_id, 'agent_id');
      const claimedParent = meta.parent_agent_id ?? null;
      if (claimedParent !== null) validateUuid(claimedParent, 'parent_agent_id');
      record(stages, 1, '7.2', 'PASS', `${label}: agent_id is a well-formed RFC 9562 UUID`, label);

      const r = await validateCertificate({
        certPem: node.cert_pem, caCert, agentId: meta.agent_id, now, role: 'agent',
      });

      // §10.5 — a child's certificate carries the Agent Spawn extension and a
      // root's does not; the parent the chain names must be the parent the CA
      // attested. Every restatement must agree (§7.2), so the document's
      // parent_agent_id is checked against the certificate's, never trusted
      // over it.
      if (!r.spawn && claimedParent !== null) {
        throw new DenyError('ERR_SPAWN_EXT_INVALID',
          `${label}: the chain names a parent but the certificate carries no Agent Spawn extension`);
      }
      if (r.spawn && claimedParent === null) {
        throw new DenyError('ERR_PARENT_MISMATCH',
          `${label}: the certificate carries an Agent Spawn extension but the chain presents this agent as a root`);
      }
      if (r.spawn && r.spawn.parent_agent_id !== claimedParent) {
        throw new DenyError('ERR_PARENT_MISMATCH',
          `${label}: the certificate attests parent ${r.spawn.parent_agent_id.slice(0, 8)}…, the chain names ${claimedParent.slice(0, 8)}…`);
      }
      byId.set(meta.agent_id, {
        template: r.template, spawn: r.spawn, notAfter: r.cert.notAfter.value, node, label,
      });
      record(stages, 2, '7', 'PASS',
        `${label}: certificate verifies to the anchor; template${r.spawn ? ' and spawn provenance' : ''} attested by the CA`, label);

      assertNotRevoked({ agentId: meta.agent_id, crl });
      record(stages, 3, '14', 'PASS', `${label}: not revoked, not DISABLED at the Registry`, label);
    };

    // Roots first, then children, so a child's parent is known when it is reached.
    const ordered = [...agents].sort((a, b) =>
      (a.metadata?.parent_agent_id ? 1 : 0) - (b.metadata?.parent_agent_id ? 1 : 0));
    let childN = 0;
    for (const node of ordered) {
      const isChild = Boolean(node.metadata?.parent_agent_id);
      const label = isChild ? (++childN > 1 ? `CHILD AGENT ${childN}` : 'CHILD AGENT') : 'PARENT AGENT';
      try {
        await nodeChecks(node, label);
        const t = byId.get(node.metadata.agent_id).template;
        step(label, 'PASS',
          `identity, certificate, template and standing all check out · ${t.allowed_scopes.join(', ')}`);
      } catch (e) {
        if (e instanceof DenyError) { e.subject = label; step(label, 'DENY', e.detail || e.title); }
        throw e;
      }
    }

    // §10.5 — every attested parent is in the chain, and no nonce is issued twice.
    const children = ordered.filter((n) => byId.get(n.metadata.agent_id).spawn);
    for (const node of children) {
      const { spawn, label } = byId.get(node.metadata.agent_id);
      if (!byId.has(spawn.parent_agent_id)) {
        const e = new DenyError('ERR_PARENT_MISMATCH',
          `${label}: the certificate names a parent that is not in the chain`);
        e.subject = label; step(label, 'DENY', e.detail); throw e;
      }
    }
    const nonces = children.map((n) => byId.get(n.metadata.agent_id).spawn.spawn_nonce);
    if (new Set(nonces).size !== nonces.length) {
      // §10.5 — a consistency check on the document: the Registry accepts each
      // nonce once; a relying party holding one chain cannot observe another.
      const e = new DenyError('ERR_NONCE_REUSED', 'two certificates in the chain carry the same spawn_nonce');
      e.subject = 'CHILD AGENT'; step('CHILD AGENT', 'DENY', e.detail); throw e;
    }

    // ── Authorities: validated to the anchor before any signature is trusted (§9.2)
    const authorities = document.authorities ?? {};
    const policiesInForce = document.policies ?? [];
    if (!Array.isArray(policiesInForce)) {
      throw new DenyError('ERR_SCHEMA_VIOLATION', 'policies must be an array of §3.1 envelopes');
    }
    const needAuthorities = isPolicyUpdate(document)
      || (document.grant !== undefined && document.grant !== null)
      || policiesInForce.length > 0;
    // Attributed to whichever walk step actually needs the authorities: the
    // grant if one is present, the policy update otherwise — so a refusal here
    // still produces a DENY row in `walk`, the way every other block's does.
    const authoritySubject = (document.grant !== undefined && document.grant !== null)
      ? 'CROSS-ORG GRANT' : 'POLICY UPDATE';
    if (needAuthorities) {
      try {
        if (!authorities.owner?.cert_pem || !authorities.pa?.cert_pem) {
          throw new DenyError('ERR_AUTHORITY_CHAIN',
            'a signed envelope requires both the Owner and Policy Authority certificates');
        }
        for (const [role, node] of [['Owner', authorities.owner], ['Policy Authority', authorities.pa]]) {
          try {
            await validateCertificate({
              certPem: node.cert_pem, caCert, agentId: node.common_name, now, role: 'authority',
            });
          } catch (e) {
            throw new DenyError('ERR_AUTHORITY_CHAIN', `${role} certificate: ${e.detail || e.message}`);
          }
        }
      } catch (e) {
        if (e instanceof DenyError) { e.subject = authoritySubject; step(authoritySubject, 'DENY', e.detail || e.title); }
        throw e;
      }
    }

    // ── Cross-organizational grant (§13) ──────────────────────────────────
    /** childId -> the grant's allowed_scopes, for the request check in stage 8 */
    const grantScopes = new Map();
    const crossOrg = children.filter((n) => {
      const c = byId.get(n.metadata.agent_id);
      return c.template.org_id !== byId.get(c.spawn.parent_agent_id).template.org_id;
    });
    try {
      if (crossOrg.length) {
        if (document.grant === undefined || document.grant === null) {
          const c = byId.get(crossOrg[0].metadata.agent_id);
          const p = byId.get(c.spawn.parent_agent_id);
          throw new DenyError('ERR_GRANT_MISSING',
            `${c.template.org_id} has issued no grant to ${p.template.org_id} — no implicit trust exists between organizations`);
        }
        for (const node of crossOrg) {
          const c = byId.get(node.metadata.agent_id);
          const p = byId.get(c.spawn.parent_agent_id);
          const underGrant = crossOrg.filter((n) => byId.get(n.metadata.agent_id).template.org_id === c.template.org_id).length;
          const body = await validateGrant({
            grant: document.grant, childTemplate: c.template, parentTemplate: p.template,
            ownerCertPem: authorities.owner.cert_pem, paCertPem: authorities.pa.cert_pem,
            now, spawnsUnderGrant: underGrant,
          });
          // §10.5 — a cross-organizational spawn records the grant it was
          // issued under, and it must be THIS grant: that member is what lets
          // §13.4 revoke the certificates a revoked grant produced.
          if (!c.spawn.grant_id) {
            throw new DenyError('ERR_GRANT_ID_MISMATCH',
              `${c.label}: spawned across organizations, but the certificate names no grant`);
          }
          if (c.spawn.grant_id !== body.grant_id) {
            throw new DenyError('ERR_GRANT_INVALID',
              `the certificate was issued under grant ${c.spawn.grant_id.slice(0, 8)}…, not this one (${body.grant_id.slice(0, 8)}…)`);
          }
          grantScopes.set(node.metadata.agent_id, body.allowed_scopes);
        }
        const g = document.grant.body;
        step('CROSS-ORG GRANT', 'PASS',
          `${g.grantor} → ${g.grantee}: signed by the grantor's Owner and Policy Authority, current, within the template; ${crossOrg.length} of max_spawns ${g.max_spawns}`);
      } else if (document.grant !== undefined && document.grant !== null) {
        // A grant nothing uses is still checked: an envelope that survives
        // validation reads as meaningful to whoever handles the document next.
        // Paired against the agent ITS OWN BODY NAMES, when that agent is
        // present in this chain — pairing it with an ARBITRARY agent instead
        // would require the grant to address whichever unrelated agent was
        // picked, refusing a grant that is simply not the one behind today's
        // cross-org spawn (e.g. a child later re-parented into one
        // organization, leaving its old grant in the document unused but
        // still meaningfully checkable against the agent it actually names).
        const named = [...byId.values()].find((v) => v.template.subject === document.grant.body?.template);
        const c = named ?? (byId.get(children[0]?.metadata.agent_id) ?? [...byId.values()][0]);
        const p = c.spawn ? byId.get(c.spawn.parent_agent_id) : c;
        await validateGrant({
          grant: document.grant, childTemplate: c.template, parentTemplate: p.template,
          ownerCertPem: authorities.owner.cert_pem, paCertPem: authorities.pa.cert_pem,
          now, spawnsUnderGrant: 0,
        });
        step('CROSS-ORG GRANT', 'PASS', 'grant verifies; no spawn in this chain crosses an organization, so it is unused');
      } else {
        step('CROSS-ORG GRANT', 'PASS', 'not needed — parent and child are in one organization');
      }
    } catch (e) {
      if (e instanceof DenyError) { e.subject = 'CROSS-ORG GRANT'; step('CROSS-ORG GRANT', 'DENY', e.detail || e.title); }
      throw e;
    }

    // ── Stages 4-6 — the policy envelope (§3.1, §11) ──────────────────────
    const templates = new Map([...byId].map(([id, v]) => [id, { template: v.template, notAfter: v.notAfter }]));
    if (isPolicyUpdate(document)) {
      let result;
      try {
        result = await validatePolicyUpdate({
          document, templates, now,
          ownerCertPem: authorities.owner.cert_pem,
          paCertPem: authorities.pa.cert_pem,
          onStage: (n, detail) => completed.push([n, detail]),
        });
      } catch (e) {
        if (e instanceof DenyError) { e.subject = 'POLICY UPDATE'; step('POLICY UPDATE', 'DENY', e.detail || e.title); }
        throw e;
      }
      for (const [n, detail] of completed) record(stages, n, n === 4 ? '11.3' : '11.4', 'PASS', detail);
      if (!completed.some(([n]) => n === 4)) record(stages, 4, '11.3', 'PASS', result.detail);
      step('POLICY UPDATE', 'PASS', result.detail);
      stages.sort((a, b) => a.n - b.n);
    } else {
      // Not a policy update. Recorded as PASS with the reason, never omitted —
      // a stage that silently vanishes from the log is indistinguishable from
      // one that was forgotten.
      const detail = 'not a policy update — no envelope to verify';
      step('POLICY UPDATE', 'PASS', detail);
      record(stages, 4, '11.3', 'PASS', detail);
      record(stages, 5, '11.4', 'PASS', detail);
      record(stages, 6, '11.4', 'PASS', detail);
    }

    // ── Stage 7 — the two-check spawn rule, from the PARENT's certificate ───
    try {
    // The policies the document says the Registry holds in force (§11.4):
    // each a §3.1 envelope, both signatures verified, bounded by the template
    // of the subject it governs. What §10.2 step 3 was evaluated against.
    /** subject -> the in-force policy body */
    const inForce = new Map();
    for (const envelope of policiesInForce) {
      const r = await validatePolicyUpdate({
        document: { policy: envelope }, templates, now,
        ownerCertPem: authorities.owner.cert_pem, paCertPem: authorities.pa.cert_pem,
      });
      if (inForce.has(r.subject)) {
        throw new DenyError('ERR_SCHEMA_VIOLATION', `two policies in force for ${r.subject.slice(0, 8)}… — a subject has one`);
      }
      inForce.set(r.subject, envelope.body);
    }
    for (const node of children) {
      const c = byId.get(node.metadata.agent_id);
      const parent = byId.get(c.spawn.parent_agent_id);
      const parentT = parent.template;
      const siblings = children.filter((n) =>
        byId.get(n.metadata.agent_id).spawn.parent_agent_id === c.spawn.parent_agent_id
        && n.metadata.agent_id !== node.metadata.agent_id).length;
      assertSpawnPermitted({ parentTemplate: parentT, childId: node.metadata.agent_id, siblings });
      // §10.2 step 3 — consistency with the policy in force for the parent.
      assertSpawnInPolicy({
        policy: inForce.get(c.spawn.parent_agent_id) ?? null,
        childId: node.metadata.agent_id, parentId: c.spawn.parent_agent_id,
      });
      // §10.5 — grant_id is present exactly when the spawn crossed organizations.
      if (c.template.org_id === parentT.org_id && c.spawn.grant_id) {
        throw new DenyError('ERR_GRANT_ID_MISMATCH',
          `${c.label}: the certificate names a grant, but parent and child are in one organization`);
      }
    }
    record(stages, 7, '10.1', 'PASS', children.length
      ? 'DELEGATION: parent holds spawn, child is in CanSpawn and in the policy in force; child count is consistent with MaxChildren (the Registry enforces the cap)'
      : 'no spawn in this chain', 'DELEGATION');

    // ── Stage 8 — scope containment (§10.3) ─────────────────────────────────
    for (const node of children) {
      const c = byId.get(node.metadata.agent_id);
      const parentT = byId.get(c.spawn.parent_agent_id).template;
      assertScopeSubset(c.template.allowed_scopes, parentT.allowed_scopes, { label: 'child' });
      // SHOULD, not MUST: reported, never refused.
      if (c.template.ttl_seconds > parentT.ttl_seconds) {
        const detail = `${c.label}: ttl_seconds ${c.template.ttl_seconds} exceeds its parent's ${parentT.ttl_seconds} — a delegation that outlives its delegator (SHOULD NOT)`;
        advisories.push({ section: '10.3', subject: c.label, detail });
        record(stages, 8, '10.3', 'ADVISORY', detail, 'DELEGATION');
      }
    }
    for (const node of agents) {
      if (node.requested_scopes === undefined) continue;
      if (!Array.isArray(node.requested_scopes)) {
        throw new DenyError('ERR_SCHEMA_VIOLATION', 'requested_scopes must be an array of scopes');
      }
      const a = byId.get(node.metadata.agent_id);
      assertScopeSubset(node.requested_scopes, a.template.allowed_scopes, { label: 'requested' });
      if (grantScopes.has(node.metadata.agent_id)) {
        assertScopeSubset(node.requested_scopes, grantScopes.get(node.metadata.agent_id), { label: 'requested (under the grant)' });
      }
    }
    record(stages, 8, '10.3', 'PASS', children.length
      ? 'DELEGATION: child scopes are a subset of the parent\'s; requested scopes are within bounds'
      : 'no delegation to check; requested scopes are within bounds', 'DELEGATION');
    } catch (e) {
      if (e instanceof DenyError) { e.subject = 'DELEGATION'; step('DELEGATION', 'DENY', e.detail || e.title); }
      throw e;
    }
    step('DELEGATION', advisories.length ? 'ADVISORY' : 'PASS', advisories.length
      ? advisories[0].detail
      : children.length ? 'child scopes are a subset of the parent, spawn rule and cap satisfied' : 'no delegation in this chain');

    // ── Stage 9 — the audit entries (§10.4) and audit integrity (§19.7) ────
    try { audit.assertEntries(); } catch (e) {
      if (e instanceof DenyError) { e.subject = 'AUDIT CHAIN'; step('AUDIT CHAIN', 'DENY', e.detail); }
      throw e;
    }
    const integrity = await audit.verify();
    if (!integrity.valid) {
      const e = new DenyError('ERR_AUDIT_CHAIN_BROKEN', integrity.reason ?? 'hash chain is broken');
      e.subject = 'AUDIT CHAIN'; step('AUDIT CHAIN', 'DENY', e.detail); throw e;
    }
    await audit.append({ action: 'verify_chain', outcome: 'ALLOWED',
      agents: agents.map((n) => n.metadata.agent_id) }, now);
    record(stages, 9, '19.7', 'PASS', `hash chain valid across ${audit.length} entr(ies)`);
    step('AUDIT CHAIN', 'PASS', `intact across ${audit.length} entr${audit.length === 1 ? 'y' : 'ies'}`);

    verdict = 'PASS';
  } catch (error) {
    const deny = error instanceof DenyError
      ? error
      // §15.1 — anything unexpected is a DENY that says so, not a crash and not
      // a pass. The original message is deliberately not surfaced: it can echo
      // input, and this page renders everything it reports.
      : new DenyError('ERR_INTERNAL', 'validation could not be completed');
    failure = deny;

    const n = deny.stage > 0 ? deny.stage : (stages.length + 1);
    for (const [sn, detail] of completed) {
      if (sn < n) record(stages, sn, sn === 4 ? '11.3' : '11.4', 'PASS', detail);
    }
    record(stages, n, deny.section, 'DENY', deny.detail || deny.title, deny.subject ?? null);
    stages.sort((a, b) => a.n - b.n);

    // The refusal is itself an auditable event (§10.4). Read the chain from
    // `document`, not from a binding scoped inside the try block.
    try {
      const covered = (document?.chain ?? [])
        .filter((n) => n?.role === 'agent')
        .map((n) => n.metadata?.agent_id)
        .filter(Boolean);
      await audit.append({
        action: 'verify_chain', outcome: 'DENIED', reason: deny.code,
        ...(covered.length ? { agents: covered } : {}),
      }, now);
    } catch { /* an audit failure must not mask the original refusal */ }
  }

  stages.sort((a, b) => a.n - b.n);

  // Stable key order, no undefined, verdict never absent.
  return {
    playground_version: version,
    draft: DRAFT,
    generated_at: now.toISOString(),
    demo_only: true,
    verdict,
    walk,
    advisories,
    error_code: failure?.code ?? null,
    draft_section: failure?.section ?? null,
    banner: failure ? failure.banner : 'DELEGATION AUTHORIZED',
    stages,
    not_applicable: NOT_APPLICABLE.map((s) => ({ ...s, result: 'NOT-APPLICABLE' })),
    chain: document?.chain ?? [],
    authorities: document?.authorities ?? {},
    crl: document?.crl ?? { revoked: [], disabled: [] },
    audit: {
      entries: audit.length,
      head_hash: audit.headHash,
      chain_valid: verdict === 'PASS' || failure?.code !== 'ERR_AUDIT_CHAIN_BROKEN',
      chain: audit.chain,
    },
  };
}
