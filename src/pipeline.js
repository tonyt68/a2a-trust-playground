/**
 * The nine-stage validation pipeline.
 *
 * Ordered; any failure is a DENY and stops the run. This mirrors
 * `service.py`'s write_event chain, minus the two stages that require a server
 * (replay prevention §16.2 and Cedar policy evaluation §9) — both are named on
 * the page under Stated Limits rather than quietly counted as done.
 *
 *   1  agent id format          implementation hardening
 *   2  X.509 identity + state   §6, §10.4
 *   3  revocation + TTL         §12
 *   4  dual signature           §9.3
 *   5  policy field guard       §9.3, §7.1
 *   6  required fields          §9.3
 *   7  authorization bounds     §7, §8.1
 *   8  scope containment        §8.3
 *   9  audit chain append       §16.6
 *
 * ── The stages array IS the decision log ───────────────────────────────────
 *
 * The UI renders `stages`, the JSON export carries `stages`, and both come from
 * this one array — so the log and the export can never disagree. DESIGN.md is
 * explicit that the log matters more than the diagram; this is why it is data
 * rather than console output.
 *
 * ── Fail-closed means the catch block too ──────────────────────────────────
 *
 * Every stage runs inside a boundary that converts an unexpected throw into
 * ERR_INTERNAL (§13.1). A validator that crashes must DENY, not fall through to
 * a verdict that was initialised optimistically — so `verdict` starts as DENY
 * and is only set to PASS after all nine stages have actually passed.
 */

import { DenyError } from './errors.js';
import { validateUuid4, validateTimestamp } from './validate-input.js';
import { validateCertificate, parseCertificate } from './x509.js';
import { validatePolicyUpdate, isPolicyUpdate } from './policy.js';
import {
  assertNotRevoked, assertActive, parseAuthorizationBounds,
  assertMaySpawn, assertScopeSubset,
} from './bounds.js';
import { AuditChain } from './audit-chain.js';

export const DRAFT = 'draft-tonyai-a2a-trust-02';

/** Stages the playground does not implement, named rather than skipped (AC-3). */
export const NOT_APPLICABLE = Object.freeze([
  { check: 'replay_prevention', section: '16.2',
    reason: 'requires a nonce store and a request lifecycle; a stateless page has neither' },
  { check: 'cedar_policy_evaluation', section: '9',
    reason: 'requires a policy engine; the playground enforces static bounds only' },
]);

const STAGE_NAMES = Object.freeze({
  1: 'agent_id_format', 2: 'x509_identity', 3: 'revocation',
  4: 'dual_signature', 5: 'policy_field_guard', 6: 'required_fields',
  7: 'authorization_bounds', 8: 'scope_subset', 9: 'audit_chain',
});

/**
 * Record one stage outcome, once.
 *
 * Idempotent by stage number: the success path and the failure path both replay
 * the sub-stages that completed inside the §9.3 group, and a stage recorded
 * twice would show up twice in the decision log — which is the log lying about
 * how many checks ran.
 */
function record(stages, n, section, result, detail, subject = null) {
  const existing = stages.findIndex((s) => s.n === n);
  if (existing !== -1) {
    // A DENY always wins over an already-recorded PASS for the same stage: the
    // sub-checks inside the §9.3 group report progress optimistically, and one
    // of them failing afterwards must not be swallowed by the earlier row.
    // Dropping it would turn a refusal into a silent pass — the exact failure
    // mode fail-closed exists to prevent.
    if (result === 'DENY') stages[existing] = { n, check: STAGE_NAMES[n], section, result, detail, subject };
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
  // Same fail-closed reasoning as the CRL below: an absent audit log is not an
  // empty one. §16.6 requires tamper-evidence, and a document that simply omits
  // the chain has no evidence to be tampered with.
  const crlPresent = document?.crl !== undefined && document?.crl !== null;
  const auditMissing = document?.audit === undefined || document?.audit === null;
  // The refusal for a missing audit log is raised INSIDE the walk, not here:
  // `runPipeline` never throws, it returns a DENY, and the audit chain is what
  // records that refusal. So the chain is constructed either way and the
  // document's own absence of one is reported through the normal path.
  const audit = AuditChain.fromJSON(auditMissing ? { chain: [] } : document.audit);
  /** Sub-checks inside the §9.3 group report here as they complete. */
  const completed = [];
  /**
   * The per-subject walk: anchor, then each agent, then the relationships
   * between them. `stages` answers "which of the nine checks ran"; `walk`
   * answers "how far down the chain did we get before something refused",
   * which is what someone who just edited the child needs.
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

    // EXACTLY one trust anchor. `find` silently takes the first and ignores the
    // rest, so a document with two CAs validated cleanly against whichever
    // happened to be first — a reader of that JSON could not tell which anchor
    // the result depended on. A chain with an ambiguous root has no answer to
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

    const agents = chain.filter((n) => n.role === 'agent');
    if (agents.length === 0) {
      throw new DenyError('ERR_SCHEMA_VIOLATION', 'document carries no agent nodes');
    }

    // One entry per identity. Duplicates let the same agent be counted twice
    // when tallying siblings against max_children, and make "which node is this
    // decision about" unanswerable.
    const ids = agents.map((n) => n?.metadata?.agent_id);
    const duplicated = ids.filter((id, i) => id !== undefined && ids.indexOf(id) !== i);
    if (duplicated.length) {
      throw new DenyError('ERR_SCHEMA_VIOLATION',
        `chain contains the same agent more than once: ${[...new Set(duplicated)].join(', ')}`);
    }

    // Unknown roles are refused rather than ignored — silently skipping a node
    // means a chain can carry entries nothing ever validates.
    const strays = chain.filter((n) => n?.role !== 'ca' && n?.role !== 'agent');
    if (strays.length) {
      throw new DenyError('ERR_SCHEMA_VIOLATION',
        `chain contains ${strays.length} node(s) with an unrecognised role`);
    }

    /**
     * Walk the chain SUBJECT BY SUBJECT: the anchor, then each agent in order,
     * running that node's checks to completion before moving on.
     *
     * The alternative — sweep every node through stage 1, then every node
     * through stage 2 — is what this used to do, and it answers the wrong
     * question. Break the child's certificate and it reported "IDENTITY
     * refused" without saying whose. Walking per subject reports
     * "anchor ok, parent ok, CHILD refused", which is what someone who just
     * edited the child actually needs to know.
     *
     * It is also the closer reading of the reference implementation:
     * service.py validates ONE agent through the full chain of stages per
     * request, not all agents through one stage at a time.
     */
    const nodeChecks = async (node, label) => {
      const meta = node.metadata;
      validateUuid4(meta?.agent_id, 'agent_id');
      // §7.1 carries the identity THREE times — `subject`, `agent_id`,
      // `agent_uuid`. All three are in the owner_sig projection, so a mismatch
      // inside `existing_cert` breaks the signature. Nothing signs the CHAIN
      // copy, so a mismatch there was silent: `subject` could name a different
      // agent than the certificate was issued to and the document validated.
      // Three names for one identity means all three must agree, or the
      // document does not have one identity.
      for (const field of ['agent_uuid', 'subject']) {
        if (meta[field] !== meta.agent_id) {
          throw new DenyError('ERR_SCHEMA_VIOLATION',
            `${field} and agent_id disagree — an agent has exactly one identity`);
        }
      }
      // §9.2 matches policy submitters against the template's owner with `===`.
      // A non-string owner cannot match anything, so it would have failed
      // closed — but only by accident, and only on the policy path. A typed
      // field is checked because it is typed, not because something downstream
      // happens to survive it.
      if (typeof meta.owner !== 'string' || meta.owner.length === 0) {
        throw new DenyError('ERR_SCHEMA_VIOLATION', 'owner must be a non-empty string');
      }
      if (typeof meta.org_id !== 'string' || meta.org_id.length === 0) {
        throw new DenyError('ERR_SCHEMA_VIOLATION', 'org_id must be a non-empty string');
      }
      if (meta.created_at) {
        validateTimestamp(meta.created_at, 'created_at');
        // A certificate that has not been issued yet cannot be relied on. X.509
        // notBefore covers the certificate; nothing covered the METADATA's own
        // claim, so an agent could assert it was created in 2099 and still
        // validate — the two would simply disagree, unnoticed.
        if (new Date(meta.created_at).getTime() > now.getTime()) {
          throw new DenyError('ERR_TIMESTAMP_FORMAT', 'created_at is in the future');
        }
      }
      if (meta.expires_at) validateTimestamp(meta.expires_at, 'expires_at');
      record(stages, 1, null, 'PASS', `${label}: agent_id is a well-formed UUID4`, label);

      await validateCertificate({
        certPem: node.cert_pem, caPem: anchor.cert_pem, agentId: meta.agent_id, now,
      });
      assertActive(meta);
      record(stages, 2, '6', 'PASS',
        `${label}: certificate verifies to the anchor, state is ${meta.state}`, label);

      assertNotRevoked({ agentId: meta.agent_id, crl, metadata: meta, now });
      record(stages, 3, '12', 'PASS', `${label}: not revoked, not disabled, TTL current`, label);

      // §9.2 scopes authority to "the organization that signed the template",
      // and §11 puts cross-organisational trust behind federation this document
      // has no way to express. A child declaring a different org_id than its
      // parent is therefore claiming a delegation the draft does not define —
      // and it validated cleanly, because org_id was only ever compared on the
      // policy path, never between a parent and the child it spawned.
      if (meta.parent_agent_id) {
        const parentNode = agents.find((n) => n.metadata?.agent_id === meta.parent_agent_id);
        if (parentNode && parentNode.metadata.org_id !== meta.org_id) {
          throw new DenyError('ERR_ORG_MISMATCH',
            `${label}: org_id "${meta.org_id}" differs from its parent's "${parentNode.metadata.org_id}"`);
        }
      }

      boundsByAgent.set(meta.agent_id, parseAuthorizationBounds(meta));
      record(stages, 7, '7', 'PASS',
        `${label}: bounds parsed — ${boundsByAgent.get(meta.agent_id).allowed_scopes.length} scope(s), `
        + `max_children ${boundsByAgent.get(meta.agent_id).max_children}`, label);
    };

    // §13.1 Fail Closed. `document.crl ?? { revoked: [], disabled: [] }` read as
    // a harmless default and was the opposite: a document that OMITS the CRL is
    // a document whose revocation status is unknown, and substituting an empty
    // CRL answers "nothing is revoked" to a question nobody could answer.
    // Deleting one key turned every revocation check into a pass.
    //
    // An EMPTY crl is fine and means "nothing is revoked". A MISSING one means
    // "we do not know", and the two must not be the same value.
    if (auditMissing) {
      throw new DenyError('ERR_SCHEMA_VIOLATION',
        'document carries no audit chain — integrity cannot be established (§16.6)');
    }
    if (!crlPresent) {
      throw new DenyError('ERR_SCHEMA_VIOLATION',
        'document carries no crl — revocation status cannot be determined (§13.1)');
    }
    const crl = document.crl;
    const boundsByAgent = new Map();

    // The anchor first: everything else is measured against it.
    parseCertificate(anchor.cert_pem);
    // §12 revocation applied only to agent ids, so a CRL naming the ANCHOR was
    // accepted and ignored — the one revocation that voids everything beneath it
    // was the one revocation with no effect. Checked before any agent, because
    // if the anchor is revoked no agent's verification means anything.
    const anchorSubject = anchor.metadata?.subject;
    const revokedList = Array.isArray(document.crl.revoked) ? document.crl.revoked : [];
    const disabledList = Array.isArray(document.crl.disabled) ? document.crl.disabled : [];
    if (anchorSubject && (revokedList.includes(anchorSubject) || disabledList.includes(anchorSubject))) {
      throw new DenyError('ERR_AGENT_REVOKED',
        'the trust anchor is revoked — every certificate beneath it is void (§12)');
    }
    record(stages, 2, '6', 'PASS', 'trust anchor parses and is self-signed', 'TRUST ANCHOR');
    step('TRUST ANCHOR', 'PASS', 'self-signed, in no trust store, name-constrained');

    const ordered = [...agents].sort((a, b) =>
      (a.metadata?.parent_agent_id ? 1 : 0) - (b.metadata?.parent_agent_id ? 1 : 0));
    for (const node of ordered) {
      const label = node.metadata?.parent_agent_id ? 'CHILD AGENT' : 'PARENT AGENT';
      try {
        await nodeChecks(node, label);
        const b = boundsByAgent.get(node.metadata.agent_id);
        step(label, 'PASS',
          `identity, certificate, standing and bounds all check out · ${b.allowed_scopes.join(', ') || 'no scopes'}`);
      } catch (e) {
        if (e instanceof DenyError) { e.subject = label; step(label, 'DENY', e.detail || e.title); }
        throw e;
      }
    }

    // ── Stages 4-6 — dual signature, field guard, required fields (§9.3) ───
    const authorities = document.authorities ?? {};
    if (isPolicyUpdate(document)) {
      if (!authorities.owner?.cert_pem || !authorities.pa?.cert_pem) {
        throw new DenyError('ERR_AUTHORITY_CHAIN',
          'a policy update requires both the Owner and Policy Authority certificates');
      }
      // Chain of custody: the signing authorities must themselves be CA-signed
      // and current, or a valid signature from a bogus authority would pass.
      for (const [role, node] of [['Owner', authorities.owner], ['Policy Authority', authorities.pa]]) {
        try {
          await validateCertificate({
            certPem: node.cert_pem, caPem: anchor.cert_pem,
            agentId: node.common_name, now,
          });
        } catch (e) {
          throw new DenyError('ERR_AUTHORITY_CHAIN', `${role} certificate: ${e.detail || e.message}`);
        }
      }
      // Sub-checks report as they complete, so a refusal in the middle of the
      // group still leaves an honest log: the stages that genuinely passed are
      // shown as PASS, and the log never skips a number.
      const result = await validatePolicyUpdate({
        document,
        ownerCertPem: authorities.owner.cert_pem,
        paCertPem: authorities.pa.cert_pem,
        onStage: (n, detail) => completed.push([n, detail]),
      });
      for (const [n, detail] of completed) {
        record(stages, n, n === 4 ? '9.3' : '9.3', 'PASS', detail);
      }
      if (!completed.some(([n]) => n === 4)) record(stages, 4, '9.3', 'PASS', result.detail);
      step('POLICY UPDATE', 'PASS', result.detail);
      stages.sort((a, b) => a.n - b.n);
    } else {
      // Not a policy update: the reference implementation returns "Not a policy
      // update" and continues. Recorded as PASS with the reason, never omitted —
      // a stage that silently vanishes from the log is indistinguishable from
      // one that was forgotten.
      const detail = 'not a policy update — no signatures to verify';
      step('POLICY UPDATE', 'PASS', detail);
      record(stages, 4, '9.3', 'PASS', detail);
      record(stages, 5, '9.3', 'PASS', detail);
      record(stages, 6, '9.3', 'PASS', detail);
    }

    // ── Delegation: the parent-to-child relationship (§8.1, §7) ────────────
    for (const node of agents) {
      const parentId = node.metadata.parent_agent_id;
      if (!parentId) continue;
      const parentBounds = boundsByAgent.get(parentId);
      if (!parentBounds) {
        throw new DenyError('ERR_BOUNDS_UNPARSEABLE', 'a child names a parent that is not in the chain');
      }
      const siblings = agents.filter((n) => n.metadata.parent_agent_id === parentId
        && n.metadata.agent_id !== node.metadata.agent_id).length;
      assertMaySpawn({ parentBounds, childId: node.metadata.agent_id, currentChildren: siblings });
    }
    record(stages, 7, '7', 'PASS',
      'DELEGATION: spawn whitelist and max_children satisfied', 'DELEGATION');

    // ── Stage 8 — scope containment (§8.3) ─────────────────────────────────
    let delegations = 0;
    for (const node of agents) {
      const bounds = boundsByAgent.get(node.metadata.agent_id);
      const parentId = node.metadata.parent_agent_id;
      if (parentId) {
        assertScopeSubset(bounds.allowed_scopes, boundsByAgent.get(parentId).allowed_scopes);
        delegations += 1;
      }
      if (Array.isArray(node.requested_scopes)) {
        assertScopeSubset(node.requested_scopes, bounds.allowed_scopes);
      }
    }
    record(stages, 8, '8.3', 'PASS',
      delegations > 0
        ? `DELEGATION: child scopes are a subset of the parent's`
        : 'no delegation to check; requested scopes are within bounds', 'DELEGATION');
    step('DELEGATION', 'PASS', delegations > 0
      ? 'child scopes are a subset of the parent, spawn whitelist and cap satisfied'
      : 'no delegation in this chain');

    // ── Stage 9 — audit integrity (§16.6) ──────────────────────────────────
    const integrity = await audit.verify();
    if (!integrity.valid) {
      throw new DenyError('ERR_AUDIT_CHAIN_BROKEN', integrity.reason ?? 'hash chain is broken');
    }
    await audit.append({ action: 'verify_chain', decision: 'ALLOWED',
      agents: agents.map((n) => n.metadata.agent_id) }, now);
    record(stages, 9, '16.6', 'PASS', `hash chain valid across ${audit.length} entr(ies)`);
    step('AUDIT CHAIN', 'PASS', `intact across ${audit.length} entr${audit.length === 1 ? 'y' : 'ies'}`);

    verdict = 'PASS';
  } catch (error) {
    const deny = error instanceof DenyError
      ? error
      // §13.1 — anything unexpected is a DENY that says so, not a crash and not
      // a pass. The original message is deliberately not surfaced: it can echo
      // input, and this page renders everything it reports.
      : new DenyError('ERR_INTERNAL', 'validation could not be completed');
    failure = deny;

    const n = deny.stage > 0 ? deny.stage : (stages.length + 1);
    // Any sub-check that completed before the failure is already recorded by
    // the onStage callback; sort so the log reads 1..n with no gaps.
    for (const [sn, detail] of completed) {
      if (sn < n) record(stages, sn, '9.3', 'PASS', detail);
    }
    record(stages, n, deny.section, 'DENY', deny.detail || deny.title, deny.subject ?? null);
    if (!deny.subject) {
      const POLICY_CODES = new Set([
        'ERR_OWNER_SIG_MISSING', 'ERR_PA_SIG_MISSING', 'ERR_OWNER_SIG_INVALID',
        'ERR_PA_SIG_INVALID', 'ERR_SINGLE_SIGNATURE', 'ERR_IMMUTABLE_FIELD',
        'ERR_UNKNOWN_POLICY_FIELD', 'ERR_REQUIRED_FIELD', 'ERR_AUTHORITY_CHAIN',
        'ERR_POLICY_EXCEEDS_TEMPLATE', 'ERR_SPAWN_EXCEEDS_TEMPLATE',
        'ERR_OWNER_MISMATCH', 'ERR_ORG_MISMATCH', 'ERR_POLICY_VERSION',
        'ERR_CONTENT_HASH',
      ]);
      const where = POLICY_CODES.has(deny.code) ? 'POLICY UPDATE'
        : deny.code === 'ERR_AUDIT_CHAIN_BROKEN' ? 'AUDIT CHAIN'
        : deny.stage === 7 || deny.stage === 8 ? 'DELEGATION'
        : null;
      if (where) step(where, 'DENY', deny.detail || deny.title);
    }
    stages.sort((a, b) => a.n - b.n);

    // The refusal is itself an auditable event. Appending after a failure keeps
    // the chain a record of decisions rather than a record of successes.
    try {
      // Name the agents this run covered. A refusal row that says only
      // "DENIED verify_chain" attributes the decision to nobody, which is the
      // one thing an audit record exists to do.
      // Read the chain from `document`, not from the `agents` binding: that one
      // is scoped inside the try block, so referencing it here throws a
      // ReferenceError which the surrounding catch swallows -- and the refusal
      // silently stops being recorded. Caught by a unit test asserting the DENY
      // entry exists, which is exactly the assertion a swallowing catch needs.
      const covered = (document?.chain ?? [])
        .filter((n) => n.role === 'agent')
        .map((n) => n.metadata?.agent_id)
        .filter(Boolean);
      await audit.append({
        action: 'verify_chain', decision: 'DENIED', reason: deny.code,
        ...(covered.length ? { agents: covered } : {}),
      }, now);
    } catch { /* an audit failure must not mask the original refusal */ }
  }

  // The walk records stages in chain order, not numeric order — the anchor's
  // §6 check lands before the first agent's stage 1. Sort once here so the
  // exported decision log always reads 1..9.
  stages.sort((a, b) => a.n - b.n);

  // Stable key order, no undefined, verdict never absent.
  return {
    playground_version: version,
    draft: DRAFT,
    generated_at: now.toISOString(),
    demo_only: true,
    verdict,
    walk,
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
