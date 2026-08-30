/**
 * Error catalogue — every DENY the playground can emit.
 *
 * The verdict banner's last line is `{code} · §{section} · {timestamp}`, and
 * DESIGN.md calls that the single most screenshot-able element on the page. So
 * the code and the draft section are data, defined here once, rather than
 * strings assembled at each call site — the decision log, the verdict banner,
 * and the exported JSON all read the same record and cannot disagree.
 *
 * `section` is the governing clause of draft-tonyai-a2a-trust-02. A null section
 * means the check is implementation hardening with no clause behind it — stage 1
 * is the only such case, and saying so is more honest than inventing a citation.
 */

/** @typedef {{code:string, section:string|null, stage:number, title:string}} ErrorSpec */

const SPECS = [
  // ── Stage 1 — input validation (implementation hardening, not a draft clause)
  ['ERR_AGENT_ID_FORMAT',      null,   1, 'agent_id is not a UUID4'],
  ['ERR_MALFORMED_JSON',       null,   1, 'document is not parseable JSON'],
  ['ERR_DOCUMENT_TOO_LARGE',   null,   1, 'document exceeds the size cap'],
  ['ERR_PROTOTYPE_POLLUTION',  null,   1, 'document contains a forbidden key'],
  ['ERR_SCHEMA_VIOLATION',     null,   1, 'document does not match the metadata schema'],
  ['ERR_FIELD_CHARSET',        null,   1, 'field contains characters outside its allowlist'],
  ['ERR_FIELD_RANGE',          null,   1, 'numeric field is out of range'],
  ['ERR_TIMESTAMP_FORMAT',     null,   1, 'timestamp is not a valid ISO-8601 instant'],
  ['ERR_MALFORMED_PEM',        null,   1, 'PEM block is malformed'],

  // ── Stage 2 — X.509 identity (§6) and template state (§10.4)
  ['ERR_CHAIN_INVALID',        '6',    2, 'certificate does not verify to the CA'],
  ['ERR_FORGED_ISSUER',        '6',    2, 'issuer is not the trust anchor'],
  ['ERR_SELF_SIGNED',          '6.2',  2, 'agent certificates must be CA-signed, never self-signed'],
  ['ERR_CERT_EXPIRED',         '6',    2, 'certificate is outside its validity window'],
  ['ERR_KEY_TOO_SMALL',        '6.1',    2, 'RSA key is smaller than 2048 bits'],
  ['ERR_SUBJECT_MISMATCH',     '6',    2, 'certificate CN does not match agent_id'],
  ['ERR_UNKNOWN_CRITICAL_EXT', '6.1',    2, 'certificate carries a critical extension this validator does not recognise'],
  ['ERR_NAME_CONSTRAINT',      '6.1',    2, 'subject falls outside the issuing CA name constraints'],
  ['ERR_BASIC_CONSTRAINTS',    '6.1',    2, 'basicConstraints absent, or asserts a role the certificate may not hold'],
  ['ERR_WEAK_SIGNATURE',       '6.1',    2, 'certificate is signed with a digest weaker than SHA-256'],
  ['ERR_AGENT_DISABLED',       '10.4', 2, 'agent state is not ACTIVE'],

  // ── Stage 3 — revocation and chain of custody (§12)
  ['ERR_AGENT_REVOKED',        '12',   3, 'agent is on the revocation list'],
  ['ERR_TTL_EXPIRED',          '12.3', 3, 'agent TTL has elapsed'],
  ['ERR_AUTHORITY_CHAIN',      '9.3',  4, 'a signing authority does not chain to the CA'],

  // ── Stages 4-6 — dual signature and the policy field guard (§9.3)
  ['ERR_OWNER_SIG_MISSING',    '9.3',  4, 'owner signature absent — Phase 1 cannot proceed'],
  ['ERR_PA_SIG_MISSING',       '9.3',  4, 'Policy Authority signature absent — Phase 2 cannot proceed'],
  ['ERR_OWNER_SIG_INVALID',    '9.3',  4, 'Phase 1 failed — owner signature does not cover the identity fields'],
  ['ERR_PA_SIG_INVALID',       '9.3',  4, 'Phase 2 failed — PA signature does not cover the policy fields'],
  ['ERR_SINGLE_SIGNATURE',     '9.3',  4, 'one signature is never sufficient for a policy update'],
  ['ERR_IMMUTABLE_FIELD',      '9.3',  5, 'policy update touches an immutable certificate field'],
  ['ERR_UNKNOWN_POLICY_FIELD', '9.3',  5, 'policy update contains a field outside the allowlist'],
  ['ERR_REQUIRED_FIELD',       '9.3',  6, 'policy update is missing a required field'],
  // §7.2 — dynamic policy is bounded by the static template. This is the clause
  // that stops two valid signatures from widening authority past the ceiling.
  ['ERR_POLICY_EXCEEDS_TEMPLATE','7.2', 7, 'dynamic policy grants beyond the static template bounds'],
  ['ERR_SPAWN_EXCEEDS_TEMPLATE','7.2',  7, 'dynamic policy adds spawn targets beyond CanSpawn'],
  // §9.2 — only the verified owner of the signing organisation may submit changes.
  ['ERR_OWNER_MISMATCH',       '9.2',  4, 'policy submitter is not the template owner'],
  ['ERR_ORG_MISMATCH',         '9.2',  4, 'policy OrgID does not match the template'],
  // §9.4 — stored with version, timestamp and content hash; all revalidated.
  ['ERR_POLICY_VERSION',       '9.4',  6, 'policy version is not current'],
  ['ERR_CONTENT_HASH',         '9.6',  6, 'policy content hash does not match the document'],

  // ── Stage 7 — authorization bounds (§7, §8.1)
  ['ERR_BOUNDS_UNPARSEABLE',   '7',    7, 'authorization bounds absent or unparseable'],
  ['ERR_MAX_CHILDREN',         '7',    7, 'max_children would be exceeded'],
  ['ERR_CHILD_NOT_WHITELISTED','8.1',  7, 'child agent is not in the parent can_spawn whitelist'],

  // ── Stage 8 — scope containment (§8.3)
  ['ERR_SCOPE_ESCALATION',     '8.3',  8, 'requested scopes are not a subset of allowed_scopes'],
  ['ERR_EMPTY_SCOPES',         '16.1', 8, 'an agent must declare the scopes it requests'],

  // ── Stage 9 — audit integrity (§16.6)
  ['ERR_AUDIT_CHAIN_BROKEN',   '16.7', 9, 'audit hash chain is broken'],

  // ── Fail-closed catch-all (§13)
  ['ERR_INTERNAL',             '13.1', 0, 'validation could not complete — failing closed'],
];

/** @type {Record<string, ErrorSpec>} */
export const ERRORS = Object.freeze(Object.fromEntries(
  SPECS.map(([code, section, stage, title]) =>
    [code, Object.freeze({ code, section, stage, title })]),
));

export const ERROR_CODES = Object.freeze(SPECS.map(([code]) => code));

/**
 * A DENY carrying its governing clause. `detail` is the specific, human-readable
 * reason — it goes on the page, so callers must never interpolate raw input into
 * it without validating first.
 */
export class DenyError extends Error {
  /** @param {string} code @param {string} [detail] */
  constructor(code, detail = '') {
    const spec = ERRORS[code];
    if (!spec) throw new Error(`unknown error code: ${code}`);
    super(detail ? `${spec.title}: ${detail}` : spec.title);
    this.name = 'DenyError';
    this.code = spec.code;
    this.section = spec.section;
    this.stage = spec.stage;
    this.title = spec.title;
    this.detail = detail;
  }

  /** The verdict banner's last line: `ERR_SCOPE_ESCALATION · §8.3` */
  get banner() {
    return this.section ? `${this.code} · §${this.section}` : this.code;
  }

  /** Shape used by the exported JSON's `stages[]` entries. */
  toJSON() {
    return { code: this.code, section: this.section, detail: this.detail };
  }
}

/** Convenience: throw a DenyError. Reads better at a guard clause. */
export function deny(code, detail) {
  throw new DenyError(code, detail);
}
