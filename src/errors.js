/**
 * Error catalogue — every DENY the playground can emit.
 *
 * The verdict banner's last line is `{code} · §{section} · {timestamp}`, and
 * DESIGN.md calls that the single most screenshot-able element on the page. So
 * the code and the draft section are data, defined here once, rather than
 * strings assembled at each call site — the decision log, the verdict banner,
 * and the exported JSON all read the same record and cannot disagree.
 *
 * `section` is the governing clause of draft-tonyai-a2a-trust-03. A null section
 * means the check is implementation hardening with no clause behind it, and
 * saying so is more honest than inventing a citation. Every non-null section is
 * checked against the draft text by tests/citations.test.js, which pins the
 * section TITLE and not just the number: -02 renumbered everything after §6 and
 * three citations went on resolving to the wrong clause, confidently.
 *
 * `stage` is the pipeline stage a refusal belongs to. Stage 0 is issuance: the
 * Registry refused to mint, so no chain exists to walk.
 */

/** @typedef {{code:string, section:string|null, stage:number, title:string}} ErrorSpec */

const SPECS = [
  // ── Stage 1 — input contract (§3 where the draft speaks, hardening where it does not)
  ['ERR_AGENT_ID_FORMAT',      '7.2',  1, 'agent identifier is not a lowercase RFC 9562 UUID'],
  ['ERR_MALFORMED_JSON',       null,   1, 'document is not parseable JSON'],
  ['ERR_DUPLICATE_MEMBER',     '3',    1, 'a JSON object carries the same member name twice'],
  ['ERR_OBJECT_NOT_FLAT',      '3',    1, 'object carries a member whose type this profile does not define'],
  ['ERR_DOCUMENT_TOO_LARGE',   null,   1, 'document exceeds the size cap'],
  ['ERR_PROTOTYPE_POLLUTION',  null,   1, 'document contains a forbidden key'],
  ['ERR_SCHEMA_VIOLATION',     null,   1, 'document does not match the schema'],
  ['ERR_FIELD_CHARSET',        null,   1, 'field contains characters outside its allowlist'],
  ['ERR_SCOPE_SYNTAX',         '10.3', 1, 'scope is outside the syntax the draft permits'],
  ['ERR_FIELD_RANGE',          null,   1, 'numeric field is out of range'],
  ['ERR_TIMESTAMP_FORMAT',     '3',    1, 'timestamp is not an RFC 3339 instant in UTC with the Z designator'],
  ['ERR_MALFORMED_PEM',        null,   1, 'PEM block is malformed'],

  // ── Stage 2 — X.509 identity (§7), the certificate profile (§7.1), the two
  //    extensions (§8.2, §10.5) and issuance rules a relying party re-checks (§9.3)
  ['ERR_CHAIN_INVALID',        '7',    2, 'certificate does not verify to the CA'],
  ['ERR_FORGED_ISSUER',        '7',    2, 'issuer is not the trust anchor'],
  ['ERR_SELF_SIGNED',          '7.3',  2, 'agent certificates are issued by the CA, never self-signed'],
  ['ERR_CERT_EXPIRED',         '7',    2, 'certificate is outside its validity window'],
  ['ERR_KEY_TOO_SMALL',        '7.1',  2, 'public key is below the 128-bit security level'],
  ['ERR_SUBJECT_MISMATCH',     '7.2',  2, 'certificate subject does not name the agent the document claims'],
  ['ERR_UNKNOWN_CRITICAL_EXT', '7.1',  2, 'certificate carries a critical extension this validator does not recognise'],
  ['ERR_NAME_CONSTRAINT',      '7.1',  2, 'subject falls outside the issuing CA name constraints'],
  ['ERR_BASIC_CONSTRAINTS',    '7.1',  2, 'basicConstraints absent, or asserts a role the certificate may not hold'],
  ['ERR_WEAK_SIGNATURE',       '7.1',  2, 'certificate is signed with a digest weaker than SHA-256'],
  ['ERR_KEY_USAGE',            '7.1',  2, 'keyUsage is absent, not critical, or asserts more than digitalSignature'],
  ['ERR_SERIAL_ENTROPY',       '7.1',  2, 'serial number carries fewer than 64 bits'],
  ['ERR_NO_REVOCATION_SOURCE', '14.4', 2, 'certificate does not say where its revocation state lives'],
  ['ERR_TEMPLATE_EXT_MISSING', '8.2',  2, 'agent certificate carries no Agent Template extension'],
  ['ERR_TEMPLATE_EXT_INVALID', '8.2',  2, 'Agent Template extension is malformed'],
  ['ERR_TTL_TOO_LONG',         '9.3',  2, 'ttl_seconds exceeds the seven-day maximum'],
  ['ERR_VALIDITY_EXCEEDS_TTL', '9.3',  2, 'certificate validity is longer than its own ttl_seconds'],
  ['ERR_SPAWN_EXT_INVALID',    '10.5', 2, 'Agent Spawn extension is malformed'],
  ['ERR_PARENT_MISMATCH',      '10.5', 2, 'the parent the certificate attests is not the parent the chain names'],
  ['ERR_NONCE_REUSED',         '19.2', 2, 'a spawn nonce was issued more than once'],
  ['ERR_DUPLICATE_SUBJECT',    '12.1', 2, 'one subject presents two unrevoked certificates'],
  // Catalogued at stage 3, not 2: `assertNotRevoked` runs at the same point in
  // the walk as ERR_AGENT_REVOKED, right after the stage-2 X.509 identity
  // check records PASS. A stage-2 code here would overwrite that PASS row
  // with this DENY, misreporting a certificate check that in fact succeeded.
  ['ERR_AGENT_DISABLED',       '12.4', 3, 'template is DISABLED at the Registry'],

  // ── Stage 3 — revocation (§14)
  ['ERR_AGENT_REVOKED',        '14',   3, 'certificate is on the revocation list'],

  // ── Stages 4-6 — the signature envelope (§3.1), dual signature (§11.3),
  //    ownership (§11.2), the policy document (§11.4) and its coverage (§11.6)
  ['ERR_AUTHORITY_CHAIN',      '9.2',  4, 'a signing authority does not validate to the trust anchor'],
  ['ERR_ENVELOPE_MEMBER',      '3.1',  4, 'envelope carries a member the draft does not define'],
  ['ERR_SIGNATURE_ALGORITHM',  '3.1',  4, 'signature is not the form Table 2 assigns to the signer key type'],
  ['ERR_OWNER_SIG_MISSING',    '11.3', 4, 'owner signature absent'],
  ['ERR_PA_SIG_MISSING',       '11.3', 4, 'Policy Authority signature absent'],
  ['ERR_OWNER_SIG_INVALID',    '11.3', 4, 'owner signature does not verify over the body'],
  ['ERR_PA_SIG_INVALID',       '11.3', 4, 'Policy Authority signature does not verify over the body'],
  ['ERR_SINGLE_SIGNATURE',     '3.1',  4, 'one key cannot satisfy both roles'],
  ['ERR_OWNER_CERT_MISMATCH',  '9.2',  4, 'the Owner certificate does not name the template owner'],
  ['ERR_IMMUTABLE_FIELD',      '11.4', 5, 'policy carries a field that only re-certification may change'],
  ['ERR_UNKNOWN_POLICY_FIELD', '11.4', 5, 'policy carries a field outside the complete set'],
  ['ERR_REQUIRED_FIELD',       '11.4', 6, 'policy is missing a required field'],
  ['ERR_POLICY_EXCEEDS_TEMPLATE','8.3', 7, 'dynamic policy grants beyond the static template bounds'],
  ['ERR_SPAWN_EXCEEDS_TEMPLATE','8.3', 7, 'dynamic policy adds spawn targets beyond CanSpawn'],
  ['ERR_OWNER_MISMATCH',       '11.2', 4, 'policy submitter is not the template owner'],
  ['ERR_ORG_MISMATCH',         '11.2', 4, 'policy OrgID does not match the template'],
  ['ERR_SUBJECT_UNKNOWN',      '11.4', 4, 'policy names a subject that is not in the chain'],
  ['ERR_POLICY_VERSION',       '11.4', 6, 'policy version does not supersede the version in force'],
  ['ERR_POLICY_EXPIRED',       '11.4', 6, 'policy is not valid beyond the certificate it governs'],
  ['ERR_CONTENT_HASH',         '11.6', 6, 'content hash does not match the body'],

  // ── Stage 7 — the two-check spawn rule (§10.1), the document-level
  //    MaxChildren consistency check (§10.2), and cross-organizational grants (§13)
  ['ERR_SPAWN_NOT_PERMITTED',  '10.1', 7, 'parent does not hold the spawn operation'],
  ['ERR_CHILD_NOT_WHITELISTED','10.1', 7, 'child is not in the parent CanSpawn list'],
  ['ERR_MAX_CHILDREN',         '10.2', 7, 'the document names more children than MaxChildren'],
  ['ERR_GRANT_MISSING',        '13.1', 7, 'cross-organizational spawn has no explicit grant'],
  ['ERR_GRANT_INVALID',        '13.2', 7, 'grant is malformed, mis-addressed or not validly signed'],
  ['ERR_GRANT_EXPIRED',        '13.2', 7, 'grant has expired, or is dated in the future'],
  ['ERR_GRANT_EXCEEDS_TEMPLATE','13.2', 7, 'grant allows scopes beyond the template it grants'],
  ['ERR_MAX_SPAWNS',           '13.2', 7, 'the document names more agents under a grant than MaxSpawns'],

  // ── Stage 8 — scope containment (§10.3)
  ['ERR_SCOPE_ESCALATION',     '10.3', 8, 'child scopes are not a subset of the parent scopes'],
  ['ERR_EMPTY_SCOPES',         '10.3', 8, 'a request for no scopes is refused'],

  // ── Stage 9 — audit integrity (§19.7)
  ['ERR_AUDIT_CHAIN_BROKEN',   '19.7', 9, 'audit hash chain is broken'],

  // ── Stage 0 — issuance. The Registry refused to attest or mint (§9, §19.2).
  ['ERR_TEMPLATE_NONCONFORMING','9.1', 0, 'template fails the conformance gate'],
  ['ERR_TEMPLATE_SIGNATURE',   '9.2',  0, 'template attestation is absent or does not verify'],
  ['ERR_SPAWN_STALE',          '19.2', 0, 'spawn request timestamp is outside the freshness window'],

  // ── Fail-closed catch-all (§15.1)
  ['ERR_INTERNAL',             '15.1', 0, 'validation could not complete — failing closed'],
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

  /** The verdict banner's last line: `ERR_SCOPE_ESCALATION · §10.3` */
  get banner() {
    return this.section ? `${this.code} · §${this.section}` : this.code;
  }

  /** Shape used by the exported JSON's `stages[]` entries. */
  toJSON() {
    return { code: this.code, section: this.section, detail: this.detail };
  }
}
