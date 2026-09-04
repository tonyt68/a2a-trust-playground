/**
 * Emit test vectors for the draft's §16.3 — the concrete artifacts a second
 * implementer needs to check their own reading of the text.
 *
 * Everything is produced by the same code paths the page uses. Certificates
 * are carried as PEM strings inside JSON, not as .crt files, because the
 * repository never tracks certificate files. No private key is emitted: every
 * signature scheme in §3.1 is randomized or verified rather than compared, so
 * a vector VERIFIES a signature and never needs the key that made it.
 *
 *     node scripts/gen-vectors.mjs        # writes docs/draft/vectors/
 */
import { writeFileSync, mkdirSync } from 'node:fs';
import { buildDefaultDocument } from '../src/defaults.js';
import { runPipeline, DRAFT } from '../src/pipeline.js';
import { canonicalize } from '../src/canonical.js';
import { parseCertificate, parseTemplateExtension, parseSpawnExtension } from '../src/x509.js';
import { spawnAcrossOrganizations, childOf, parentOf } from '../src/scenarios.js';
import { entryPreimage } from '../src/audit-chain.js';

const root = new URL('..', import.meta.url).pathname;
const out = `${root}docs/draft/vectors/`;
mkdirSync(out, { recursive: true });

const now = new Date();
const doc = await buildDefaultDocument({ now });
const single = JSON.parse(JSON.stringify(doc));
const r1 = await runPipeline({ document: JSON.parse(JSON.stringify(single)), now });
if (r1.verdict !== 'PASS') throw new Error(`single-org chain does not validate: ${r1.error_code}`);

await spawnAcrossOrganizations(doc, {}, { now });
const r2 = await runPipeline({ document: JSON.parse(JSON.stringify(doc)), now });
if (r2.verdict !== 'PASS') throw new Error(`cross-org chain does not validate: ${r2.error_code}`);

const strip = (node) => ({ role: node.role, cert_pem: node.cert_pem, metadata: node.metadata,
  ...(node.requested_scopes ? { requested_scopes: node.requested_scopes } : {}) });
const preimages = (d) => ({
  agent_template_parent: canonicalize(parseTemplateExtension(parseCertificate(parentOf(d).cert_pem))),
  agent_template_child: canonicalize(parseTemplateExtension(parseCertificate(childOf(d).cert_pem))),
  agent_spawn_child: canonicalize(parseSpawnExtension(parseCertificate(childOf(d).cert_pem))),
  policy_body: canonicalize(d.policy.body),
  policies_in_force: (d.policies ?? []).map((p) => canonicalize(p.body)),
  ...(d.grant ? { grant_body: canonicalize(d.grant.body) } : {}),
  audit_entries: d.audit.chain.map(entryPreimage),
});

const common = {
  draft: DRAFT,
  generated_at: now.toISOString(),
  note: 'Every signature is ECDSA P-256 with SHA-256, fixed-width r‖s, base64 (§3.1 Table 2). Signatures are randomized: verify them, do not compare them. Certificates carry the Agent Template extension (§8.2) and, on the child, the Agent Spawn extension (§10.5, grant_id present exactly when the spawn crossed organizations), both critical. `policies` are the envelopes the Registry holds in force (§11.4), which §10.2 step 3 was evaluated against; `audit` is the Registry\'s log, its spawn entry shaped as §10.4 Table 6. openssl verify refuses the certificates by design; openssl verify -ignore_critical accepts them.',
};

writeFileSync(`${out}01-single-organization.json`, JSON.stringify({
  ...common,
  description: 'One Registry, a root orchestrator, one child spawned from it, and a dual-signed policy narrowing the child within its ceiling. Expected verdict: PASS.',
  // Everything under `document` is EXACTLY what the playground's own editor
  // validates — paste this one object in directly, nothing stripped, nothing
  // added. The sibling keys (description, note, jcs_preimages, expected) are
  // vector metadata for an independent implementer and are not part of the
  // document schema, so the playground refuses them as unknown fields if
  // they are pasted in WITH it.
  document: {
    chain: single.chain.map(strip),
    authorities: { owner: { common_name: single.authorities.owner.common_name, cert_pem: single.authorities.owner.cert_pem },
      pa: { common_name: single.authorities.pa.common_name, cert_pem: single.authorities.pa.cert_pem } },
    policy: single.policy,
    policies: single.policies,
    current_policy_version: single.current_policy_version,
    crl: single.crl,
    audit: single.audit,
  },
  jcs_preimages: preimages(single),
  expected: { verdict: 'PASS', stages: r1.stages.map((s) => [s.n, s.section, s.result]) },
}, null, 2));

writeFileSync(`${out}02-cross-organization-grant.json`, JSON.stringify({
  ...common,
  description: 'The same chain with the child re-issued under partner-org and a grant from partner-org to playground-org (§13.2), signed by the grantor\'s Owner and Policy Authority. Expected verdict: PASS.',
  document: {
    chain: doc.chain.map(strip),
    authorities: { owner: { common_name: doc.authorities.owner.common_name, cert_pem: doc.authorities.owner.cert_pem },
      pa: { common_name: doc.authorities.pa.common_name, cert_pem: doc.authorities.pa.cert_pem } },
    policy: doc.policy,
    policies: doc.policies,
    current_policy_version: doc.current_policy_version,
    grant: doc.grant,
    crl: doc.crl,
    audit: doc.audit,
  },
  jcs_preimages: preimages(doc),
  expected: { verdict: 'PASS', stages: r2.stages.map((s) => [s.n, s.section, s.result]) },
}, null, 2));

writeFileSync(`${out}README.md`, `# Test vectors — ${DRAFT}

Concrete artifacts for §16.3, produced by the playground's own code paths
(\`scripts/gen-vectors.mjs\`). Each file's \`document\` is one complete chain
document exactly as the page validates it, plus the exact JCS preimage of
every signed or hashed object inside it, so a second implementer can check
three things independently:

1. **Canonicalization** — your JCS of each \`body\` and extension must equal the
   \`jcs_preimages\` string byte for byte.
2. **Signatures** — each \`owner_sig\` / \`pa_sig\` must verify under the named
   authority certificate over that preimage, as ECDSA P-256 / SHA-256 with a
   64-octet \`r‖s\` value. They will not byte-match anything you produce: ECDSA is
   randomized.
3. **The whole document** — your validator must reach the \`expected\` verdict.

**Paste it into the playground directly:** copy just the \`document\` object —
not the file's other top-level keys — into the editor at
https://phalanxaisec.com/a2a and press Validate. \`description\`, \`note\`,
\`jcs_preimages\` and \`expected\` are vector metadata for an independent
implementer, not part of the document schema (§3), so the playground refuses
them as unknown fields if they are pasted in along with \`document\`.

**The clock:** every certificate, grant and policy here is time-bound, same as
in any real chain. Validate as of \`generated_at\`, not whenever you happen to
be reading this — well after \`generated_at\` plus the shortest TTL involved,
\`ERR_CERT_EXPIRED\` (or \`ERR_GRANT_EXPIRED\`) is the CORRECT verdict, not a
defect in the vector. The playground's own clock is real time and cannot be
pinned from the UI, so a vector pasted in long after \`generated_at\` is
expected to read as expired there; an independent validator being tested
against \`expected\` should accept an injectable clock, the way this
repository's own round-trip harness and unit tests do.

| file | what |
|---|---|
| \`01-single-organization.json\` | Registry, root orchestrator, child, dual-signed policy. PASS. |
| \`02-cross-organization-grant.json\` | Same, with the child under \`partner-org\` and a §13.2 grant. PASS. |

No private key is included; none is needed to verify. The certificates are
carried as PEM strings inside the JSON. Both profile extensions are critical, so
\`openssl verify\` refuses every agent certificate here — by design (§8.2) — and
\`openssl verify -ignore_critical\` accepts them.

Generated ${now.toISOString()}. Regenerate with \`node scripts/gen-vectors.mjs\`;
every run mints fresh keys, so the files change on every run and are checked in
as a snapshot, not as a fixed point.
`);
console.log('vectors written to docs/draft/vectors/');
