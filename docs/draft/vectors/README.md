# Test vectors — draft-tonyai-a2a-trust-03

Concrete artifacts for §16.3, produced by the playground's own code paths
(`scripts/gen-vectors.mjs`). Each file's `document` is one complete chain
document exactly as the page validates it, plus the exact JCS preimage of
every signed or hashed object inside it, so a second implementer can check
three things independently:

1. **Canonicalization** — your JCS of each `body` and extension must equal the
   `jcs_preimages` string byte for byte.
2. **Signatures** — each `owner_sig` / `pa_sig` must verify under the named
   authority certificate over that preimage, as ECDSA P-256 / SHA-256 with a
   64-octet `r‖s` value. They will not byte-match anything you produce: ECDSA is
   randomized.
3. **The whole document** — your validator must reach the `expected` verdict.

**Paste it into the playground directly:** copy just the `document` object —
not the file's other top-level keys — into the editor at
https://phalanxaisec.com/a2a and press Validate. `description`, `note`,
`jcs_preimages` and `expected` are vector metadata for an independent
implementer, not part of the document schema (§3), so the playground refuses
them as unknown fields if they are pasted in along with `document`.

**The clock:** every certificate, grant and policy here is time-bound, same as
in any real chain. Validate as of `generated_at`, not whenever you happen to
be reading this — well after `generated_at` plus the shortest TTL involved,
`ERR_CERT_EXPIRED` (or `ERR_GRANT_EXPIRED`) is the CORRECT verdict, not a
defect in the vector. The playground's own clock is real time and cannot be
pinned from the UI, so a vector pasted in long after `generated_at` is
expected to read as expired there; an independent validator being tested
against `expected` should accept an injectable clock, the way this
repository's own round-trip harness and unit tests do.

| file | what |
|---|---|
| `01-single-organization.json` | Registry, root orchestrator, child, dual-signed policy. PASS. |
| `02-cross-organization-grant.json` | Same, with the child under `partner-org` and a §13.2 grant. PASS. |

No private key is included; none is needed to verify. The certificates are
carried as PEM strings inside the JSON. Both profile extensions are critical, so
`openssl verify` refuses every agent certificate here — by design (§8.2) — and
`openssl verify -ignore_critical` accepts them.

Generated 2026-09-04T17:48:20.818Z. Regenerate with `node scripts/gen-vectors.mjs`;
every run mints fresh keys, so the files change on every run and are checked in
as a snapshot, not as a fixed point.
