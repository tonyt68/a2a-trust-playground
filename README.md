# A2A Trust Playground

A browser implementation of
[`draft-tonyai-a2a-trust-03`](https://datatracker.ietf.org/doc/draft-tonyai-a2a-trust/) —
an IETF Internet-Draft on agent-to-agent trust: identity carried in X.509,
spawn authorization attested by the CA, scope delegation, dual-signed policy
governance, cross-organizational grants, revocation and audit integrity.

**[Try it → phalanxaisec.com/a2a](https://phalanxaisec.com/a2a)**

Mint a Registry and two agents, delegate a narrower identity to the child, then
try to widen it and watch the chain refuse — citing the clause of the draft
that refused it. No install, no account, no API key, and nothing transmitted:
every key is generated in your tab by Web Crypto and is gone when you refresh.

---

## Why this exists

The draft has a reference implementation
([`ietf-a2a-trust-poc`](https://github.com/tonyt68/ietf-a2a-trust-poc)) and an
adversarial one that attacks its own implementation
([`hack-my-own-code`](https://github.com/tonyt68/hack-my-own-code)). Both need
Docker, and one needs an API key. So the barrier to being the draft's next
implementer was "read the spec and build a CA from scratch."

A draft moves when someone else implements it. This lowers that barrier two ways:

- **Anyone can use the model in sixty seconds** without installing anything.
- **The validation logic is readable.** Every check is a small module with the
  clause it enforces in the comment, and a test that proves it.

If you are here to build the next implementation, start with
[`src/pipeline.js`](src/pipeline.js) and follow it outward.

---

## What it demonstrates

Under `-03`, authority lives **in the certificate**. The nine template members
of §8.1 travel in a critical X.509 extension the CA signs (§8.2), and a child's
link to its parent travels in a second one (§10.5). The chain document you edit
on the page restates identifiers, carries the request, the revocation state, the
audit chain and two signed envelopes — and asserts no authority of its own.

That produces the result most people find surprising, and the page is built to
show it:

> A policy carries two valid signatures from two independent keys over the same
> body. The content hash matches. The submitter is the verified owner. **It is
> still refused**, because it grants a scope beyond the certificate's ceiling.
>
> `ERR_POLICY_EXCEEDS_TEMPLATE · §8.3`

Two valid signatures authorize a change. They do not raise the ceiling, because
the ceiling is stated in a certificate no signature over the policy covers.

The page has buttons for changes the draft **permits**, one it **advises
against** without refusing (a SHOULD, shown as an advisory), changes it
**refuses**, and things the **Registry refuses to issue** at all — a template
missing a member, a template edited after it was signed, a replayed spawn
request, a request 61 seconds stale. A wall with no door teaches nothing about
where the door is.

---

## How validation works

Each run walks the chain **subject by subject**, stopping at the first refusal:

```
TRUST ANCHOR › PARENT AGENT › CHILD AGENT › CROSS-ORG GRANT › POLICY UPDATE › DELEGATION › AUDIT CHAIN
```

Underneath, that is nine ordered checks:

| # | Check | Clause | Module |
|---|---|---|---|
| 1 | Agent identifier form (RFC 9562, lowercase, any version) | §7.2 | [validate-input.js](src/validate-input.js) |
| 2 | X.509 chain, the §7.1 profile, both critical extensions, validity bound to TTL | §7, §7.1, §8.2, §9.3, §10.5, §12.1 | [x509.js](src/x509.js) |
| 3 | Revocation, and the Registry's DISABLED state | §14, §12.4 | [bounds.js](src/bounds.js) |
| 4 | Both signatures over the JCS form of `body`, distinct keys, Owner CN binding | §3.1, §11.3, §9.2 | [policy.js](src/policy.js) |
| 5 | Policy field guard — the §11.4 field set is complete, envelope members stay outside | §11.4, §11.6 | [policy.js](src/policy.js) |
| 6 | Required fields, version currency, content hash, lifetime | §11.4, §11.6 | [policy.js](src/policy.js) |
| 7 | Two-check spawn rule from the parent's certificate; MaxChildren consistency; cross-org grants | §10.1, §10.2, §13 | [bounds.js](src/bounds.js) |
| 8 | Scope containment, set semantics, fail-closed on the empty request | §10.3 | [bounds.js](src/bounds.js) |
| 9 | Audit hash chain over the same canonical form | §11.5, §19.7 | [audit-chain.js](src/audit-chain.js) |

Any failure is a DENY carrying an error code and the governing clause. The
`stages` array in the exported JSON *is* the decision log the UI renders, so the
log and the export cannot disagree.

**Two things are not implemented**, and the page says so inline where each
would have run: the Registry-side *enforcement* of MaxChildren (§10.2 — the page
checks the document for consistency with the cap and does not present that as
enforcement) and the policy-engine gate of §11.7 step 2.

The Registry side of the draft — the conformance gate (§9.1), dual attestation
(§9.2), issuance that re-gates and re-verifies (§9.3), Check 1 of the spawn rule
and the 60-second freshness window with nonce uniqueness (§10.2, §19.2) — is
implemented in [`src/mint.js`](src/mint.js), because the page mints its own
chain and has to play that role honestly.

---

## Three things worth reading the source for

**Canonicalization** ([src/canonical.js](src/canonical.js)). Every document the
draft defines is JCS ([RFC 8785](https://www.rfc-editor.org/info/rfc8785)), and
§11.5 specifies one canonical form for signatures and audit entries alike. JCS
sorts by UTF-16 code unit, which is JavaScript's native ordering, and emits raw
UTF-8, which is what `JSON.stringify` already produces — so the module is short.
Verified against 15 vectors transcribed from RFC 8785 and 8 differential vectors
computed by Python, with the one case where the two schemes legitimately
disagree asserted against the RFC only.

**The strict parser** ([src/validate-input.js](src/validate-input.js)). §3 puts
the duplicate-member rule on the *parser*: `JSON.parse` keeps the last of two
duplicates and reports success, which is precisely the behaviour the draft says
does not satisfy it. So the page carries an eighty-line recursive-descent parser
that refuses a duplicate at any depth, accepts the same name in two different
objects, and creates `__proto__` as an own key rather than as the prototype.

**The certificate profile** ([src/mint.js](src/mint.js), [src/x509.js](src/x509.js)).
Generated certificates are **valid, untrusted, constrained — and unusable by
anything that does not implement the draft**:

- **Valid** — genuinely well-formed X.509 on P-256 keys;
  `openssl verify -ignore_critical` returns `OK`.
- **Refused by plain `openssl verify`**, by design. Both profile extensions are
  critical (§8.2), so a validator that does not implement the draft refuses the
  certificate instead of treating it as an ordinary client certificate. The
  round-trip harness asserts that refusal.
- **Untrusted** — the CA is generated in your tab and is in nobody's trust store.
- **Constrained** — a critical `nameConstraints` extension means the CA is
  structurally incapable of issuing for any name that does not say
  `OU=DEMO ONLY - NOT FOR PRODUCTION`.

---

## Running it

```bash
pnpm install
pnpm dev             # http://127.0.0.1:9100 — hot bundle, no build step
pnpm test            # 701 unit tests
pnpm test:coverage   # the same, with line coverage over the validator modules
pnpm test:e2e        # builds, then 229 assertions against the built file, offline, in Chrome
pnpm test:roundtrip  # 70 checks by python-cryptography and OpenSSL, sharing no code with the page
pnpm test:all        # all three
pnpm build           # dist/a2a.html — one self-contained file
```

`pnpm test` regenerates its certificate fixtures with OpenSSL first. Keys and
certificates are **never committed**, even as test data.

The build emits a **single HTML file** with everything inlined — no external
scripts, stylesheets, fonts or images. Save it, disconnect from the network, and
open it from your filesystem: it still mints a chain and validates it. That
property is what makes "nothing leaves your browser" checkable rather than
promised.

---

## Verifying the page has not been tampered with

The page is one static file with no dynamic code, which makes its integrity
checkable in a way most web apps are not.

**The browser enforces it for you.** The Content-Security-Policy pins the inline
script by SHA-256 hash. Alter one byte of it and the browser refuses to execute
the script at all. There is no degraded mode where a modified page runs anyway.

**You can verify it yourself, out of band.** Every build publishes its own
digest:

```bash
shasum -a 256 -c a2a.html.sha256      # a2a.html: OK
```

Compare that against the digest for the matching commit in this repository.

**What this does not defend against.** A browser extension's content script
runs in an isolated world and is not subject to the page's CSP, so it can still
read the DOM. Running the saved file in a clean profile fixes that; no
page-level control does.

## Testing

701 unit tests, 229 end-to-end assertions, 70 round-trip checks. Line coverage
of the validator modules is 99.8% with every function exercised; what remains
is four guards no input can reach. The page module is measured by the browser
suite instead. The tests that matter most are **differential**:

- **Conformance to RFC 8785, not to another codebase.** The canonicalization
  oracle is the RFC, with Python used as an independent second implementation
  only where the two schemes provably agree.
- **Certificates built by OpenSSL, not by this code.** Every profile check is
  exercised against fixtures OpenSSL generated — P-256, P-384, RSA-3072 and
  Ed25519 keys; an Ed25519 CA; and twenty ways to be wrong. A validator tested
  only against certificates it produced itself proves that two copies of one
  bug agree.
- **Round-trip through tools that share no code with the page.** The harness
  exports a document the page validated, then `python-cryptography` parses every
  certificate, verifies each chain signature and reads both critical extensions
  as raw OCTET STRINGs; this repository's Python re-derives the §3, §8.2, §10.5
  and §11.4 rules from the draft text and applies them; OpenSSL verifies every
  envelope signature over JCS bytes the Python recomputed. Three toolchains, one
  answer.

The reference implementation is no longer an oracle here. It implements `-00`
and shells out to `openssl verify`, which `-03` makes refuse every agent
certificate on purpose. Asking it to accept `-03` artifacts would be asking the
wrong question.

Things `openssl verify -ignore_critical` **accepts** that this validator refuses,
each generated by the fixture script and asserted both ways:

| Certificate | `openssl verify -ignore_critical` | here |
|---|---|---|
| leaf asserting `basicConstraints CA:TRUE` | `OK` | `ERR_BASIC_CONSTRAINTS` |
| leaf signed `ecdsa-with-SHA1` | `OK` | `ERR_WEAK_SIGNATURE` |
| leaf with no `basicConstraints` at all | `OK` | `ERR_BASIC_CONSTRAINTS` |
| leaf asserting `keyCertSign` | `OK` | `ERR_KEY_USAGE` |
| RSA-2048 key | `OK` | `ERR_KEY_TOO_SMALL` |
| one-octet serial number | `OK` | `ERR_SERIAL_ENTROPY` |
| no `cRLDistributionPoints`, no OCSP | `OK` | `ERR_NO_REVOCATION_SOURCE` |
| ordinary client cert, no Agent Template extension | `OK` | `ERR_TEMPLATE_EXT_MISSING` |
| extension carrying valid JSON that is not JCS | `OK` | `ERR_TEMPLATE_EXT_INVALID` |
| one-day certificate whose template says `ttl_seconds: 900` | `OK` | `ERR_VALIDITY_EXCEEDS_TTL` |

`openssl verify` answers *was this issued by the CA*. It is not asking whether
the certificate is entitled to be used the way it is being used.

---

## Scope

Things this deliberately is not, so they are not mistaken for oversights:

| | |
|---|---|
| **One Registry** | The page mints one CA and one Owner / Policy Authority pair, and plays the grantor's authorities too when a spawn crosses organizations — the "federated CA" option of §13.3. |
| **In-memory revocation** | The CRL and the Registry's DISABLED list are fields in the document. Every leaf carries a `cRLDistributionPoints` pointing at a `.invalid` host (§14.4), honest that there is no live CRL. |
| **Not an interoperability test** | It exercises one implementation of the draft. What the draft actually needs is an *independent* one — which is what this repository is for. |
| **Self-assigned OIDs** | The two profile extensions and the demo notice use OIDs under the `2.25` UUID arc, which is self-assigning: `2.25.` followed by the decimal form of a UUID. That gives them the collision probability of the UUID itself and no more (§17.1). |

---

## A note on the draft revision

This implements and is verified against **`-03`**, at tag `impl/draft-03`. The
`-02` implementation stays retrievable at tag `impl/draft-02`.

`-02` and `-03` both exist because of this repository. Implementing `-01` found
an exploitable replay in both existing implementations; implementing `-02`
found that one specification had produced three implementations with three
different answers — a JSON sidecar, per-field extensions, and two incompatible
canonicalizations — and one bug of this playground's own: its Owner signature
covered the certificate's identity fields rather than the policy body, so a
valid Owner signature was identical for every later policy on that agent. `-03`
specifies the wire encoding, the envelope, the certificate extensions, the
attestation flow, the freshness window and the signature algorithms, so that
cannot happen again.

**Reference implementations stay locked to the revision they were verified
against.** [`ietf-a2a-trust-poc`](https://github.com/tonyt68/ietf-a2a-trust-poc)
and [`hack-my-own-code`](https://github.com/tonyt68/hack-my-own-code) implement
`-00`, say `-00`, and are tagged `impl/draft-00`. A version string is a
conformance claim, and it moves when someone re-reads the revision and re-runs
the vectors, not when a newer number exists.

## Where to send what

Feedback takes two routes, because a spec bug and a code bug are different things:

- **The tool refuses something the draft permits, or permits something it
  forbids** → open a [GitHub issue](https://github.com/tonyt68/a2a-trust-playground/issues).
  That is an implementation bug.
- **The draft is ambiguous, contradictory, or unimplementable** → the IETF
  list, or the [datatracker](https://datatracker.ietf.org/doc/draft-tonyai-a2a-trust/).
  That is a spec bug, and it becomes the next revision.
- **You built your own implementation and it disagrees with this one** → say so
  on the list. Two implementations disagreeing is the most useful thing anyone
  can report; it is what produced `-02` and `-03`.

## Licence

Apache 2.0. See [LICENSE](LICENSE).

Built by [PhalanxAI Security](https://phalanxaisec.com).
