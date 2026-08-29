# A2A Trust Playground

A browser implementation of
[`draft-tonyai-a2a-trust-02`](https://datatracker.ietf.org/doc/draft-tonyai-a2a-trust/) —
an IETF Internet-Draft on agent-to-agent trust: identity, spawn authorization,
scope delegation, dual-signed policy governance, revocation and audit integrity.

**[Try it → phalanxaisec.com/a2a](https://phalanxaisec.com/a2a)**

Mint an agent identity, delegate a narrower one to a child, then try to widen it
and watch the chain refuse — citing the clause of the draft that refused it. No
install, no account, no API key, and nothing transmitted: every key is generated
in your tab by Web Crypto and is gone when you refresh.

---

## Why this exists

The draft already has a reference implementation
([`ietf-a2a-trust-poc`](https://github.com/tonyt68/ietf-a2a-trust-poc)) and an
adversarial one that attacks its own implementation
([`hack-my-own-code`](https://github.com/tonyt68/hack-my-own-code)). Both need
Docker, and one needs an API key. So the barrier to being the draft's *second
implementer* has been "read the spec and build a CA from scratch."

A draft moves when someone else implements it. This lowers that barrier two ways:

- **Anyone can use the model in sixty seconds** without installing anything.
- **The validation logic is readable.** Every check is a small module with the
  clause it enforces in the comment, and a test that proves it.

If you are here to build implementation #3, start with
[`src/pipeline.js`](src/pipeline.js) and follow it outward.

---

## What it demonstrates

The interesting part of this draft is not that a certificate chain verifies.
It is the **two-lane model** in §9.1: the template certificate is the guardrail
(*who the agent is, who it may spawn* — changing it requires re-certification),
and dynamic policy is the fast lane (*what it may do, within the certificate's
bounds* — changing it requires two signatures).

Those two lanes produce a result most people find surprising, and the page is
built to show it:

> A policy update carries two valid signatures from two independent keys. The
> content hash matches. The submitter is the verified owner. **It is still
> refused**, because it grants a scope beyond the certificate's ceiling.
>
> `ERR_POLICY_EXCEEDS_TEMPLATE · §7.2`

Two valid signatures authorise a change. They do not raise the ceiling. §9.3
answers *who approved this*; §7.2 answers *was it within bounds* — and only the
first has a cryptographic component, which is exactly why it is easy to assume
the signatures covered both.

The page has buttons for changes the draft **permits** as well as ones it
refuses, because a wall with no door teaches nothing about where the door is.
Narrow a scope and the chain stays valid; widen it and it does not.

---

## How validation works

Each run walks the chain **subject by subject**, stopping at the first refusal:

```
TRUST ANCHOR › PARENT AGENT › CHILD AGENT › DELEGATION › POLICY UPDATE › AUDIT CHAIN
```

Underneath, that is nine ordered checks ported from the reference
implementation's `services/mcp_server/`:

| # | Check | Clause | Module |
|---|---|---|---|
| 1 | Agent id format (strict UUID4) | hardening | [validate-input.js](src/validate-input.js) |
| 2 | X.509 chain, certificate profile, validity, state | §6, §6.3, §10.4 | [x509.js](src/x509.js) |
| 3 | Revocation, disablement, TTL | §12 | [bounds.js](src/bounds.js) |
| 4 | Dual-signature validation over the JCS canonical form | §9.3, §9.5, §9.6 | [policy.js](src/policy.js) |
| 5 | Policy field guard — the §9.4 field set is complete | §9.4, §7.1 | [policy.js](src/policy.js) |
| 6 | Required fields, version currency, content hash | §9.4, §9.6 | [policy.js](src/policy.js) |
| 7 | Authorization bounds, spawn rule, template ceiling | §7, §7.2, §8.1 | [bounds.js](src/bounds.js) |
| 8 | Scope containment, fail-closed | §8.3 | [bounds.js](src/bounds.js) |
| 9 | Audit hash chain over the same canonical form | §9.5, §16.6 | [audit-chain.js](src/audit-chain.js) |

Any failure is a DENY carrying an error code and the governing clause. The
`stages` array in the exported JSON *is* the decision log the UI renders, so the
log and the export cannot disagree.

**Two checks are not implemented**, and the page says so inline where each would
have run rather than burying it:

- **§16.2 replay prevention** — needs a nonce store and a request lifecycle.
- **§9 Cedar policy evaluation** — needs a policy engine. Static bounds only.

---

## Two things worth reading the source for

**Canonicalization** ([src/canonical.js](src/canonical.js)). The dual signature
is computed over a canonical serialization, and `-02` §9.5 specifies exactly one:
**JCS, [RFC 8785](https://www.rfc-editor.org/info/rfc8785)**.

That is a change, and the reason is worth reading. `-01` specified no
canonicalization at all — so the only way to implement its dual signature was to
read the reference implementation's Python and reproduce
`json.dumps(sort_keys=True, separators=(',',':'))` byte for byte, including
`ensure_ascii` escaping and code-point key ordering that JavaScript does not do
natively. A signature is over bytes; a spec that does not say how the bytes are
produced cannot be implemented twice.

Citing an existing RFC rather than describing a bespoke scheme also made this
file **shorter**: JCS sorts by UTF-16 code unit, which is JavaScript's native
ordering, and emits raw UTF-8, which is what `JSON.stringify` already produces.
The custom comparator and escape table that existed only to imitate Python are
deleted rather than ported. `-01`'s implementation carried *two* serializations —
compact for signatures, spaced for audit hashes — because the reference
implementation called `json.dumps` two different ways in two different files.
§9.5 specifies one form for both.

Verified against 15 vectors transcribed from RFC 8785 and 6 differential vectors
computed by Python, with the one case where the two schemes legitimately
disagree (astral-plane key ordering) asserted against the RFC only — and the
generator refusing to emit a Python answer for it.

**The demo-only certificate profile** ([src/mint.js](src/mint.js)). Generated
certificates are **valid, untrusted and constrained** — three different things:

- **Valid** — genuinely well-formed X.509; `openssl verify` returns `OK`. That
  is deliberate: parity with the reference implementation depends on these being
  real certificates.
- **Untrusted** — the CA is generated in your tab and is in nobody's trust store.
- **Constrained** — a critical `nameConstraints` extension means the CA is
  structurally incapable of issuing for any name that does not say
  `OU=DEMO ONLY - NOT FOR PRODUCTION`. Ask it to sign
  `CN=login.bank.example.com` and every conformant validator refuses the result
  with `error 47: permitted subtree violation`.

The obvious alternative — a *critical unrecognised* extension saying "demo only"
— was tried and rejected. RFC 5280 §4.2 requires rejecting a critical extension
you do not recognise, which makes the certificate unusable to **every** validator
including `openssl verify`, and therefore breaks the round-trip proof. The
guarantee had to move into an extension validators actually implement.

---

## Running it

```bash
pnpm install
pnpm dev      # http://127.0.0.1:5173 — hot bundle, no build step
pnpm test     # 472 unit tests
pnpm e2e      # 150 assertions against the built file, offline
pnpm build    # dist/a2a.html — one self-contained file
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
script by SHA-256 hash. Alter one byte of it — a rogue browser extension
injecting into the page context, malware editing a saved copy, a proxy rewriting
it in flight — and the browser refuses to execute the script at all. Measured: 17
injected bytes and the app does not load, with `Refused to execute` in the
console. There is no degraded mode where a modified page runs anyway.

**You can verify it yourself, out of band.** Every build publishes its own
digest:

```bash
shasum -a 256 -c a2a.html.sha256      # a2a.html: OK
```

Compare that against the digest for the matching commit in this repository. This
is the check that matters against a compromised machine, because a sufficiently
privileged local attacker could replace both the file and its CSP hash together —
only an independent comparison catches that.

**What this does not defend against.** A browser extension's content script runs
in an isolated world and is not subject to the page's CSP, so it can still read
the DOM. It cannot inject executable code into the page's own context — that
path is blocked — but it can observe. No page-level control fixes that; running
the saved file in a clean profile does.

## Testing

472 unit tests and 150 end-to-end assertions. The two that matter most are **differential**:

- **Conformance to RFC 8785, not to another codebase.** The canonicalization
  oracle is the RFC, with Python used as an independent second implementation
  only where the two schemes provably agree. The previous oracle was the
  reference implementation's own `json.dumps` output, which proved agreement
  with one program rather than with a specification — the exact circularity
  `-02` §9.5 exists to remove.
- **Differential against OpenSSL.** Certificate fixtures are built by OpenSSL,
  not by this code — a validator tested only against certificates it produced
  itself proves that two copies of one bug agree. Fingerprints, DER length,
  serial, validity, key size, DN ordering and every extension are compared
  against `openssl x509` for the same bytes.

Signatures produced here are **byte-identical** to `openssl dgst -sha256 -sign`,
and OpenSSL reports `Verified OK` on them. PKCS#1 v1.5 is deterministic, so that
is a complete proof of both the canonicalization and the algorithm choice.

The round-trip harness (`pnpm test:roundtrip`) checks the two layers with two
different oracles, because they need different ones. **Certificates and spawn
rules** are validated by `ietf-a2a-trust-poc`'s own Python, unmodified — X.509
identity is unchanged between `-00` and `-02`, so that implementation is still
the right authority. **Signatures and hashes** are validated by OpenSSL against
a canonical form this harness recomputes independently, because the reference
implementation implements `-00`, whose field set and serialization differ, and
asking it to validate `-02` artifacts would be asking the wrong question.

Certificates minted in the browser verify under `openssl verify`, and the browser
validator refuses everything OpenSSL refuses — including name-constraint
violations and unrecognised critical extensions.

It also refuses three things `openssl verify` **accepts**, which is the more
interesting direction. The fixture generator asserts that all three return `OK`
from `openssl verify -CAfile ca-root.crt`, so the distinction is checked rather
than claimed:

| Certificate | `openssl verify` | here |
|---|---|---|
| leaf asserting `basicConstraints CA:TRUE` | `OK` | `ERR_BASIC_CONSTRAINTS` |
| leaf signed `sha1WithRSAEncryption` | `OK` | `ERR_WEAK_SIGNATURE` |
| leaf with no `basicConstraints` at all | `OK` | `ERR_BASIC_CONSTRAINTS` |

`openssl verify` answers *was this issued by the CA*. It is not asking whether
the certificate is entitled to be used the way it is being used, and for the
first row the answer matters a great deal: an agent whose certificate says
`CA:TRUE` can issue its own children, so §8.1's spawn rule and §8.3's scope
constraint stop being enforceable — the agent no longer has to ask. No signature
is broken anywhere in that attack.

---

## Scope

Things this deliberately is not, so they are not mistaken for oversights:

| | |
|---|---|
| **Single trust anchor** | §11 cross-organisational federation needs two organisations. A single page has one. |
| **In-memory CRL** | An architecture choice for a page with no backend, not a missing revocation service. |
| **Not an interoperability test** | It exercises one implementation of the draft. What the draft actually needs is an *independent* one — which is what this repository is for. |
| **Placeholder OID** | The demo notice uses a self-assigned OID under the `2.25` UUID arc, which is collision-free by construction, until an IANA Private Enterprise Number is issued. |

---

## A note on the draft revision

This implements and is verified against **`-02`**.

`-02` exists because of this repository. Building a second, independent
implementation of `-01` and attacking it surfaced six things the text did not
say enough about, including one that was **exploitable in both existing
implementations**: `-01` listed the policy version as a value stored *alongside*
the signature and never required the signature to *cover* it, so an attacker
holding no key could take a superseded but validly signed policy, increment one
integer, and have it accepted. Both signatures verified, the content hash
matched, and the version read as current. Neither implementation signed the
version, because neither had been told to.

**Reference implementations stay locked to the revision they were verified
against.** [`ietf-a2a-trust-poc`](https://github.com/tonyt68/ietf-a2a-trust-poc)
and [`hack-my-own-code`](https://github.com/tonyt68/hack-my-own-code) implement
`-00` and continue to say `-00`. That is not drift and it is not neglect: a
version string is a conformance claim, and it moves when someone re-reads the
revision and re-runs the vectors, not when a newer number exists. An
implementation pinned to an older revision remains a correct implementation of
that revision.

The practical consequence is visible in the round-trip harness above, which uses
the reference implementation as an oracle for the layer the revisions share
(X.509 identity) and an external one for the layer they do not (signatures and
hashes over the canonical form).

## Licence

Apache 2.0. See [LICENSE](LICENSE).

Feedback on the draft itself is welcome via the
[IETF datatracker](https://datatracker.ietf.org/doc/draft-tonyai-a2a-trust/).
Independent implementations are the thing the draft most needs.

Built by [PhalanxAI Security](https://phalanxaisec.com).
