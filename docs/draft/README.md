# The draft this playground implements

`draft-tonyai-a2a-trust-03` — the revision [../../src](../../src) validates against.

| file | what it is |
|---|---|
| `draft-tonyai-a2a-trust-03.xml` | xml2rfc v3 source, as submitted |
| `draft-tonyai-a2a-trust-03.txt` | the rendered text, as published |
| `draft-tonyai-a2a-trust-02.xml`, `.txt` | the previous revision, kept so the `impl/draft-02` tag stays readable beside the text it implemented |

The `-03` pair is byte-identical to what the IETF archive serves once the
submission is posted:

- <https://www.ietf.org/archive/id/draft-tonyai-a2a-trust-03.xml>
- <https://www.ietf.org/archive/id/draft-tonyai-a2a-trust-03.txt>
- <https://datatracker.ietf.org/doc/draft-tonyai-a2a-trust/03/>

They are checked in rather than fetched because
[`tests/citations.test.js`](../../tests/citations.test.js) reads them. Every
clause the page cites is verified to exist in this text **and to still carry the
title the citing code means** — the number alone is not enough. `-02` inserted
sections, which renumbered everything after them, and `ERR_AUDIT_CHAIN_BROKEN`
went on citing §16.6 after that section had become "PKI Does Not Enforce
Authorization" rather than "Audit Integrity". It resolved, so it looked correct.
`-03` did it again on a larger scale: Document Encoding became §3 and pushed
every later section down, and the title check caught every one.

**On updating.** Replacing these with a newer revision is not a file swap. The
citation test will fail for every clause whose section moved, which is the point;
work through the failures rather than re-pointing the test at whatever the new
numbers happen to be. A version string is a conformance claim, so the code should
only say `-04` once someone has re-read `-04` and re-run the vectors.
