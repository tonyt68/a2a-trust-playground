# The draft this playground implements

`draft-tonyai-a2a-trust-02` — the revision [../../src](../../src) validates against.

| file | what it is |
|---|---|
| `draft-tonyai-a2a-trust-02.xml` | xml2rfc v3 source, as submitted |
| `draft-tonyai-a2a-trust-02.txt` | the rendered text, as published |

Both are byte-identical to what the IETF archive serves:

- <https://www.ietf.org/archive/id/draft-tonyai-a2a-trust-02.xml>
- <https://www.ietf.org/archive/id/draft-tonyai-a2a-trust-02.txt>
- <https://datatracker.ietf.org/doc/draft-tonyai-a2a-trust/02/>

They are checked in rather than fetched because
[`tests/citations.test.js`](../../tests/citations.test.js) reads them. Every
clause the page cites is verified to exist in this text **and to still carry the
title the citing code means** — the number alone is not enough. `-02` inserted
sections, which renumbered everything after them, and `ERR_AUDIT_CHAIN_BROKEN`
went on citing §16.6 after that section had become "PKI Does Not Enforce
Authorization" rather than "Audit Integrity". It resolved, so it looked correct.

**On updating.** Replacing these with a newer revision is not a file swap. The
citation test will fail for every clause whose section moved, which is the point;
work through the failures rather than re-pointing the test at whatever the new
numbers happen to be. A version string is a conformance claim, so the code should
only say `-03` once someone has re-read `-03` and re-run the vectors.
