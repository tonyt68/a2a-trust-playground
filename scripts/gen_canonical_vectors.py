#!/usr/bin/env python3
"""
Generate canonicalization ground truth for RFC 8785 (JCS).

── Why this file changed shape ────────────────────────────────────────────────

It used to import the reference implementation's IDENTITY_FIELDS / POLICY_FIELDS
and re-run its exact `json.dumps` calls, because `draft-tonyai-a2a-trust-01`
specified no canonicalization and the only available ground truth was one
codebase's behaviour. That is a circular oracle: it proves the browser agrees
with a particular Python program, not that either agrees with a specification.

`-03` §3 and §11.5 normatively specify JCS (RFC 8785), so the ground truth is now the
RFC. Two independent sources are used, and the distinction between them matters:

  1. NORMATIVE vectors, transcribed from RFC 8785 itself. These are the
     authority. Where Python and the RFC disagree, the RFC wins.

  2. DIFFERENTIAL vectors, produced by Python's own serializer configured to
     match JCS. This is a genuinely independent implementation in another
     language, which is what makes it worth having — but it is an oracle only
     within the range where the two agree, and that range has a hard edge:

       * `ensure_ascii=False` matches JCS's raw-UTF-8 output.
       * `separators=(',', ':')` matches JCS's no-whitespace rule.
       * `sort_keys=True` sorts by Unicode CODE POINT. JCS §3.2.3 sorts by
         UTF-16 CODE UNIT. These agree for the entire BMP and DISAGREE above
         it — U+1F510 sorts before U+FFFD under JCS and after it in Python.

     So astral-plane key ordering is deliberately excluded from the differential
     set and asserted against the RFC instead. Generating it here would bake a
     wrong answer into the fixture with a Python program to vouch for it.

Run: pnpm vectors
"""

import json
from pathlib import Path

OUT = Path(__file__).parent.parent / "tests" / "fixtures" / "canonical_vectors.json"


def jcs_via_python(o):
    """
    Python's serializer configured to produce JCS output.

    Valid as a differential oracle only for BMP keys — see the module docstring.
    """
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


# ── Normative — transcribed from RFC 8785 ────────────────────────────────────
# The authority. Python is not consulted for these.
NORMATIVE = [
    ("empty object", {}, "{}"),
    ("empty array value", {"a": []}, '{"a":[]}'),
    ("keys sorted, not insertion order", {"b": 2, "a": 1}, '{"a":1,"b":2}'),
    ("array order is preserved, never sorted", {"a": [3, 1, 2]}, '{"a":[3,1,2]}'),
    ("null and booleans", {"n": None, "t": True, "f": False},
     '{"f":false,"n":null,"t":true}'),
    ("integers including zero and negative", {"z": 0, "n": -17, "p": 42},
     '{"n":-17,"p":42,"z":0}'),
    # JCS emits raw UTF-8. The old Python-parity form escaped these as \\uXXXX,
    # which is the single most visible difference between the two schemes.
    ("non-ASCII in a value stays raw UTF-8", {"k": "café"}, '{"k":"café"}'),
    ("non-ASCII in a key stays raw UTF-8", {"é": 1}, '{"é":1}'),
    ("only JSON-mandated escapes", {"q": 'a"b\\c'}, '{"q":"a\\"b\\\\c"}'),
    ("control characters use the short escapes", {"c": "\t\n\r"}, '{"c":"\\t\\n\\r"}'),
    ("other control characters use \\u form", {"c": ""}, '{"c":"\\u0001"}'),
    ("forward slash is not escaped", {"u": "a/b"}, '{"u":"a/b"}'),
    ("BMP key ordering", {"€": 1, "$": 2, "¢": 3}, '{"$":2,"¢":3,"€":1}'),
    # RFC 8785 §3.2.3 — UTF-16 code unit order. Python's sort_keys disagrees
    # here, which is exactly why this row is normative and not differential.
    ("astral key ordering is by UTF-16 code unit",
     {"\U0001F510": 1, "�": 2}, '{"\U0001F510":1,"�":2}'),
    ("nested object and array",
     {"o": {"b": 1, "a": 2}, "l": [1, {"d": 4, "c": 3}]},
     '{"l":[1,{"c":3,"d":4}],"o":{"a":2,"b":1}}'),
]

# ── Differential — Python computes these ─────────────────────────────────────
# Realistic documents in this profile. BMP keys only, so Python is a valid
# oracle; the point is that a serializer written in another language, by other
# people, produces the same bytes.
DIFFERENTIAL = [
        ("a complete -03 policy document (§11.4)", {
        "subject": "c669186f-a84b-4d7a-81f3-05880df87114",
        "owner": "owner-authority",
        "org_id": "playground-org",
        "scopes": ["read:events"],
        "version": 2,
        "issued_at": "2026-09-03T00:00:00.000Z",
    }),
    ("a policy carrying the optional fields", {
        "subject": "c669186f-a84b-4d7a-81f3-05880df87114",
        "owner": "owner-authority",
        "org_id": "playground-org",
        "scopes": ["read:events", "write:events"],
        "spawn_targets": ["8f14e45f-ceea-467a-9c0f-7ad0f1b0d5aa"],
        "version": 7,
        "issued_at": "2026-09-03T00:00:00.000Z",
        "not_after": "2026-09-04T00:00:00.000Z",
    }),
    ("an Agent Template extension body (§8.2 Table 5)", {
        "subject": "8f14e45f-ceea-467a-9c0f-7ad0f1b0d5aa",
        "owner": "owner-authority",
        "org_id": "playground-org",
        "permitted_operations": ["spawn", "read"],
        "allowed_scopes": ["read:events", "write:events"],
        "can_spawn": ["c669186f-a84b-4d7a-81f3-05880df87114"],
        "max_children": 2,
        "policy_ref": "policy-store/8f14e45f-ceea-467a-9c0f-7ad0f1b0d5aa/current",
        "ttl_seconds": 86400,
    }),
    ("an Agent Spawn extension body (§10.5 Table 6)", {
        "parent_agent_id": "8f14e45f-ceea-467a-9c0f-7ad0f1b0d5aa",
        "spawned_at": "2026-09-03T00:00:00Z",
        "spawn_nonce": "AAAAAAAAAAAAAAAAAAAAAA==",
    }),
    ("a cross-organizational grant body (§13.2 Table 10)", {
        "grantor": "partner-org",
        "grantee": "playground-org",
        "template": "c669186f-a84b-4d7a-81f3-05880df87114",
        "allowed_scopes": ["read:events"],
        "issued_at": "2026-09-03T00:00:00.000Z",
        "ttl_seconds": 3600,
        "max_spawns": 3,
    }),
    ("an audit chain entry", {
        "index": 0,
        "previous_hash": "0" * 64,
        "decision": "ALLOWED",
        "timestamp": "2026-09-03T00:00:00.000Z",
    }),
    ("unicode in ordinary values", {"owner": "José", "note": "naïve café"}),
    ("keys needing escapes", {'a"b': 1, "c\\d": 2, "e\tf": 3}),
]

vectors = []
for name, value, expected in NORMATIVE:
    vectors.append({"name": name, "source": "RFC 8785", "value": value,
                    "expected": expected})
for name, value in DIFFERENTIAL:
    vectors.append({"name": name, "source": "python-differential", "value": value,
                    "expected": jcs_via_python(value)})

# Self-check: every normative row Python CAN reproduce, it must — otherwise one
# of the two transcriptions is wrong and the fixture would ship the error.
mismatches = []
for row in vectors:
    if row["source"] != "RFC 8785":
        continue
    # Skip rows containing an astral key — the one place the two schemes are
    # SUPPOSED to disagree. Detected by scanning the keys themselves; checking
    # json.dumps output would miss it, because the default escapes the character
    # into a surrogate pair and the literal is then never found.
    if any(ord(ch) > 0xFFFF for k in row["value"] for ch in str(k)):
        continue
    if jcs_via_python(row["value"]) != row["expected"]:
        mismatches.append(row["name"])

if mismatches:
    raise SystemExit(
        "Python disagrees with the transcribed RFC vectors on rows where the two "
        "schemes should agree — one of them is wrong:\n  " + "\n  ".join(mismatches))

OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_text(json.dumps(vectors, indent=2, ensure_ascii=False) + "\n")
print(f"{len(vectors)} vectors written to {OUT.relative_to(Path.cwd())}")
print(f"  {sum(1 for v in vectors if v['source'] == 'RFC 8785')} normative (RFC 8785)")
print(f"  {sum(1 for v in vectors if v['source'] != 'RFC 8785')} differential (Python)")
print("Python agrees with every normative row it is capable of reproducing.")
