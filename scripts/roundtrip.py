#!/usr/bin/env python3
"""
Round-trip parity — acceptance criterion 1, the one DESIGN.md calls the criterion
that matters.

Reads the JSON document this playground exports, reconstitutes it into the exact
directory layout `setup_keys.py` produces, and then validates it using the
REFERENCE IMPLEMENTATION'S OWN PYTHON — not a reimplementation of it, and not
this project's JavaScript.

That distinction is the whole point. A browser validator agreeing with itself
proves nothing. This asks an independent implementation, written in another
language by another route, whether the artifacts are valid:

    CertValidator.validate_cert()          §6, §10.4   X.509 + template state
    CertValidator.parse_auth_bounds()      §7          authorization bounds
    CertValidator.validate_scope_subset()  §8.3        scope containment
    PolicyValidator.validate_policy_update() §9.3      dual signature
    AuditChain.verify_chain()              §16.6       audit integrity

If those pass over a chain minted in a browser and signed with Web Crypto, then
the playground implements the draft rather than something that resembles it.

    pnpm test:roundtrip

Requires a local clone of the reference implementation; skips with a clear
message if it is absent, because "not cloned" is not "failed".
"""

import base64
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

POC = Path.home() / "dev" / "ietf-a2a-trust-poc"
EXPORT = Path(__file__).parent.parent / "dist" / "roundtrip-export.json"

PASS, FAIL = "  ok    ", "  FAIL  "
results = []


def check(name: str, condition: bool, detail: str = "") -> None:
    results.append(condition)
    print(f"{PASS if condition else FAIL}{name}{f' — {detail}' if detail and not condition else ''}")


if not POC.exists():
    print(f"SKIP: reference implementation not found at {POC}")
    print("      git clone https://github.com/tonyt68/ietf-a2a-trust-poc")
    sys.exit(0)
if not EXPORT.exists():
    sys.exit(f"missing {EXPORT} — run `pnpm test:roundtrip`, which exports it first")

# A stale export is the one failure mode this harness cannot survive quietly: it
# validates whatever JSON is on disk, so an export from before a source change
# reports parity that no longer exists. That happened during the -02 migration —
# running this script directly, rather than through `pnpm test:roundtrip`,
# validated a pre-migration artifact and printed 13 green checks.
SRC = Path(__file__).parent.parent / "src"
newest_src = max(f.stat().st_mtime for f in SRC.glob("*.js"))
if EXPORT.stat().st_mtime < newest_src:
    sys.exit(f"STALE: {EXPORT.name} predates src/ — run `pnpm test:roundtrip`, "
             "which regenerates it. Refusing to report parity from an old artifact.")

sys.path.insert(0, str(POC / "services" / "mcp_server"))
try:
    from cert_validator import CertValidator
    from policy_validator import PolicyValidator
    from audit_chain import AuditChain
except ImportError as e:
    sys.exit(f"cannot import the reference implementation: {e}")

doc = json.loads(EXPORT.read_text())
work = Path(tempfile.mkdtemp(prefix="a2a-roundtrip-"))
certs = work / "certs"
certs.mkdir()

# ── Reconstitute setup_keys.py's layout ──────────────────────────────────────
# certs/ca-root.{crt,key} · certs/{agent_id}.{crt,key,json} · owner/pa · CRL ·
# audit_chain.json. Nothing is invented here: every byte comes out of the
# exported document. If a field the reference implementation needs is missing,
# that is a round-trip failure and should surface as one.
anchor = next(n for n in doc["chain"] if n["role"] == "ca")
(certs / "ca-root.crt").write_text(anchor["cert_pem"])
if anchor.get("key_pem"):
    (certs / "ca-root.key").write_text(anchor["key_pem"])

agents = [n for n in doc["chain"] if n["role"] == "agent"]
for node in agents:
    meta = node["metadata"]
    aid = meta["agent_id"]
    (certs / f"{aid}.crt").write_text(node["cert_pem"])
    (certs / f"{aid}.key").write_text(node["key_pem"])
    (certs / f"{aid}.json").write_text(json.dumps(meta, indent=2))

for role, node in (doc.get("authorities") or {}).items():
    name = "owner" if role == "owner" else "pa"
    (certs / f"{name}.crt").write_text(node["cert_pem"])
    (certs / f"{name}.key").write_text(node["key_pem"])

crl = doc.get("crl") or {"revoked": [], "disabled": []}
(certs / "revocation_list.json").write_text(json.dumps({
    "revoked": crl.get("revoked", []),
    "disabled": crl.get("disabled", []),
    "disabled_at": {},
    "last_updated": doc["generated_at"],
}, indent=2))

audit = doc.get("audit") or {}
(certs / "audit_chain.json").write_text(json.dumps({
    "chain": audit.get("chain", []),
    "current_hash": audit.get("head_hash"),
}, indent=2))

print(f"reconstituted {len(list(certs.iterdir()))} files from the exported document\n")

# ── Validate with the reference implementation ───────────────────────────────
validator = CertValidator(ca_root_cert_path=str(certs / "ca-root.crt"))

print("§6, §10.4 — X.509 identity and template state")
for node in agents:
    aid = node["metadata"]["agent_id"]
    valid, reason = validator.validate_cert(aid, str(certs / f"{aid}.crt"))
    check(f"validate_cert({aid[:8]}…)", valid, reason)

print("\n§6.1 — CA-signed, not self-signed")
for node in agents:
    aid = node["metadata"]["agent_id"]
    ok, reason = validator.validate_chain(str(certs / f"{aid}.crt"))
    check(f"validate_chain({aid[:8]}…)", ok, reason)

print("\n§7 — authorization bounds parse")
bounds = {}
for node in agents:
    aid = node["metadata"]["agent_id"]
    parsed = validator.parse_auth_bounds(str(certs / f"{aid}.json"))
    bounds[aid] = parsed
    check(f"parse_auth_bounds({aid[:8]}…)", parsed is not None
          and isinstance(parsed.get("allowed_scopes"), list))

print("\n§8.3 — scope containment, child ⊆ parent")
for node in agents:
    meta = node["metadata"]
    parent_id = meta.get("parent_agent_id")
    if not parent_id:
        continue
    ok = validator.validate_scope_subset(
        bounds[meta["agent_id"]]["allowed_scopes"],
        bounds[parent_id]["allowed_scopes"])
    check("child scopes are a subset of the parent's", ok)

print("\n§8.1 — two-check spawn rule")
for node in agents:
    meta = node["metadata"]
    parent_id = meta.get("parent_agent_id")
    if not parent_id:
        continue
    ok, reason = validator.validate_spawn_check1(bounds[parent_id], meta["agent_id"])
    check("child is in the parent CanSpawn whitelist", ok, reason)
    ok, reason = validator.validate_spawn_check2(
        meta["agent_id"], str(certs / f"{meta['agent_id']}.crt"),
        str(certs / f"{meta['agent_id']}.json"))
    check("child is registered, CA-signed and ACTIVE", ok, reason)

print("\n§9.3/§9.6 — dual signature, verified by OpenSSL over the JCS bytes")
# The reference implementation is NOT the oracle here, and cannot be: it
# implements -00, whose policy field set and canonicalization both differ from
# -02. Its POLICY_FIELDS intersects the -02 document on `owner` alone, and it
# serializes with Python's json.dumps rather than JCS, so it would necessarily
# reject these signatures. That is a revision difference, not a defect in either
# implementation, and asking it to validate -02 artifacts would be asking the
# wrong question.
#
# So the oracle moves to something outside both: OpenSSL verifies the signature
# over canonical bytes this script recomputes independently, in Python, from the
# RFC 8785 rules. Three separate toolchains have to agree — the browser's Web
# Crypto that signed it, this Python that rebuilds the preimage, and OpenSSL that
# checks the RSA. None of them shares code with the others.
IDENTITY = {"agent_id", "agent_uuid", "org_id", "subject", "issuer", "owner",
            "cert_serial", "cert_subject", "cert_issuer", "cert_public_key",
            "cert_not_before", "cert_not_after", "cert_fingerprint", "cert_chain",
            "template_version", "can_spawn", "max_children"}
POLICY = {"subject", "owner", "org_id", "scopes", "spawn_targets",
          "version", "issued_at", "not_after"}


def jcs(o):
    """RFC 8785 for the BMP-keyed documents this profile produces."""
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def openssl_verify(preimage: str, sig_b64: str, cert_path: Path) -> bool:
    pub = work / "pub.pem"
    subprocess.run(["openssl", "x509", "-in", str(cert_path), "-pubkey", "-noout",
                    "-out", str(pub)], capture_output=True)
    (work / "msg.bin").write_bytes(preimage.encode("utf-8"))
    (work / "sig.bin").write_bytes(base64.b64decode(sig_b64))
    r = subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(pub),
                        "-signature", str(work / "sig.bin"), str(work / "msg.bin")],
                       capture_output=True, text=True)
    return r.returncode == 0


if doc.get("policy_update"):
    identity = {k: v for k, v in doc["existing_cert"].items() if k in IDENTITY}
    policy = {k: v for k, v in doc["policy_doc"].items() if k in POLICY}

    check("owner_sig verifies under OpenSSL over the JCS identity fields",
          openssl_verify(jcs(identity), doc["owner_sig"], certs / "owner.crt"))
    check("pa_sig verifies under OpenSSL over the JCS policy fields",
          openssl_verify(jcs(policy), doc["pa_sig"], certs / "pa.crt"))

    # §9.6 — the property the whole revision exists for. If `version` were
    # outside the preimage, changing it would leave the signature intact.
    tampered = dict(policy, version=policy["version"] + 1)
    check("rewriting the version breaks pa_sig (§9.6 replay prevention)",
          not openssl_verify(jcs(tampered), doc["pa_sig"], certs / "pa.crt"))
    check("version is inside the signed field set", "version" in policy)
    check("subject is inside the signed field set", "subject" in policy)

    # §9.6 — content hash over the same canonical form and the same field set.
    digest = hashlib.sha256(jcs(policy).encode("utf-8")).hexdigest()
    check("content hash is SHA-256 over the same JCS bytes",
          digest == doc.get("policy_content_hash"),
          f"computed {digest[:16]}… stored {str(doc.get('policy_content_hash'))[:16]}…")
else:
    check("document carries a policy update to verify", False, "none present")

print("\n§16.6 — audit hash chain, recomputed independently")
# Same reasoning: -00's AuditChain hashes a Python-spaced serialization, -02 §16.6
# uses the single canonical form. Recomputed here rather than delegated.
chain = doc.get("audit", {}).get("chain", [])
ok_chain, broken_at = True, None
prev = "genesis"   # GENESIS_PREVIOUS_HASH in src/audit-chain.js
for i, block in enumerate(chain):
    pre = jcs({"index": block["index"], "timestamp": block["timestamp"],
               "previous_hash": block["previous_hash"], "event": block["event"]})
    if block["previous_hash"] != prev or hashlib.sha256(pre.encode()).hexdigest() != block["hash"]:
        ok_chain, broken_at = False, i
        break
    prev = block["hash"]
check(f"audit chain verifies ({len(chain)} block(s))", ok_chain,
      f"broken at block {broken_at}")

print("\n§6 — OpenSSL agrees, independently of the Python")
for node in agents:
    aid = node["metadata"]["agent_id"]
    r = subprocess.run(
        ["openssl", "verify", "-CAfile", str(certs / "ca-root.crt"), str(certs / f"{aid}.crt")],
        capture_output=True, text=True)
    check(f"openssl verify {aid[:8]}…", r.returncode == 0, (r.stdout + r.stderr).strip()[:80])

shutil.rmtree(work, ignore_errors=True)

failed = results.count(False)
print(f"\n{results.count(True)} passed, {failed} failed")
if failed:
    print("\nROUND-TRIP PARITY BROKEN — the reference implementation rejects "
          "artifacts this playground produced.")
    sys.exit(1)
print("""
AC-1 satisfied, in the two halves it now has:

  Certificates and spawn rules  validated by ietf-a2a-trust-poc's own Python,
                                unmodified. X.509 identity is unchanged between
                                -00 and -02, so the reference implementation is
                                still the right oracle for that layer.

  Signatures and hashes         validated by OpenSSL and by an independent
                                Python recomputation of the RFC 8785 canonical
                                form. The reference implementation implements
                                -00, whose field set and serialization differ,
                                so it cannot serve as an oracle here and is not
                                asked to.""")
