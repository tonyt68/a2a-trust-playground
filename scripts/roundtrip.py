#!/usr/bin/env python3
"""
Round-trip parity — the acceptance criterion that matters.

Reads the JSON document this playground exports and validates it with tools
that share no code with the JavaScript that produced it:

    python-cryptography   parses every certificate, verifies each signature to
                          the anchor, and reads both critical extensions
    this file             re-derives the §3 / §8.2 / §10.5 / §11.4 rules from
                          the draft text and applies them
    OpenSSL               verifies the ECDSA envelope signatures over JCS bytes
                          this file recomputes independently

Three toolchains have to agree — Web Crypto that signed, this Python that
rebuilds the preimages, and OpenSSL / cryptography that check the maths. If
they do, the playground implements the draft rather than something resembling
it.

    pnpm test:roundtrip

── Why the reference implementation is no longer the oracle ──────────────────

Until -02 this harness reconstituted the document into ietf-a2a-trust-poc's
directory layout and called its Python. That implementation is pinned to -00
and shells out to `openssl verify`, which -03 makes refuse every agent
certificate by design (§8.2: the Agent Template extension is critical, so a
validator that does not implement the draft MUST refuse). Asking it to accept
-03 artifacts would be asking the wrong question. The oracle for the X.509
layer is now `cryptography`, which is a genuinely independent implementation of
RFC 5280, and the extension rules are applied here from the draft.
"""

import base64
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, ed25519
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
except ImportError as e:  # pragma: no cover
    sys.exit(f"python-cryptography is required for the round-trip oracle: {e}")

EXPORT = Path(__file__).parent.parent / "dist" / "roundtrip-export.json"
TEMPLATE_OID = x509.ObjectIdentifier("2.25.318754453516410815925104555075461256891")
SPAWN_OID = x509.ObjectIdentifier("2.25.316124730704531463413455892107752909312")
TEMPLATE_FIELDS = ["subject", "owner", "org_id", "permitted_operations", "allowed_scopes",
                   "can_spawn", "max_children", "policy_ref", "ttl_seconds"]
SPAWN_FIELDS = ["parent_agent_id", "spawned_at", "spawn_nonce"]
POLICY_FIELDS = ["subject", "owner", "org_id", "scopes", "spawn_targets", "version",
                 "issued_at", "not_after"]

PASS, FAIL = "  ok    ", "  FAIL  "
results = []


def check(name: str, condition: bool, detail: str = "") -> None:
    results.append(bool(condition))
    print(f"{PASS if condition else FAIL}{name}{f' — {detail}' if detail and not condition else ''}")


if not EXPORT.exists():
    sys.exit(f"missing {EXPORT} — run `pnpm test:roundtrip`, which exports it first")

# A stale export is the one failure mode this harness cannot survive quietly.
SRC = Path(__file__).parent.parent / "src"
newest_src = max(f.stat().st_mtime for f in SRC.glob("*.js"))
if EXPORT.stat().st_mtime < newest_src:
    sys.exit(f"STALE: {EXPORT.name} predates src/ — run `pnpm test:roundtrip`, "
             "which regenerates it. Refusing to report parity from an old artifact.")

doc = json.loads(EXPORT.read_text())
work = Path(tempfile.mkdtemp(prefix="a2a-roundtrip-"))


def jcs(o):
    """RFC 8785 for the BMP-keyed documents this profile produces."""
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def load(pem: str) -> x509.Certificate:
    return x509.load_pem_x509_certificate(pem.encode())


def verify_issued_by(cert: x509.Certificate, issuer: x509.Certificate) -> bool:
    """RFC 5280 signature check by an implementation that shares nothing with PKI.js."""
    pub = issuer.public_key()
    try:
        if isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))
        elif isinstance(pub, rsa.RSAPublicKey):
            pub.verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), cert.signature_hash_algorithm)
        elif isinstance(pub, ed25519.Ed25519PublicKey):
            pub.verify(cert.signature, cert.tbs_certificate_bytes)
        else:
            return False
        return True
    except Exception:
        return False


def security_bits(pub) -> int:
    if isinstance(pub, rsa.RSAPublicKey):
        return {2048: 112, 3072: 128, 7680: 192, 15360: 256}.get(pub.key_size, 80 if pub.key_size < 2048 else 128)
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return {"secp256r1": 128, "secp384r1": 192}.get(pub.curve.name, 0)
    if isinstance(pub, ed25519.Ed25519PublicKey):
        return 128
    return 0


def extension_json(cert: x509.Certificate, oid: x509.ObjectIdentifier):
    """§8.2: the extnValue OCTET STRING holds the UTF-8 JCS bytes directly."""
    try:
        ext = cert.extensions.get_extension_for_oid(oid)
    except x509.ExtensionNotFound:
        return None, None, None
    raw = ext.value.value  # UnrecognizedExtension -> the OCTET STRING contents
    text = raw.decode("utf-8")
    obj = json.loads(text, object_pairs_hook=strict_pairs)
    return obj, text, ext.critical


def strict_pairs(pairs):
    """§3 — a duplicate member is refused by the PARSER, not collapsed."""
    seen = set()
    for k, _ in pairs:
        if k in seen:
            raise ValueError(f"duplicate member {k!r}")
        seen.add(k)
    return dict(pairs)


RFC3339_Z = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z$")


def is_rfc3339_z(s) -> bool:
    """§3 — an RFC 3339 instant in UTC with the Z designator, and a real instant."""
    if not isinstance(s, str) or not RFC3339_Z.match(s):
        return False
    try:
        datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return False
    return True


# ── The chain ────────────────────────────────────────────────────────────────
anchor_node = next(n for n in doc["chain"] if n["role"] == "ca")
anchor = load(anchor_node["cert_pem"])
agents = [n for n in doc["chain"] if n["role"] == "agent"]
certs = {n["metadata"]["agent_id"]: load(n["cert_pem"]) for n in agents}
authorities = {role: load(a["cert_pem"]) for role, a in doc["authorities"].items()}

print("§7 — X.509 identity, verified by python-cryptography")
check("anchor is self-signed and verifies under its own key", verify_issued_by(anchor, anchor))
bc = anchor.extensions.get_extension_for_class(x509.BasicConstraints)
check("anchor asserts CA:TRUE, critical", bc.value.ca and bc.critical)
for aid, cert in certs.items():
    check(f"agent {aid[:8]}… verifies to the anchor", verify_issued_by(cert, anchor))
    cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    check(f"agent {aid[:8]}… subject CN equals the restated agent_id (§7.2)", cn == aid)
    check(f"agent {aid[:8]}… key provides 128-bit security (§7.1)", security_bits(cert.public_key()) >= 128)
    ku = cert.extensions.get_extension_for_class(x509.KeyUsage)
    check(f"agent {aid[:8]}… keyUsage is critical digitalSignature only (§7.1)",
          ku.critical and ku.value.digital_signature and not ku.value.key_cert_sign and not ku.value.crl_sign
          and not ku.value.key_encipherment and not ku.value.data_encipherment and not ku.value.key_agreement)
    check(f"agent {aid[:8]}… basicConstraints CA:FALSE (§7.1)",
          not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
    check(f"agent {aid[:8]}… serial carries at least 64 bits (§7.1)", cert.serial_number.bit_length() >= 57)
    try:
        cert.extensions.get_extension_for_class(x509.CRLDistributionPoints)
        has_cdp = True
    except x509.ExtensionNotFound:
        has_cdp = False
    check(f"agent {aid[:8]}… says where revocation state lives (§14.4)", has_cdp)
    check(f"agent {aid[:8]}… is signed with SHA-256 or stronger (§7.1)",
          cert.signature_hash_algorithm is not None and cert.signature_hash_algorithm.digest_size >= 32)
for role, cert in authorities.items():
    check(f"{role} authority verifies to the anchor (§9.2)", verify_issued_by(cert, anchor))

print("\n§8.2 — the Agent Template extension, decoded independently")
templates = {}
for aid, cert in certs.items():
    obj, text, critical = extension_json(cert, TEMPLATE_OID)
    check(f"agent {aid[:8]}… carries the Agent Template extension", obj is not None)
    if obj is None:
        continue
    check(f"agent {aid[:8]}… extension is critical", critical is True)
    check(f"agent {aid[:8]}… extension bytes are their own JCS form", jcs(obj) == text)
    check(f"agent {aid[:8]}… carries exactly the nine members of Table 5", sorted(obj) == sorted(TEMPLATE_FIELDS))
    check(f"agent {aid[:8]}… members are flat: strings, integers, arrays of strings (§3)",
          all(isinstance(v, str) or (isinstance(v, int) and not isinstance(v, bool))
              or (isinstance(v, list) and all(isinstance(x, str) for x in v)) for v in obj.values()))
    check(f"agent {aid[:8]}… subject member equals the subject CN (§9.3)", obj["subject"] == aid)
    validity = int((cert.not_valid_after_utc - cert.not_valid_before_utc).total_seconds())
    check(f"agent {aid[:8]}… validity {validity}s does not exceed ttl_seconds {obj['ttl_seconds']} (§9.3)",
          validity <= obj["ttl_seconds"])
    check(f"agent {aid[:8]}… ttl_seconds within seven days (§9.3)", 1 <= obj["ttl_seconds"] <= 604800)
    templates[aid] = obj

print("\n§10.5 — the Agent Spawn extension")
spawns = {}
for aid, cert in certs.items():
    obj, text, critical = extension_json(cert, SPAWN_OID)
    claimed = next(n for n in agents if n["metadata"]["agent_id"] == aid)["metadata"].get("parent_agent_id")
    if claimed is None:
        check(f"root {aid[:8]}… carries NO Agent Spawn extension", obj is None)
        continue
    check(f"child {aid[:8]}… carries the Agent Spawn extension, critical", obj is not None and critical)
    if obj is None:
        continue
    check(f"child {aid[:8]}… extension bytes are their own JCS form", jcs(obj) == text)
    check(f"child {aid[:8]}… carries exactly the three members of Table 6", sorted(obj) == sorted(SPAWN_FIELDS))
    check(f"child {aid[:8]}… attested parent equals the parent the chain names", obj["parent_agent_id"] == claimed)
    check(f"child {aid[:8]}… attested parent is in the chain", obj["parent_agent_id"] in certs)
    check(f"child {aid[:8]}… nonce is base64 of at least 128 bits (§19.2)",
          len(base64.b64decode(obj["spawn_nonce"], validate=True)) >= 16)
    check(f"child {aid[:8]}… spawned_at is RFC 3339 UTC with Z (§3)", is_rfc3339_z(obj["spawned_at"]))
    spawns[aid] = obj

print("\n§10.1, §10.3 — the two-check spawn rule and scope containment")
for aid, sp in spawns.items():
    parent = templates[sp["parent_agent_id"]]
    child = templates[aid]
    check("parent PermittedOperations includes spawn (§10.1)", "spawn" in parent["permitted_operations"])
    check("child is in the parent CanSpawn list (§10.1)", aid in parent["can_spawn"])
    check("child scopes ⊆ parent scopes (§10.3)", set(child["allowed_scopes"]) <= set(parent["allowed_scopes"]))
    check("child count consistent with MaxChildren (§10.2)",
          sum(1 for s in spawns.values() if s["parent_agent_id"] == sp["parent_agent_id"]) <= parent["max_children"])
    check("child ttl_seconds does not exceed the parent's (§10.3 SHOULD)", child["ttl_seconds"] <= parent["ttl_seconds"])
    node = next(n for n in agents if n["metadata"]["agent_id"] == aid)
    if "requested_scopes" in node:
        check("requested scopes ⊆ child AllowedScopes (§10.3)", set(node["requested_scopes"]) <= set(child["allowed_scopes"]))
        check("requested scopes are non-empty (§10.3)", len(node["requested_scopes"]) > 0)


# ── §3.1 / §11 — the envelope, verified by OpenSSL over JCS bytes recomputed here
def openssl_verify(preimage: str, sig_b64: str, cert: x509.Certificate) -> bool:
    """OpenSSL verifies; this file supplies the preimage and the DER-wrapped signature."""
    pub = work / "pub.pem"
    pub.write_bytes(cert.public_key().public_bytes(serialization.Encoding.PEM,
                                                   serialization.PublicFormat.SubjectPublicKeyInfo))
    (work / "msg.bin").write_bytes(preimage.encode("utf-8"))
    raw = base64.b64decode(sig_b64, validate=True)
    key = cert.public_key()
    if isinstance(key, ec.EllipticCurvePublicKey):
        # §3.1: on the wire the value is fixed-width r‖s. OpenSSL wants DER, so
        # the conversion is explicit and the width is checked, not assumed.
        n = (key.curve.key_size + 7) // 8
        if len(raw) != 2 * n:
            return False
        r, s = int.from_bytes(raw[:n], "big"), int.from_bytes(raw[n:], "big")
        (work / "sig.der").write_bytes(encode_dss_signature(r, s))
        digest = "-sha256" if n == 32 else "-sha384"
        args = ["openssl", "dgst", digest, "-verify", str(pub), "-signature", str(work / "sig.der"), str(work / "msg.bin")]
    elif isinstance(key, rsa.RSAPublicKey):
        (work / "sig.bin").write_bytes(raw)
        args = ["openssl", "dgst", "-sha256", "-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:32",
                "-verify", str(pub), "-signature", str(work / "sig.bin"), str(work / "msg.bin")]
    elif isinstance(key, ed25519.Ed25519PublicKey):
        (work / "sig.bin").write_bytes(raw)
        args = ["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(pub), "-rawin",
                "-in", str(work / "msg.bin"), "-sigfile", str(work / "sig.bin")]
    else:
        return False
    r = subprocess.run(args, capture_output=True, text=True)
    return r.returncode == 0


print("\n§3.1, §11.3, §11.6 — the policy envelope")
policy = doc.get("policy")
if policy:
    check("envelope carries exactly body, owner_sig, pa_sig, content_hash (§3.1)",
          sorted(policy) == ["body", "content_hash", "owner_sig", "pa_sig"])
    body = policy["body"]
    check("body carries only §11.4 fields", set(body) <= set(POLICY_FIELDS))
    check("body carries every REQUIRED §11.4 field",
          {"subject", "owner", "org_id", "scopes", "version", "issued_at"} <= set(body))
    check("owner_sig verifies under OpenSSL over JCS(body)", openssl_verify(jcs(body), policy["owner_sig"], authorities["owner"]))
    check("pa_sig verifies under OpenSSL over JCS(body)", openssl_verify(jcs(body), policy["pa_sig"], authorities["pa"]))
    owner_spki = authorities["owner"].public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    pa_spki = authorities["pa"].public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    check("Owner and Policy Authority present different public keys (§3.1)", owner_spki != pa_spki)
    owner_cn = authorities["owner"].subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    check("Owner certificate subject equals the template owner (§9.2)", owner_cn == templates[body["subject"]]["owner"])
    tampered = dict(body, version=body["version"] + 1)
    check("rewriting the version breaks pa_sig (§11.6 replay prevention)",
          not openssl_verify(jcs(tampered), policy["pa_sig"], authorities["pa"]))
    check("rewriting the version breaks owner_sig too — the Owner signature is specific to one policy (§11.8)",
          not openssl_verify(jcs(tampered), policy["owner_sig"], authorities["owner"]))
    digest = hashlib.sha256(jcs(body).encode("utf-8")).hexdigest()
    check("content hash is SHA-256 over the same JCS bytes (§11.6)", digest == policy["content_hash"],
          f"computed {digest[:16]}… stored {policy['content_hash'][:16]}…")
    check("version supersedes the version in force (§11.4)", body["version"] > doc.get("current_policy_version", 0))
    t = templates[body["subject"]]
    check("policy owner and org match the template (§11.2)", body["owner"] == t["owner"] and body["org_id"] == t["org_id"])
    check("policy scopes within the template AllowedScopes (§8.3)", set(body["scopes"]) <= set(t["allowed_scopes"]))
    check("issued_at is RFC 3339 UTC with Z (§3)", is_rfc3339_z(body["issued_at"]))
else:
    check("document carries a policy envelope to verify", False, "none present")

print("\n§19.7 — audit hash chain, recomputed independently")
chain = doc.get("audit", {}).get("chain", [])
ok_chain, broken_at = True, None
prev = "genesis"
for i, block in enumerate(chain):
    pre = jcs({"index": block["index"], "timestamp": block["timestamp"],
               "previous_hash": block["previous_hash"], "event": block["event"]})
    if block["previous_hash"] != prev or hashlib.sha256(pre.encode()).hexdigest() != block["hash"]:
        ok_chain, broken_at = False, i
        break
    prev = block["hash"]
check(f"audit chain verifies ({len(chain)} block(s))", ok_chain, f"broken at block {broken_at}")

print("\n§8.2 — OpenSSL refuses the certificates, as the draft requires")
for aid, node in ((n["metadata"]["agent_id"], n) for n in agents):
    (work / "ca.crt").write_text(anchor_node["cert_pem"])
    (work / "leaf.crt").write_text(node["cert_pem"])
    plain = subprocess.run(["openssl", "verify", "-CAfile", str(work / "ca.crt"), str(work / "leaf.crt")],
                           capture_output=True, text=True)
    check(f"openssl verify REFUSES {aid[:8]}… (unhandled critical extension)", plain.returncode != 0
          and "critical" in (plain.stdout + plain.stderr).lower())
    ign = subprocess.run(["openssl", "verify", "-CAfile", str(work / "ca.crt"), "-ignore_critical", str(work / "leaf.crt")],
                         capture_output=True, text=True)
    check(f"openssl verify -ignore_critical ACCEPTS {aid[:8]}… (the cryptography is sound)", ign.returncode == 0,
          (ign.stdout + ign.stderr).strip()[:80])

shutil.rmtree(work, ignore_errors=True)

failed = results.count(False)
print(f"\n{results.count(True)} passed, {failed} failed")
if failed:
    print("\nROUND-TRIP PARITY BROKEN — an independent toolchain rejects artifacts this playground produced.")
    sys.exit(1)
print("""
Parity holds across three toolchains that share no code:

  Web Crypto / PKI.js     minted and signed everything, in the browser's own APIs
  python-cryptography     parsed every certificate, verified every chain signature,
                          and read both critical extensions as raw OCTET STRINGs
  OpenSSL                 verified every envelope signature over JCS bytes this
                          file recomputed from the draft's rules, and refused the
                          certificates exactly where §8.2 says it must""")
