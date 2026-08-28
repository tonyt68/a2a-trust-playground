#!/bin/sh
# Generate the test certificate chain with OpenSSL.
#
# Fixtures are generated, never committed: DESIGN.md Repo Setup §2 says key and
# cert material must stay out of git even as test data, and the pre-commit leak
# guard enforces that independently. Output goes to tests/fixtures/certs/, which
# .gitignore covers via the `certs/` rule.
#
# Using OpenSSL rather than the page's own PKI.js generator is deliberate. A
# validator tested only against certificates it produced itself proves that two
# copies of one bug agree. These are built by an independent implementation, in
# the exact profile the playground ships.
#
# Profile — see docs/DRAFT-IMPACT.md and DESIGN.md "Demo-Only Certificates":
#
#   CA    basicConstraints critical CA:TRUE, pathlen:0
#         keyUsage         critical keyCertSign, cRLSign
#         nameConstraints  critical, permitted dirName C=US / O=PhalanxAI A2A
#                          Playground / OU=DEMO ONLY - NOT FOR PRODUCTION
#         demo notice      NON-critical, OID 2.25.<uuid>
#
#   leaf  basicConstraints critical CA:FALSE
#         keyUsage         critical digitalSignature
#         extendedKeyUsage critical clientAuth
#         demo notice      NON-critical
#         validity         24h
#
# The name constraint is what makes the CA structurally incapable of minting a
# credential whose DN does not say DEMO ONLY — a compliant validator rejects any
# attempt with "permitted subtree violation". The demo notice is deliberately
# NON-critical: an unrecognised critical extension makes the certificate
# unparseable to every RFC 5280 validator, which would also break the round-trip
# proof against the reference implementation's Python verifier.

set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT="$ROOT/tests/fixtures/certs"
DEMO_OID="2.25.329800735698586629295641978511506172918"
NOTICE="PhalanxAI A2A Playground - demonstration only, not valid for any production use"
DN_PREFIX="/C=US/O=PhalanxAI A2A Playground/OU=DEMO ONLY - NOT FOR PRODUCTION"

rm -rf "$OUT"; mkdir -p "$OUT"; cd "$OUT"

cat > ca.cnf <<EOF
[req]
distinguished_name=dn
[dn]
[v3]
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
nameConstraints=critical,permitted;dirName:demo_dn,permitted;DNS:.invalid,permitted;email:.invalid
$DEMO_OID=ASN1:UTF8String:$NOTICE
[demo_dn]
C=US
O=PhalanxAI A2A Playground
OU=DEMO ONLY - NOT FOR PRODUCTION
EOF

cat > leaf.cnf <<EOF
[v3]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=critical,clientAuth
subjectKeyIdentifier=hash
$DEMO_OID=ASN1:UTF8String:$NOTICE
EOF

# ── Root CA ─────────────────────────────────────────────────────────────────
openssl genrsa -out ca-root.key 2048 2>/dev/null
openssl req -new -x509 -key ca-root.key -out ca-root.crt -days 1 \
  -subj "$DN_PREFIX/CN=A2A-Trust-Playground-CA" -extensions v3 -config ca.cnf 2>/dev/null

# ── Leaf issuance ───────────────────────────────────────────────────────────
# $1 = filename stem, $2 = CN
issue () {
  openssl genrsa -out "$1.key" 2048 2>/dev/null
  openssl req -new -key "$1.key" -out "$1.csr" -subj "$DN_PREFIX/CN=$2" 2>/dev/null
  openssl x509 -req -in "$1.csr" -CA ca-root.crt -CAkey ca-root.key -CAcreateserial \
    -out "$1.crt" -days 1 -extfile leaf.cnf -extensions v3 -sha256 2>/dev/null
  rm -f "$1.csr"
}

# Agents are identified by UUID4 (§6), not by a human-readable name.
AGENT_A="8f14e45f-ceea-467a-9c0f-7ad0f1b0d5aa"
AGENT_B="c669186f-a84b-4d7a-81f3-05880df87114"
echo "$AGENT_A" > agent-a.uuid
echo "$AGENT_B" > agent-b.uuid

issue agent-a "$AGENT_A"
issue agent-b "$AGENT_B"
# §9.3 requires the Owner and Policy Authority to hold independent keys.
issue owner    owner-authority
issue pa       policy-authority

# ── Negative fixtures — what a validator MUST refuse ────────────────────────
# Self-signed agent cert (§6.1: agent certs are CA-signed, never self-signed).
openssl genrsa -out selfsigned.key 2048 2>/dev/null
openssl req -new -x509 -key selfsigned.key -out selfsigned.crt -days 1 \
  -subj "$DN_PREFIX/CN=$AGENT_A" 2>/dev/null

# Issued by a DIFFERENT CA — the "forge the issuer" sabotage.
openssl genrsa -out rogue-ca.key 2048 2>/dev/null
openssl req -new -x509 -key rogue-ca.key -out rogue-ca.crt -days 1 \
  -subj "$DN_PREFIX/CN=Rogue-CA" 2>/dev/null
openssl genrsa -out forged.key 2048 2>/dev/null
openssl req -new -key forged.key -out forged.csr -subj "$DN_PREFIX/CN=$AGENT_A" 2>/dev/null
openssl x509 -req -in forged.csr -CA rogue-ca.crt -CAkey rogue-ca.key -CAcreateserial \
  -out forged.crt -days 1 -extfile leaf.cnf -extensions v3 -sha256 2>/dev/null
rm -f forged.csr

# Already expired.
openssl genrsa -out expired.key 2048 2>/dev/null
openssl req -new -key expired.key -out expired.csr -subj "$DN_PREFIX/CN=$AGENT_A" 2>/dev/null
faketime_unavailable=1
openssl x509 -req -in expired.csr -CA ca-root.crt -CAkey ca-root.key -CAcreateserial \
  -out expired.crt -days 1 -not_before 20200101000000Z -not_after 20200102000000Z \
  -extfile leaf.cnf -extensions v3 -sha256 2>/dev/null
rm -f expired.csr

# Undersized key (§6: RSA >= 2048).
openssl genrsa -out weak.key 1024 2>/dev/null
openssl req -new -key weak.key -out weak.csr -subj "$DN_PREFIX/CN=$AGENT_A" 2>/dev/null
openssl x509 -req -in weak.csr -CA ca-root.crt -CAkey ca-root.key -CAcreateserial \
  -out weak.crt -days 1 -extfile leaf.cnf -extensions v3 -sha256 2>/dev/null
rm -f weak.csr

# A certificate the name constraint MUST refuse — proves the CA is structurally
# incapable of minting a production-looking credential (AC-9).
openssl genrsa -out repurposed.key 2048 2>/dev/null
openssl req -new -key repurposed.key -out repurposed.csr \
  -subj "/C=US/O=Real Bank/CN=login.bank.example.com" 2>/dev/null
openssl x509 -req -in repurposed.csr -CA ca-root.crt -CAkey ca-root.key -CAcreateserial \
  -out repurposed.crt -days 365 -extfile leaf.cnf -extensions v3 -sha256 2>/dev/null
rm -f repurposed.csr

# The profile DESIGN.md originally specified: demo notice marked CRITICAL. Kept
# as a fixture because it is the thing the validator must refuse — RFC 5280 §4.2
# requires rejecting an unrecognised critical extension, so this certificate is
# unusable to every conformant validator, which is why the shipped profile marks
# the notice non-critical and puts the guarantee in nameConstraints instead.
cat > critical.cnf <<EOF
[v3]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
subjectKeyIdentifier=hash
$DEMO_OID=critical,ASN1:UTF8String:$NOTICE
EOF
openssl genrsa -out critical-demo-ext.key 2048 2>/dev/null
openssl req -new -key critical-demo-ext.key -out critical-demo-ext.csr \
  -subj "$DN_PREFIX/CN=$AGENT_A" 2>/dev/null
openssl x509 -req -in critical-demo-ext.csr -CA ca-root.crt -CAkey ca-root.key -CAcreateserial \
  -out critical-demo-ext.crt -days 1 -extfile critical.cnf -extensions v3 -sha256 2>/dev/null
rm -f critical-demo-ext.csr critical.cnf

# ── Certificates that are structurally wrong rather than cryptographically ──
#
# All three verified cleanly under this validator before the checks that refuse
# them existed. They are generated by OpenSSL rather than by the minter for the
# same reason as every other fixture here: a validator tested only against
# certificates it produced itself proves that two copies of one bug agree.

# A LEAF that asserts it is a certificate authority. Genuinely CA-signed, so the
# signature verifies — and it was accepted as an ordinary agent, which is an
# agent structurally entitled to issue its own certificates.
cat > ca-true-leaf.cnf <<EOF
[v3]
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign,digitalSignature
subjectKeyIdentifier=hash
EOF
openssl genrsa -out ca-true-leaf.key 2048 2>/dev/null
openssl req -new -key ca-true-leaf.key -out ca-true-leaf.csr -subj "$DN_PREFIX/CN=$AGENT_A" 2>/dev/null
openssl x509 -req -in ca-true-leaf.csr -CA ca-root.crt -CAkey ca-root.key -CAcreateserial \
  -out ca-true-leaf.crt -days 1 -extfile ca-true-leaf.cnf -extensions v3 -sha256 2>/dev/null

# A leaf signed with SHA-1. The key is 2048 bits and the signature verifies; the
# DIGEST is the part that is broken, and nothing was checking it.
openssl genrsa -out sha1-leaf.key 2048 2>/dev/null
openssl req -new -key sha1-leaf.key -out sha1-leaf.csr -subj "$DN_PREFIX/CN=$AGENT_A" 2>/dev/null
openssl x509 -req -in sha1-leaf.csr -CA ca-root.crt -CAkey ca-root.key -CAcreateserial \
  -out sha1-leaf.crt -days 1 -extfile leaf.cnf -extensions v3 -sha1 2>/dev/null

# A leaf carrying no basicConstraints at all — it does not say what it is.
openssl genrsa -out no-bc-leaf.key 2048 2>/dev/null
openssl req -new -key no-bc-leaf.key -out no-bc-leaf.csr -subj "$DN_PREFIX/CN=$AGENT_A" 2>/dev/null
openssl x509 -req -in no-bc-leaf.csr -CA ca-root.crt -CAkey ca-root.key -CAcreateserial \
  -out no-bc-leaf.crt -days 1 -sha256 2>/dev/null

rm -f ca-true-leaf.cnf ca-true-leaf.csr sha1-leaf.csr no-bc-leaf.csr

rm -f ca.cnf leaf.cnf ca-root.srl rogue-ca.srl

# ── Self-check: the profile must behave as documented ───────────────────────
fail=0
check () { # $1 = description, $2 = expected pass|fail, $3 = cert
  if openssl verify -CAfile ca-root.crt "$3" >/dev/null 2>&1; then got=pass; else got=fail; fi
  if [ "$got" = "$2" ]; then echo "  ok    $1 ($got)"; else echo "  BROKEN $1 (expected $2, got $got)"; fail=1; fi
}
echo "OpenSSL verification of the generated profile:"
check "agent-a verifies to the CA"                    pass agent-a.crt
check "agent-b verifies to the CA"                    pass agent-b.crt
check "owner authority verifies"                      pass owner.crt
check "policy authority verifies"                     pass pa.crt
check "self-signed agent is refused"                  fail selfsigned.crt
check "forged issuer is refused"                      fail forged.crt
check "expired cert is refused"                       fail expired.crt
check "repurposed DN hits the name constraint"        fail repurposed.crt
check "critical demo ext makes the cert unusable"     fail critical-demo-ext.crt
# These three PASS openssl verify. That is exactly why they are here: a chain
# that verifies is not the same as a certificate entitled to be used this way,
# and `openssl verify` alone does not make the distinction this profile needs.
check "a CA:TRUE leaf still verifies to the CA"       pass ca-true-leaf.crt
check "a SHA-1 leaf still verifies to the CA"         pass sha1-leaf.crt
check "a leaf with no basicConstraints verifies"      pass no-bc-leaf.crt
[ "$fail" = "0" ] || { echo "fixture profile is not behaving as documented"; exit 1; }

echo "fixtures written to tests/fixtures/certs/"
