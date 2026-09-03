#!/bin/sh
# Generate the test certificate chain with OpenSSL.
#
# Fixtures are generated, never committed: key and cert material stays out of
# git even as test data, and the pre-commit leak guard enforces that
# independently. Output goes to tests/fixtures/certs/, which .gitignore covers
# via the `certs/` rule.
#
# Using OpenSSL rather than the page's own PKI.js generator is deliberate. A
# validator tested only against certificates it produced itself proves that two
# copies of one bug agree. These are built by an independent implementation, in
# the exact profile the playground ships under draft-tonyai-a2a-trust-03:
#
#   CA    P-256; basicConstraints critical CA:TRUE, pathlen:0
#         keyUsage critical keyCertSign, cRLSign
#         nameConstraints critical, permitted dirName C=US / O=PhalanxAI A2A
#         Playground / OU=DEMO ONLY - NOT FOR PRODUCTION; demo notice NON-critical
#
#   leaf  P-256; basicConstraints critical CA:FALSE; keyUsage critical
#         digitalSignature; extendedKeyUsage critical clientAuth;
#         cRLDistributionPoints (§14.4); demo notice NON-critical
#         agents additionally carry the CRITICAL Agent Template extension (§8.2)
#         and, for a child, the CRITICAL Agent Spawn extension (§10.5); both a
#         DER OCTET STRING holding the UTF-8 JCS bytes — `DER:` in an OpenSSL
#         extension config places raw bytes as the extnValue, which is exactly
#         that encoding.
#         validity 1 day = ttl_seconds 86400 (§9.3)
#
# Both profile extensions are critical, so `openssl verify` refuses every agent
# certificate here with "unhandled critical extension". That is the draft
# working as designed: a validator that does not implement it must refuse. The
# self-check below verifies the chains with -ignore_critical, which answers the
# cryptographic question only, and asserts the refusal without it.

set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT="$ROOT/tests/fixtures/certs"
TEMPLATE_OID="2.25.318754453516410815925104555075461256891"
SPAWN_OID="2.25.316124730704531463413455892107752909312"
DEMO_OID="2.25.28836631322710226650474936410307455437"
NOTICE="PhalanxAI A2A Playground - demonstration only, not valid for any production use"
DN_PREFIX="/C=US/O=PhalanxAI A2A Playground/OU=DEMO ONLY - NOT FOR PRODUCTION"
CDP="URI:http://crl.a2a-playground.invalid/ca.crl"

# Agents are identified by RFC 9562 UUIDs (§7.2). One v4, one v7, so the
# fixtures exercise both versions the validator must accept.
AGENT_A="8f14e45f-ceea-467a-9c0f-7ad0f1b0d5aa"
AGENT_B="019b3c8e-2f10-7a4b-9c6d-3e5f7a9b1c2d"
NONCE=$(openssl rand -base64 16)
SPAWNED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)

rm -rf "$OUT"; mkdir -p "$OUT"; cd "$OUT"
echo "$AGENT_A" > agent-a.uuid
echo "$AGENT_B" > agent-b.uuid
echo "$NONCE" > agent-b.nonce

# JCS bytes as hex. BMP-only input, so Python's sort_keys agrees with RFC 8785.
jcs_hex () {
  python3 -c 'import json,sys; print(json.dumps(json.loads(sys.argv[1]), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode().hex())' "$1"
}
template_json () { # $1 subject, $2 scopes json, $3 can_spawn json, $4 max_children, $5 ttl
  printf '{"subject":"%s","owner":"owner-authority","org_id":"fixture-org","permitted_operations":["spawn","read"],"allowed_scopes":%s,"can_spawn":%s,"max_children":%s,"policy_ref":"policy-store/%s/current","ttl_seconds":%s}' \
    "$1" "$2" "$3" "$4" "$1" "$5"
}
TEMPLATE_A=$(jcs_hex "$(template_json "$AGENT_A" '["read:events","write:events"]' "[\"$AGENT_B\"]" 2 86400)")
TEMPLATE_B=$(jcs_hex "$(template_json "$AGENT_B" '["read:events"]' '[]' 0 86400)")
SPAWN_B=$(jcs_hex "{\"parent_agent_id\":\"$AGENT_A\",\"spawned_at\":\"$SPAWNED_AT\",\"spawn_nonce\":\"$NONCE\"}")
# The same object with whitespace: valid JSON, not valid JCS.
BAD_JCS=$(printf '{"subject": "%s", "owner": "owner-authority", "org_id": "fixture-org", "permitted_operations": ["spawn"], "allowed_scopes": ["read:events"], "can_spawn": [], "max_children": 0, "policy_ref": "p", "ttl_seconds": 86400}' "$AGENT_A" | od -An -v -tx1 | tr -d ' \n')
TEMPLATE_A_TTL900=$(jcs_hex "$(template_json "$AGENT_A" '["read:events"]' '[]' 0 900)")
TEMPLATE_A_TTL_LONG=$(jcs_hex "$(template_json "$AGENT_A" '["read:events"]' '[]' 0 700000)")

cat > ca.cnf <<CNF
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
CNF

# leaf_cnf FILE TEMPLATE_HEX_OR_EMPTY [extra config lines]
leaf_cnf () {
  {
    echo "[v3]"
    echo "basicConstraints=critical,CA:FALSE"
    echo "keyUsage=critical,digitalSignature"
    echo "extendedKeyUsage=critical,clientAuth"
    echo "subjectKeyIdentifier=hash"
    echo "crlDistributionPoints=$CDP"
    echo "$DEMO_OID=ASN1:UTF8String:$NOTICE"
    if [ -n "$2" ]; then echo "$TEMPLATE_OID=critical,DER:$2"; fi
    if [ $# -ge 3 ]; then printf '%s\n' "$3"; fi
  } > "$1"
}

genkey () { # $1 out, $2 alg
  case "$2" in
    ec256)   openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2>/dev/null ;;
    ec384)   openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out "$1" 2>/dev/null ;;
    rsa3072) openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$1" 2>/dev/null ;;
    rsa2048) openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$1" 2>/dev/null ;;
    ed25519) openssl genpkey -algorithm ed25519 -out "$1" 2>/dev/null ;;
  esac
}

serial () { echo "0x$(openssl rand -hex 16)"; }

# ── Root CA ─────────────────────────────────────────────────────────────────
genkey ca-root.key ec256
openssl req -new -x509 -key ca-root.key -out ca-root.crt -days 1 -sha256 \
  -set_serial "$(serial)" \
  -subj "$DN_PREFIX/CN=A2A-Trust-Playground-CA" -extensions v3 -config ca.cnf 2>/dev/null

# issue STEM CN KEYALG CNF [extra openssl x509 args…]   (DIGEST=sha1 to weaken)
DIGEST=sha256
issue () {
  stem=$1; cn=$2; alg=$3; cnf=$4; shift 4
  genkey "$stem.key" "$alg"
  openssl req -new -key "$stem.key" -out "$stem.csr" -subj "$DN_PREFIX/CN=$cn" 2>/dev/null
  openssl x509 -req -in "$stem.csr" -CA ca-root.crt -CAkey ca-root.key -set_serial "$(serial)" \
    -out "$stem.crt" -days 1 -extfile "$cnf" -extensions v3 "-$DIGEST" "$@" 2>/dev/null
  rm -f "$stem.csr"
}

# ── The conforming chain ────────────────────────────────────────────────────
leaf_cnf agent-a.cnf "$TEMPLATE_A"
leaf_cnf agent-b.cnf "$TEMPLATE_B" "$SPAWN_OID=critical,DER:$SPAWN_B"
leaf_cnf authority.cnf ""
issue agent-a "$AGENT_A" ec256 agent-a.cnf
issue agent-b "$AGENT_B" ec256 agent-b.cnf
# §9.2 requires the Owner and Policy Authority to hold independent keys.
issue owner    owner-authority  ec256 authority.cnf
issue pa       policy-authority ec256 authority.cnf

# ── Other key types the profile ACCEPTS (§7.1) ──────────────────────────────
issue rsa3072-agent "$AGENT_A" rsa3072 agent-a.cnf
issue p384-agent    "$AGENT_A" ec384   agent-a.cnf
issue ed25519-agent "$AGENT_A" ed25519 agent-a.cnf
issue rsa3072-owner owner-authority rsa3072 authority.cnf
issue ed25519-owner owner-authority ed25519 authority.cnf

# An Ed25519 CA signing an Ed25519 leaf: exercises Ed25519 chain verification,
# which PKI.js cannot do and the validator does by hand.
genkey ca-ed.key ed25519
openssl req -new -x509 -key ca-ed.key -out ca-ed.crt -days 1 -set_serial "$(serial)" \
  -subj "$DN_PREFIX/CN=A2A-Ed25519-CA" -extensions v3 -config ca.cnf 2>/dev/null
genkey ed-leaf.key ed25519
openssl req -new -key ed-leaf.key -out ed-leaf.csr -subj "$DN_PREFIX/CN=$AGENT_A" 2>/dev/null
openssl x509 -req -in ed-leaf.csr -CA ca-ed.crt -CAkey ca-ed.key -set_serial "$(serial)" \
  -out ed-leaf.crt -days 1 -extfile agent-a.cnf -extensions v3 2>/dev/null
rm -f ed-leaf.csr

# ── Negative fixtures — what a validator MUST refuse ────────────────────────
# Self-signed agent cert (§7.3: agent certs are CA-signed, never self-signed).
genkey selfsigned.key ec256
openssl req -new -x509 -key selfsigned.key -out selfsigned.crt -days 1 -set_serial "$(serial)" \
  -subj "$DN_PREFIX/CN=$AGENT_A" 2>/dev/null

# Issued by a DIFFERENT CA — the "forge the issuer" sabotage.
genkey rogue-ca.key ec256
openssl req -new -x509 -key rogue-ca.key -out rogue-ca.crt -days 1 -set_serial "$(serial)" \
  -subj "$DN_PREFIX/CN=Rogue-CA" -extensions v3 -config ca.cnf 2>/dev/null
genkey forged.key ec256
openssl req -new -key forged.key -out forged.csr -subj "$DN_PREFIX/CN=$AGENT_A" 2>/dev/null
openssl x509 -req -in forged.csr -CA rogue-ca.crt -CAkey rogue-ca.key -set_serial "$(serial)" \
  -out forged.crt -days 1 -extfile agent-a.cnf -extensions v3 -sha256 2>/dev/null
rm -f forged.csr

# Already expired.
issue expired "$AGENT_A" ec256 agent-a.cnf -not_before 20200101000000Z -not_after 20200102000000Z

# Keys below the 128-bit floor (§7.1). RSA-2048 is the one people expect to pass.
issue rsa2048-agent "$AGENT_A" rsa2048 agent-a.cnf

# A certificate the name constraint MUST refuse — proves the CA is structurally
# incapable of minting a production-looking credential.
genkey repurposed.key ec256
openssl req -new -key repurposed.key -out repurposed.csr \
  -subj "/C=US/O=Real Bank/CN=$AGENT_A" 2>/dev/null
openssl x509 -req -in repurposed.csr -CA ca-root.crt -CAkey ca-root.key -set_serial "$(serial)" \
  -out repurposed.crt -days 365 -extfile agent-a.cnf -extensions v3 -sha256 2>/dev/null
rm -f repurposed.csr

# An unrecognised CRITICAL extension: RFC 5280 §4.2 requires refusal.
leaf_cnf critical.cnf "$TEMPLATE_A"
sed -i '' "s|^$DEMO_OID=ASN1|$DEMO_OID=critical,ASN1|" critical.cnf
issue critical-demo-ext "$AGENT_A" ec256 critical.cnf

# ── Structurally wrong rather than cryptographically wrong ──────────────────
# All of these verify under `openssl verify -ignore_critical`. That is why they
# are here: a chain that verifies is not a certificate entitled to be used this
# way, and the cryptographic question alone does not make the distinction.

# A LEAF that asserts it is a certificate authority.
leaf_cnf ca-true-leaf.cnf "$TEMPLATE_A"
sed -i '' 's/^basicConstraints=.*/basicConstraints=critical,CA:TRUE/; s/^keyUsage=.*/keyUsage=critical,keyCertSign,cRLSign,digitalSignature/' ca-true-leaf.cnf
issue ca-true-leaf "$AGENT_A" ec256 ca-true-leaf.cnf

# A leaf signed with SHA-1. The key is fine; the DIGEST is the broken part.
DIGEST=sha1 issue sha1-leaf "$AGENT_A" ec256 agent-a.cnf
DIGEST=sha256

# A leaf carrying no basicConstraints at all — it does not say what it is.
leaf_cnf no-bc-leaf.cnf "$TEMPLATE_A"
sed -i '' '/^basicConstraints=/d' no-bc-leaf.cnf
issue no-bc-leaf "$AGENT_A" ec256 no-bc-leaf.cnf

# An agent asserting keyCertSign with CA:FALSE — §7.1 refuses it independently
# of basicConstraints.
leaf_cnf keycertsign-leaf.cnf "$TEMPLATE_A"
sed -i '' 's/^keyUsage=.*/keyUsage=critical,digitalSignature,keyCertSign/' keycertsign-leaf.cnf
issue keycertsign-leaf "$AGENT_A" ec256 keycertsign-leaf.cnf

# keyUsage not critical.
leaf_cnf noncrit-ku-leaf.cnf "$TEMPLATE_A"
sed -i '' 's/^keyUsage=.*/keyUsage=digitalSignature/' noncrit-ku-leaf.cnf
issue noncrit-ku-leaf "$AGENT_A" ec256 noncrit-ku-leaf.cnf

# A serial number of one octet (§7.1 requires 64 bits of randomness).
genkey short-serial.key ec256
openssl req -new -key short-serial.key -out short-serial.csr -subj "$DN_PREFIX/CN=$AGENT_A" 2>/dev/null
openssl x509 -req -in short-serial.csr -CA ca-root.crt -CAkey ca-root.key -set_serial 7 \
  -out short-serial.crt -days 1 -extfile agent-a.cnf -extensions v3 -sha256 2>/dev/null
rm -f short-serial.csr

# No cRLDistributionPoints and no OCSP (§14.4).
leaf_cnf no-cdp-leaf.cnf "$TEMPLATE_A"
sed -i '' '/^crlDistributionPoints=/d' no-cdp-leaf.cnf
issue no-cdp-leaf "$AGENT_A" ec256 no-cdp-leaf.cnf

# An ordinary client certificate: conformant in every way except that it
# carries no Agent Template extension (§8.2).
leaf_cnf no-template.cnf ""
issue no-template "$AGENT_A" ec256 no-template.cnf

# The Agent Template extension present but NOT critical (§8.2 requires critical).
leaf_cnf noncrit-template.cnf ""
echo "$TEMPLATE_OID=DER:$TEMPLATE_A" >> noncrit-template.cnf
issue noncrit-template "$AGENT_A" ec256 noncrit-template.cnf

# Valid JSON in the extension that is not its own canonical form (§8.2 refuses;
# §3 forbids re-canonicalizing).
leaf_cnf bad-jcs.cnf "$BAD_JCS"
issue bad-jcs "$AGENT_A" ec256 bad-jcs.cnf

# A one-day certificate whose template says ttl_seconds 900 (§9.3).
leaf_cnf ttl-exceeded.cnf "$TEMPLATE_A_TTL900"
issue ttl-exceeded "$AGENT_A" ec256 ttl-exceeded.cnf

# ttl_seconds above the seven-day maximum (§9.3).
leaf_cnf ttl-too-long.cnf "$TEMPLATE_A_TTL_LONG"
issue ttl-too-long "$AGENT_A" ec256 ttl-too-long.cnf -days 9

# A root orchestrator carrying an Agent Spawn extension — MUST be refused as a root (§10.5).
leaf_cnf root-with-spawn.cnf "$TEMPLATE_A" "$SPAWN_OID=critical,DER:$SPAWN_B"
issue root-with-spawn "$AGENT_A" ec256 root-with-spawn.cnf

# Two Agent Template extensions (§8.2: refuse rather than choose).
# OpenSSL refuses to write a duplicate extension, so this one is assembled by
# the unit tests from the minter instead.

rm -f ./*.cnf ./*.srl

# ── Self-check: the profile must behave as documented ───────────────────────
fail=0
check () { # $1 description, $2 expected pass|fail, $3 cert, [$4 extra verify args]
  if openssl verify -CAfile ca-root.crt ${4:-} "$3" >/dev/null 2>&1; then got=pass; else got=fail; fi
  if [ "$got" = "$2" ]; then echo "  ok    $1 ($got)"; else echo "  BROKEN $1 (expected $2, got $got)"; fail=1; fi
}
echo "OpenSSL verification of the generated profile:"
check "agent-a is REFUSED by plain openssl verify — critical extension, by design" fail agent-a.crt
check "agent-a verifies with -ignore_critical"       pass agent-a.crt -ignore_critical
check "agent-b verifies with -ignore_critical"       pass agent-b.crt -ignore_critical
check "owner authority verifies"                     pass owner.crt
check "policy authority verifies"                    pass pa.crt
check "rsa3072 agent verifies"                       pass rsa3072-agent.crt -ignore_critical
check "p384 agent verifies"                          pass p384-agent.crt -ignore_critical
check "ed25519-key agent verifies"                   pass ed25519-agent.crt -ignore_critical
check "self-signed agent is refused"                 fail selfsigned.crt
check "forged issuer is refused"                     fail forged.crt -ignore_critical
check "expired cert is refused"                      fail expired.crt -ignore_critical
check "repurposed DN hits the name constraint"       fail repurposed.crt -ignore_critical
# These PASS openssl verify. That is exactly why they are here.
check "rsa2048 agent still verifies"                 pass rsa2048-agent.crt -ignore_critical
check "a CA:TRUE leaf still verifies"                pass ca-true-leaf.crt -ignore_critical
check "a SHA-1 leaf still verifies"                  pass sha1-leaf.crt -ignore_critical
check "a leaf with no basicConstraints verifies"     pass no-bc-leaf.crt -ignore_critical
check "a keyCertSign leaf still verifies"            pass keycertsign-leaf.crt -ignore_critical
check "a one-octet serial still verifies"            pass short-serial.crt -ignore_critical
check "a leaf with no revocation source verifies"    pass no-cdp-leaf.crt -ignore_critical
check "a template-less client cert verifies"         pass no-template.crt
check "a non-JCS template still verifies"            pass bad-jcs.crt -ignore_critical
check "a ttl-exceeding cert still verifies"          pass ttl-exceeded.crt -ignore_critical
if openssl verify -CAfile ca-ed.crt -ignore_critical ed-leaf.crt >/dev/null 2>&1; then echo "  ok    ed25519 chain verifies (pass)"; else echo "  BROKEN ed25519 chain"; fail=1; fi
[ "$fail" = "0" ] || { echo "fixture profile is not behaving as documented"; exit 1; }

echo "fixtures written to tests/fixtures/certs/"
