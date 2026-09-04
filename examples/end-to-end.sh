#!/usr/bin/env bash
#
# End-to-end demo: University issues a diploma, student shares via QR,
# employer verifies.
#
# Prerequisites:
#   - cargo build (or run via cargo run)
#   - Docker (optional, for web verifier)
#
# Usage:
#   ./examples/end-to-end.sh
#
set -euo pipefail

TRUSTMESH="${TRUSTMESH:-cargo run --bin trustmesh --}"
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

divider() { echo -e "\n━━━ $1 ━━━\n"; }

# ─── 1. University (Issuer) ────────────────────────────────────────────────

divider "Step 1: University generates its signing key"

SEED=$($TRUSTMESH keygen 2>"$TMPDIR/keygen.log")
DID=$(grep "^DID:" "$TMPDIR/keygen.log" | awk '{print $2}')

echo "University DID: $DID"
echo "$SEED" > "$TMPDIR/university.key"

divider "Step 2: University issues a diploma credential"

cat > "$TMPDIR/diploma-draft.json" <<EOF
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://www.w3.org/ns/credentials/examples/v2"
  ],
  "type": ["VerifiableCredential", "ExampleAlumniCredential"],
  "issuer": "$DID",
  "credentialSubject": {
    "id": "did:example:alice",
    "name": "Alice Smith",
    "alumniOf": "Example University",
    "degree": "Bachelor of Science in Computer Science",
    "graduationDate": "2026-06-15"
  }
}
EOF

$TRUSTMESH issue \
  --key "$TMPDIR/university.key" \
  --draft "$TMPDIR/diploma-draft.json" \
  --out "$TMPDIR/diploma.json"

echo "Issued diploma credential → $TMPDIR/diploma.json"

# ─── 2. Student (Holder) ──────────────────────────────────────────────────

divider "Step 3: Student receives the credential and generates a QR code"

echo "Credential received. Generating QR code for sharing..."
echo ""

$TRUSTMESH qr \
  --credential "$TMPDIR/diploma.json" \
  --url http://localhost:3000

echo ""
echo "The QR code encodes a URL that loads the credential into the web verifier."
echo "Scan it with a phone camera to verify at http://localhost:3000"

# ─── 3. Employer (Verifier) ───────────────────────────────────────────────

divider "Step 4: Employer verifies the credential (CLI)"

$TRUSTMESH verify \
  --credential "$TMPDIR/diploma.json" \
  --trusted "$DID"

echo ""
echo "Credential verified successfully."

divider "Step 5: Employer verifies via web verifier (browser)"

echo "Start the web verifier:"
echo "  docker compose up -d"
echo ""
echo "Then open http://localhost:3000 and paste the credential JSON,"
echo "or scan the QR code generated in Step 3."
echo ""
echo "Full credential JSON:"
echo ""
cat "$TMPDIR/diploma.json"
