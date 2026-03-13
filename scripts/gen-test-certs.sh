#!/usr/bin/env bash
# Generate signing certificates for all cert type / algorithm combinations.
#
# Cert types:  Desktop, Server, Multipurpose
# Algorithms:  RSA-2048, RSA-3072, RSA-4096, ECDSA P-256, ECDSA P-384
# Total:       15 PFX files
#
# Usage: PFX_TEST_PASS=test ./scripts/gen-test-certs.sh [output_dir]
set -euo pipefail

PASS="${PFX_TEST_PASS:?Set PFX_TEST_PASS env var}"
OUT_DIR="${1:-/tmp/pki-sign/certs}"
mkdir -p "$OUT_DIR"

echo "Generating 15 signing certificates in $OUT_DIR ..."

# --- Cert type definitions ---
# type_name  subject_cn                    EKUs
CERT_TYPES=(
    "desktop|Desktop Code Signing|codeSigning"
    "server|Server Code Signing|codeSigning,serverAuth"
    "multipurpose|Multipurpose Signing|codeSigning,emailProtection"
)

# --- Algorithm definitions ---
# algo_suffix  keygen_args
ALGOS=(
    "rsa2048|-newkey rsa:2048"
    "rsa3072|-newkey rsa:3072"
    "rsa4096|-newkey rsa:4096"
    "p256|-newkey ec -pkeyopt ec_paramgen_curve:P-256"
    "p384|-newkey ec -pkeyopt ec_paramgen_curve:P-384"
)

count=0

for cert_entry in "${CERT_TYPES[@]}"; do
    IFS='|' read -r type_name cn ekus <<< "$cert_entry"

    for algo_entry in "${ALGOS[@]}"; do
        IFS='|' read -r algo_suffix keygen_args <<< "$algo_entry"

        name="${type_name}_${algo_suffix}"

        echo "  $name ..."

        # Generate self-signed cert + key
        # shellcheck disable=SC2086
        openssl req -x509 $keygen_args \
            -keyout "$OUT_DIR/${name}.key" \
            -out "$OUT_DIR/${name}.crt" \
            -days 365 -nodes \
            -subj "/CN=${cn} (${algo_suffix})/O=PKI-Sign Test/C=US" \
            -addext "extendedKeyUsage=${ekus}" \
            -addext "keyUsage=digitalSignature" \
            2>/dev/null

        # Bundle into PFX (legacy mode for p12 crate compatibility — SHA-1 MAC + 3DES)
        openssl pkcs12 -export -legacy \
            -out "$OUT_DIR/${name}.pfx" \
            -inkey "$OUT_DIR/${name}.key" \
            -in "$OUT_DIR/${name}.crt" \
            -passout "pass:$PASS" \
            2>/dev/null

        count=$((count + 1))
    done
done

# Clean up intermediate files
rm -f "$OUT_DIR"/*.key "$OUT_DIR"/*.crt

echo ""
echo "Generated $count PFX files:"
echo ""
printf "  %-30s  %-15s  %s\n" "FILE" "ALGORITHM" "EKUs"
printf "  %-30s  %-15s  %s\n" "----" "---------" "----"
for cert_entry in "${CERT_TYPES[@]}"; do
    IFS='|' read -r type_name cn ekus <<< "$cert_entry"
    for algo_entry in "${ALGOS[@]}"; do
        IFS='|' read -r algo_suffix keygen_args <<< "$algo_entry"
        printf "  %-30s  %-15s  %s\n" "${type_name}_${algo_suffix}.pfx" "$algo_suffix" "$ekus"
    done
done
echo ""
echo "Password: \$PFX_TEST_PASS"
