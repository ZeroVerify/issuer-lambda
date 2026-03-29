#!/bin/bash
# Generates HMAC and BabyJubJub private keys and stores them in AWS Secrets Manager.
# Run once per environment. Never commit the .secrets/ directory.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="${REPO_ROOT}/.secrets"
mkdir -p "${OUT_DIR}"
chmod 700 "${OUT_DIR}"

PROJECT_NAME="${PROJECT_NAME:-zeroverify}"
AWS_REGION="${AWS_REGION:-us-east-1}"

HMAC_SECRET_NAME="${PROJECT_NAME}/hmac-key"
EDDSA_SECRET_NAME="${PROJECT_NAME}/baby-jubjub-private-key"

echo "Generating HMAC key (32 bytes)..."
openssl rand 32 > "${OUT_DIR}/hmac-key.bin"
chmod 600 "${OUT_DIR}/hmac-key.bin"

echo "Generating BabyJubJub private key (32 bytes)..."
openssl rand 32 > "${OUT_DIR}/baby-jubjub-private-key.bin"
chmod 600 "${OUT_DIR}/baby-jubjub-private-key.bin"

echo "Storing HMAC key in Secrets Manager (${AWS_REGION})..."
aws secretsmanager put-secret-value \
  --region "${AWS_REGION}" \
  --secret-id "${HMAC_SECRET_NAME}" \
  --secret-binary "fileb://${OUT_DIR}/hmac-key.bin"

echo "Storing BabyJubJub key in Secrets Manager (${AWS_REGION})..."
aws secretsmanager put-secret-value \
  --region "${AWS_REGION}" \
  --secret-id "${EDDSA_SECRET_NAME}" \
  --secret-binary "fileb://${OUT_DIR}/baby-jubjub-private-key.bin"

echo ""
echo "========================================================"
echo "  Keys stored in AWS Secrets Manager (${AWS_REGION})   "
echo "  ${HMAC_SECRET_NAME}                                   "
echo "  ${EDDSA_SECRET_NAME}                                  "
echo "========================================================"
echo ""
echo "Local copies saved to ${OUT_DIR}/ — store in a password"
echo "manager and delete this directory when done."
