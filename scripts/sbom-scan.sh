#!/usr/bin/env bash
set -euo pipefail

# --- Usage ---
# ./sbom-scan.sh <folder>
#
# Generates:
#   <folder-name>-sbom.json        — CycloneDX SBOM via Syft
#   <folder-name>-vulns.json       — Vulnerability report via Grype
#   <folder-name>-licenses.json    — License report via Grant

# --- Input validation ---
if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <folder>"
  exit 1
fi

SOURCE_DIR="$1"

if [[ ! -d "$SOURCE_DIR" ]]; then
  echo "Error: '$SOURCE_DIR' is not a directory."
  exit 1
fi

# Derive prefix from folder name (strip trailing slash, take basename)
PREFIX="$(basename "${SOURCE_DIR%/}")"
OUTDIR="$(pwd)"

SBOM_FILE="${OUTDIR}/${PREFIX}-sbom.json"
VULN_FILE="${OUTDIR}/${PREFIX}-vulns.json"
LICENSE_FILE="${OUTDIR}/${PREFIX}-licenses.json"

# --- Dependency checks ---
for cmd in syft grype grant jq; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "Error: '$cmd' is not installed or not in PATH."
    exit 1
  fi
done

echo "=== SBOM Scan Pipeline ==="
echo "Source:    ${SOURCE_DIR}"
echo "Prefix:   ${PREFIX}"
echo ""

# --- Step 1: Generate SBOM with Syft ---
echo "[1/3] Generating SBOM with Syft..."
syft dir:"${SOURCE_DIR}" -o cyclonedx-json="${SBOM_FILE}"
jq . "${SBOM_FILE}" > "${SBOM_FILE}.tmp" && mv "${SBOM_FILE}.tmp" "${SBOM_FILE}"
echo "  -> ${SBOM_FILE}"

# --- Step 2: Scan for vulnerabilities with Grype ---
echo "[2/3] Scanning for vulnerabilities with Grype..."
grype sbom:"${SBOM_FILE}" -o json --file "${VULN_FILE}"
jq . "${VULN_FILE}" > "${VULN_FILE}.tmp" && mv "${VULN_FILE}.tmp" "${VULN_FILE}"
echo "  -> ${VULN_FILE}"

# --- Step 3: Check licenses with Grant ---
echo "[3/3] Generating license report with Grant..."
grant check "${SBOM_FILE}" -o json | jq . > "${LICENSE_FILE}"
echo "  -> ${LICENSE_FILE}"

echo ""
echo "=== Done ==="
echo "SBOM:           ${SBOM_FILE}"
echo "Vulnerabilities: ${VULN_FILE}"
echo "Licenses:        ${LICENSE_FILE}"
