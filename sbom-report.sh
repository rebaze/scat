#!/usr/bin/env bash
set -euo pipefail

# --- Usage ---
# ./sbom-report.sh <prefix>
#
# Expects these files to exist (created by sbom-scan.sh):
#   <prefix>-sbom.json
#   <prefix>-vulns.json
#   <prefix>-licenses.json
#
# Generates:
#   <prefix>-report-sbom.md
#   <prefix>-report-vulns.md
#   <prefix>-report-licenses.md

# --- Input validation ---
if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <prefix>"
  echo "  e.g. $0 my-project"
  exit 1
fi

PREFIX="$1"
SBOM_FILE="${PREFIX}-sbom.json"
VULN_FILE="${PREFIX}-vulns.json"
LICENSE_FILE="${PREFIX}-licenses.json"

for f in "$SBOM_FILE" "$VULN_FILE" "$LICENSE_FILE"; do
  if [[ ! -f "$f" ]]; then
    echo "Error: '$f' not found. Run sbom-scan.sh first."
    exit 1
  fi
done

for cmd in jq; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "Error: '$cmd' is not installed or not in PATH."
    exit 1
  fi
done

REPORT_SBOM="${PREFIX}-report-sbom.md"
REPORT_VULNS="${PREFIX}-report-vulns.md"
REPORT_LICENSES="${PREFIX}-report-licenses.md"
GENERATED_AT="$(date -u '+%Y-%m-%d %H:%M:%S UTC')"

# ============================================================
# Report 1: SBOM Summary
# ============================================================
echo "[1/3] Generating SBOM summary report..."

cat > "${REPORT_SBOM}" <<EOF
# SBOM Summary — ${PREFIX}

**Generated:** ${GENERATED_AT}
**Source:** ${SBOM_FILE}

## Overview

| Metric | Value |
|--------|-------|
$(jq -r '
  "| Total Components | \(.components | length) |",
  "| SBOM Format | \(.bomFormat // "n/a") \(.specVersion // "") |",
  "| Serial Number | \(.serialNumber // "n/a") |"
' "$SBOM_FILE")

## Components by Type

| Type | Count |
|------|-------|
$(jq -r '
  [.components[] | .type] | group_by(.) | map({type: .[0], count: length})
  | sort_by(-.count)[]
  | "| \(.type) | \(.count) |"
' "$SBOM_FILE")

## Components by Package Manager (PURL scheme)

| Ecosystem | Count |
|-----------|-------|
$(jq -r '
  [.components[] | .purl // empty | capture("^pkg:(?<scheme>[^/]+)/") | .scheme]
  | group_by(.) | map({scheme: .[0], count: length})
  | sort_by(-.count)[]
  | "| \(.scheme) | \(.count) |"
' "$SBOM_FILE")

## Component List

| Name | Version | Type | PURL |
|------|---------|------|------|
$(jq -r '
  .components | sort_by(.name)[]
  | "| \(.name) | \(.version // "-") | \(.type // "-") | \(.purl // "-") |"
' "$SBOM_FILE")
EOF

echo "  -> ${REPORT_SBOM}"

# ============================================================
# Report 2: Vulnerability Report
# ============================================================
echo "[2/3] Generating vulnerability report..."

cat > "${REPORT_VULNS}" <<EOF
# Vulnerability Report — ${PREFIX}

**Generated:** ${GENERATED_AT}
**Source:** ${VULN_FILE}

## Summary

| Severity | Count |
|----------|-------|
$(jq -r '
  (if .matches then .matches else [] end) as $m |
  ["Critical","High","Medium","Low","Negligible","Unknown"] | .[] as $sev |
  ($m | map(select(.vulnerability.severity == $sev)) | length) as $cnt |
  "| \($sev) | \($cnt) |"
' "$VULN_FILE")
| **Total** | $(jq -r '(if .matches then .matches | length else 0 end)' "$VULN_FILE") |

## Vulnerabilities by Severity

$(jq -r '
  (if .matches then .matches else [] end)
  | sort_by(
      if .vulnerability.severity == "Critical" then 0
      elif .vulnerability.severity == "High" then 1
      elif .vulnerability.severity == "Medium" then 2
      elif .vulnerability.severity == "Low" then 3
      elif .vulnerability.severity == "Negligible" then 4
      else 5 end
    )[]
  | "### \(.vulnerability.id) — \(.vulnerability.severity)\n\n" +
    "- **Package:** \(.artifact.name) \(.artifact.version // "")\n" +
    "- **Fix available:** \(if .vulnerability.fix and .vulnerability.fix.state then .vulnerability.fix.state else "unknown" end)\n" +
    "- **Description:** \(.vulnerability.description // "n/a" | .[0:200])\n" +
    (if .vulnerability.dataSource then "- **Reference:** \(.vulnerability.dataSource)\n" else "" end) +
    ""
' "$VULN_FILE")
EOF

echo "  -> ${REPORT_VULNS}"

# ============================================================
# Report 3: License Report
# ============================================================
echo "[3/3] Generating license report..."

cat > "${REPORT_LICENSES}" <<EOF
# License Report — ${PREFIX}

**Generated:** ${GENERATED_AT}
**Source:** ${LICENSE_FILE}

## Evaluation Summary

$(jq -r '
  .run.targets[] |
  "**Source:** \(.source.ref // "n/a")  ",
  "**Status:** \(.evaluation.status // "n/a")  ",
  "",
  "| Metric | Count |",
  "|--------|-------|",
  "| Total Packages | \(.evaluation.summary.packages.total) |",
  "| Allowed | \(.evaluation.summary.packages.allowed) |",
  "| Denied | \(.evaluation.summary.packages.denied) |",
  "| Ignored | \(.evaluation.summary.packages.ignored) |",
  "| Unlicensed | \(.evaluation.summary.packages.unlicensed) |",
  "",
  "| License Metric | Count |",
  "|----------------|-------|",
  "| Unique Licenses | \(.evaluation.summary.licenses.unique) |",
  "| Allowed | \(.evaluation.summary.licenses.allowed) |",
  "| Denied | \(.evaluation.summary.licenses.denied) |",
  "| Non-SPDX | \(.evaluation.summary.licenses.nonSPDX) |"
' "$LICENSE_FILE")

## License Distribution

| License | Packages |
|---------|----------|
$(jq -r '
  [.run.targets[].evaluation.findings.packages[] | .licenses[]? // "UNLICENSED"]
  | group_by(.) | map({license: .[0], count: length})
  | sort_by(-.count)[]
  | "| \(.license) | \(.count) |"
' "$LICENSE_FILE" 2>/dev/null || echo "| (no license data found) | - |")

## Denied Components

| Package | Version | License |
|---------|---------|---------|
$(jq -r '
  [.run.targets[].evaluation.findings.packages[] | select(.status == "denied")]
  | sort_by(.name)[]
  | "| \(.name // "unknown") | \(.version // "-") | \(.licenses // ["n/a"] | join(", ")) |"
' "$LICENSE_FILE" 2>/dev/null || echo "| (no denied packages found) | - | - |")

## Package Details

| Package | Version | License | Status |
|---------|---------|---------|--------|
$(jq -r '
  .run.targets[].evaluation.findings.packages[]
  | "| \(.name // "unknown") | \(.version // "-") | \(.licenses // ["n/a"] | join(", ")) | \(.status // "-") |"
' "$LICENSE_FILE" 2>/dev/null || echo "| (no packages found) | - | - | - |")
EOF

echo "  -> ${REPORT_LICENSES}"

echo ""
echo "=== Reports Generated ==="
echo "SBOM:            ${REPORT_SBOM}"
echo "Vulnerabilities: ${REPORT_VULNS}"
echo "Licenses:        ${REPORT_LICENSES}"
echo ""
echo "Open in VS Code: code ${REPORT_SBOM} ${REPORT_VULNS} ${REPORT_LICENSES}"
