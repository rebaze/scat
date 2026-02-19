#!/usr/bin/env bash
set -euo pipefail

# --- Usage ---
# ./sbom-summary.sh <prefix>
#
# Expects these files (created by sbom-scan.sh):
#   <prefix>-sbom.json
#   <prefix>-vulns.json
#   <prefix>-licenses.json
#
# Generates:
#   <prefix>-summary.html

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <prefix>"
  exit 1
fi

PREFIX="$1"
SBOM_FILE="${PREFIX}-sbom.json"
VULN_FILE="${PREFIX}-vulns.json"
LICENSE_FILE="${PREFIX}-licenses.json"
OUTPUT="${PREFIX}-summary.html"

for f in "$SBOM_FILE" "$VULN_FILE" "$LICENSE_FILE"; do
  if [[ ! -f "$f" ]]; then
    echo "Error: '$f' not found. Run sbom-scan.sh first."
    exit 1
  fi
done

if ! command -v jq &>/dev/null; then
  echo "Error: 'jq' is not installed."
  exit 1
fi

GENERATED_AT="$(date -u '+%Y-%m-%d %H:%M:%S UTC')"

# --- Extract data via jq ---

TOTAL_COMPONENTS=$(jq '.components | length' "$SBOM_FILE")

VULN_CRITICAL=$(jq '[(.matches // [])[] | select(.vulnerability.severity == "Critical")] | length' "$VULN_FILE")
VULN_HIGH=$(jq '[(.matches // [])[] | select(.vulnerability.severity == "High")] | length' "$VULN_FILE")
VULN_MEDIUM=$(jq '[(.matches // [])[] | select(.vulnerability.severity == "Medium")] | length' "$VULN_FILE")
VULN_LOW=$(jq '[(.matches // [])[] | select(.vulnerability.severity == "Low")] | length' "$VULN_FILE")
VULN_NEGLIGIBLE=$(jq '[(.matches // [])[] | select(.vulnerability.severity == "Negligible" or .vulnerability.severity == "Unknown")] | length' "$VULN_FILE")
VULN_TOTAL=$(jq '(.matches // []) | length' "$VULN_FILE")

LIC_TOTAL=$(jq '.run.targets[0].evaluation.summary.packages.total' "$LICENSE_FILE")
LIC_DENIED=$(jq '.run.targets[0].evaluation.summary.packages.denied' "$LICENSE_FILE")
LIC_UNLICENSED=$(jq '.run.targets[0].evaluation.summary.packages.unlicensed' "$LICENSE_FILE")
LIC_UNIQUE=$(jq '.run.targets[0].evaluation.summary.licenses.unique' "$LICENSE_FILE")
LIC_NONSPDX=$(jq '.run.targets[0].evaluation.summary.licenses.nonSPDX' "$LICENSE_FILE")

# Ecosystems table rows
ECOSYSTEM_ROWS=$(jq -r '
  [.components[] | .purl // empty | capture("^pkg:(?<s>[^/]+)/") | .s]
  | group_by(.) | map({eco: .[0], count: length})
  | sort_by(-.count)[]
  | "<tr><td>\(.eco)</td><td>\(.count)</td></tr>"
' "$SBOM_FILE")

# Top vulnerabilities (Critical + High only)
VULN_ROWS=$(jq -r '
  [(.matches // [])[] | select(.vulnerability.severity == "Critical" or .vulnerability.severity == "High")]
  | sort_by(if .vulnerability.severity == "Critical" then 0 else 1 end)[]
  | "<tr class=\"sev-\(.vulnerability.severity | ascii_downcase)\"><td>\(.vulnerability.id)</td><td>\(.vulnerability.severity)</td><td>\(.artifact.name)</td><td>\(.artifact.version // "-")</td><td>\(if .vulnerability.fix and .vulnerability.fix.state then .vulnerability.fix.state else "unknown" end)</td></tr>"
' "$VULN_FILE")

# License distribution rows
LICENSE_DIST_ROWS=$(jq -r '
  [.run.targets[].evaluation.findings.packages[] | .licenses[]? // "UNLICENSED"]
  | group_by(.) | map({license: .[0], count: length})
  | sort_by(-.count)[]
  | "<tr><td>\(.license)</td><td>\(.count)</td></tr>"
' "$LICENSE_FILE" 2>/dev/null || echo "<tr><td colspan='2'>No license data available</td></tr>")

# Denied packages rows
DENIED_ROWS=$(jq -r '
  [.run.targets[].evaluation.findings.packages[] | select(.status == "denied")]
  | sort_by(.name)[:20][]
  | "<tr><td>\(.name // "unknown")</td><td>\(.version // "-")</td><td>\(.licenses // ["n/a"] | join(", "))</td></tr>"
' "$LICENSE_FILE" 2>/dev/null || echo "<tr><td colspan='3'>No denied packages</td></tr>")

DENIED_TOTAL=$(jq '[.run.targets[].evaluation.findings.packages[] | select(.status == "denied")] | length' "$LICENSE_FILE" 2>/dev/null || echo "0")

# Risk score (simple heuristic)
RISK_SCORE="Low"
RISK_COLOR="#2d8a4e"
if [[ "$VULN_CRITICAL" -gt 0 ]]; then
  RISK_SCORE="Critical"
  RISK_COLOR="#c0392b"
elif [[ "$VULN_HIGH" -gt 0 ]]; then
  RISK_SCORE="High"
  RISK_COLOR="#e67e22"
elif [[ "$VULN_MEDIUM" -gt 5 ]]; then
  RISK_SCORE="Medium"
  RISK_COLOR="#f39c12"
fi

# --- Generate HTML ---
cat > "$OUTPUT" <<'HTMLHEAD'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Software Composition Analysis — Summary Report</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Source+Sans+3:wght@300;400;600;700&family=Source+Code+Pro:wght@400;500&display=swap');

  :root {
    --bg: #f7f8fa;
    --surface: #ffffff;
    --border: #e2e5ea;
    --text: #1a1d23;
    --text-secondary: #5a6170;
    --accent: #2563eb;
    --critical: #c0392b;
    --high: #e67e22;
    --medium: #f39c12;
    --low: #2d8a4e;
    --negligible: #8395a7;
  }

  * { margin: 0; padding: 0; box-sizing: border-box; }

  body {
    font-family: 'Source Sans 3', -apple-system, BlinkMacSystemFont, sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.6;
    padding: 0;
  }

  .page {
    max-width: 1060px;
    margin: 0 auto;
    padding: 48px 40px;
  }

  header {
    border-bottom: 3px solid var(--text);
    padding-bottom: 20px;
    margin-bottom: 40px;
  }

  header h1 {
    font-size: 28px;
    font-weight: 700;
    letter-spacing: -0.5px;
    margin-bottom: 4px;
  }

  header .meta {
    font-size: 14px;
    color: var(--text-secondary);
  }

  .cards {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 16px;
    margin-bottom: 40px;
  }

  .card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 20px 24px;
  }

  .card .label {
    font-size: 12px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    color: var(--text-secondary);
    margin-bottom: 8px;
  }

  .card .value {
    font-size: 36px;
    font-weight: 700;
    letter-spacing: -1px;
    line-height: 1;
  }

  .card .sub {
    font-size: 13px;
    color: var(--text-secondary);
    margin-top: 6px;
  }

  .risk-badge {
    display: inline-block;
    font-size: 14px;
    font-weight: 600;
    padding: 3px 12px;
    border-radius: 4px;
    color: #fff;
  }

  section {
    margin-bottom: 40px;
  }

  h2 {
    font-size: 18px;
    font-weight: 700;
    margin-bottom: 16px;
    padding-bottom: 8px;
    border-bottom: 1px solid var(--border);
  }

  .two-col {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 24px;
  }

  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 14px;
  }

  thead th {
    text-align: left;
    font-weight: 600;
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: var(--text-secondary);
    padding: 10px 12px;
    border-bottom: 2px solid var(--border);
    background: var(--bg);
  }

  tbody td {
    padding: 9px 12px;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
  }

  tbody tr:last-child td { border-bottom: none; }
  tbody tr:hover { background: #f0f2f5; }

  .sev-bar {
    display: flex;
    height: 28px;
    border-radius: 6px;
    overflow: hidden;
    margin-bottom: 12px;
    background: var(--border);
  }

  .sev-bar > div {
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 12px;
    font-weight: 600;
    color: #fff;
    min-width: 2px;
  }

  .sev-bar .crit { background: var(--critical); }
  .sev-bar .high { background: var(--high); }
  .sev-bar .med  { background: var(--medium); color: var(--text); }
  .sev-bar .low  { background: var(--low); }
  .sev-bar .neg  { background: var(--negligible); }

  .sev-legend {
    display: flex;
    gap: 20px;
    font-size: 13px;
    color: var(--text-secondary);
    margin-bottom: 20px;
  }

  .sev-legend span::before {
    content: '';
    display: inline-block;
    width: 10px;
    height: 10px;
    border-radius: 2px;
    margin-right: 6px;
    vertical-align: middle;
  }

  .sev-legend .l-crit::before { background: var(--critical); }
  .sev-legend .l-high::before { background: var(--high); }
  .sev-legend .l-med::before  { background: var(--medium); }
  .sev-legend .l-low::before  { background: var(--low); }
  .sev-legend .l-neg::before  { background: var(--negligible); }

  tr.sev-critical td:first-child { border-left: 3px solid var(--critical); }
  tr.sev-high td:first-child     { border-left: 3px solid var(--high); }

  .tag {
    display: inline-block;
    font-family: 'Source Code Pro', monospace;
    font-size: 12px;
    background: #eef1f5;
    padding: 2px 8px;
    border-radius: 3px;
  }

  .footnote {
    font-size: 12px;
    color: var(--text-secondary);
    margin-top: 6px;
  }

  footer {
    margin-top: 48px;
    padding-top: 16px;
    border-top: 1px solid var(--border);
    font-size: 12px;
    color: var(--text-secondary);
    text-align: center;
  }

  @media print {
    body { background: #fff; }
    .page { padding: 20px; }
    .cards { grid-template-columns: repeat(4, 1fr); }
    .two-col { grid-template-columns: 1fr 1fr; }
    tbody tr:hover { background: none; }
  }

  @media (max-width: 768px) {
    .cards { grid-template-columns: repeat(2, 1fr); }
    .two-col { grid-template-columns: 1fr; }
  }
</style>
</head>
<body>
<div class="page">
HTMLHEAD

cat >> "$OUTPUT" <<EOF
<header>
  <h1>Software Composition Analysis</h1>
  <div class="meta">Report for <strong>${PREFIX}</strong> &mdash; Generated ${GENERATED_AT}</div>
</header>

<!-- Executive Summary Cards -->
<div class="cards">
  <div class="card">
    <div class="label">Components</div>
    <div class="value">${TOTAL_COMPONENTS}</div>
    <div class="sub">in SBOM</div>
  </div>
  <div class="card">
    <div class="label">Vulnerabilities</div>
    <div class="value">${VULN_TOTAL}</div>
    <div class="sub">${VULN_CRITICAL} critical, ${VULN_HIGH} high</div>
  </div>
  <div class="card">
    <div class="label">License Issues</div>
    <div class="value">${LIC_DENIED}</div>
    <div class="sub">${LIC_UNLICENSED} unlicensed</div>
  </div>
  <div class="card">
    <div class="label">Risk Level</div>
    <div class="value"><span class="risk-badge" style="background:${RISK_COLOR}">${RISK_SCORE}</span></div>
    <div class="sub">${LIC_UNIQUE} unique licenses</div>
  </div>
</div>
EOF

# --- Vulnerability section ---
cat >> "$OUTPUT" <<EOF
<section>
  <h2>Vulnerability Overview</h2>
EOF

# Severity bar (compute percentages)
if [[ "$VULN_TOTAL" -gt 0 ]]; then
  calc_pct() { echo "scale=1; $1 * 100 / $VULN_TOTAL" | bc; }
  PCT_C=$(calc_pct "$VULN_CRITICAL")
  PCT_H=$(calc_pct "$VULN_HIGH")
  PCT_M=$(calc_pct "$VULN_MEDIUM")
  PCT_L=$(calc_pct "$VULN_LOW")
  PCT_N=$(calc_pct "$VULN_NEGLIGIBLE")

  cat >> "$OUTPUT" <<EOF
  <div class="sev-bar">
    <div class="crit" style="width:${PCT_C}%">${VULN_CRITICAL}</div>
    <div class="high" style="width:${PCT_H}%">${VULN_HIGH}</div>
    <div class="med"  style="width:${PCT_M}%">${VULN_MEDIUM}</div>
    <div class="low"  style="width:${PCT_L}%">${VULN_LOW}</div>
    <div class="neg"  style="width:${PCT_N}%">${VULN_NEGLIGIBLE}</div>
  </div>
  <div class="sev-legend">
    <span class="l-crit">Critical (${VULN_CRITICAL})</span>
    <span class="l-high">High (${VULN_HIGH})</span>
    <span class="l-med">Medium (${VULN_MEDIUM})</span>
    <span class="l-low">Low (${VULN_LOW})</span>
    <span class="l-neg">Other (${VULN_NEGLIGIBLE})</span>
  </div>
EOF
else
  echo '<p style="color:var(--low);font-weight:600;">No vulnerabilities found.</p>' >> "$OUTPUT"
fi

# Top vulns table
if [[ -n "$VULN_ROWS" ]]; then
  cat >> "$OUTPUT" <<EOF
  <h2 style="border:none;margin-top:24px;">Critical &amp; High Vulnerabilities</h2>
  <table>
    <thead><tr><th>CVE / ID</th><th>Severity</th><th>Package</th><th>Version</th><th>Fix</th></tr></thead>
    <tbody>
${VULN_ROWS}
    </tbody>
  </table>
EOF
fi

echo '</section>' >> "$OUTPUT"

# --- Composition + License side by side ---
cat >> "$OUTPUT" <<EOF
<section>
  <div class="two-col">
    <div>
      <h2>Composition by Ecosystem</h2>
      <table>
        <thead><tr><th>Ecosystem</th><th>Packages</th></tr></thead>
        <tbody>
${ECOSYSTEM_ROWS}
        </tbody>
      </table>
    </div>
    <div>
      <h2>License Distribution</h2>
      <table>
        <thead><tr><th>License</th><th>Packages</th></tr></thead>
        <tbody>
${LICENSE_DIST_ROWS}
        </tbody>
      </table>
      <p class="footnote">${LIC_NONSPDX} non-SPDX license identifiers detected</p>
    </div>
  </div>
</section>
EOF

# --- Denied packages ---
if [[ "$DENIED_TOTAL" -gt 0 ]]; then
  SHOWING_NOTE=""
  if [[ "$DENIED_TOTAL" -gt 20 ]]; then
    SHOWING_NOTE="<p class=\"footnote\">Showing first 20 of ${DENIED_TOTAL} denied packages. See full report for details.</p>"
  fi
  cat >> "$OUTPUT" <<EOF
<section>
  <h2>Denied Components (${DENIED_TOTAL})</h2>
  <table>
    <thead><tr><th>Package</th><th>Version</th><th>License</th></tr></thead>
    <tbody>
${DENIED_ROWS}
    </tbody>
  </table>
  ${SHOWING_NOTE}
</section>
EOF
fi

# --- Footer ---
cat >> "$OUTPUT" <<EOF
<footer>
  Generated from SBOM scan data &mdash; Syft / Grype / Grant &mdash; ${GENERATED_AT}
</footer>
</div>
</body>
</html>
EOF

echo "=== Summary report generated ==="
echo "  -> ${OUTPUT}"
echo ""
echo "Open: xdg-open ${OUTPUT}  (or: open ${OUTPUT} on macOS)"
