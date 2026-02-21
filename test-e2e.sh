#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

TARGET="${1:-testdata/vuln-sample}"
PREFIX=$(basename "$TARGET")

# Build
make build

# Output to a temp dir
OUTPUT_DIR=$(mktemp -d)
echo "Target: $TARGET"
echo "Output: $OUTPUT_DIR"

# Run full pipeline
./scat analyze --quiet --output-dir "$OUTPUT_DIR" "$TARGET"

# Verify key outputs
for f in "$PREFIX"-sbom.json "$PREFIX"-vulns.json "$PREFIX"-licenses.json "$PREFIX"-summary.html; do
  test -f "$OUTPUT_DIR/$f" || { echo "MISSING: $f"; exit 1; }
done

echo ""
echo "All outputs generated in: $OUTPUT_DIR"
ls -lh "$OUTPUT_DIR"

# Open HTML report
open "$OUTPUT_DIR/$PREFIX-summary.html"
