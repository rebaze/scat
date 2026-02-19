# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A collection of Bash shell scripts for Software Composition Analysis (SCA). The toolchain generates SBOMs, scans for vulnerabilities, checks licenses, and produces reports in Markdown and HTML formats.

## Pipeline

The scripts form a two-stage pipeline:

1. **`sbom-scan.sh <folder>`** — Scans a source directory and produces three JSON artifacts:
   - `<prefix>-sbom.json` (CycloneDX SBOM via Syft)
   - `<prefix>-vulns.json` (vulnerability report via Grype)
   - `<prefix>-licenses.json` (license report via Grant)

2. **Reporting** (both consume the JSON files from step 1):
   - `sbom-report.sh <prefix>` — Generates three Markdown reports (`*-report-sbom.md`, `*-report-vulns.md`, `*-report-licenses.md`)
   - `sbom-summary.sh <prefix>` — Generates a single HTML dashboard (`<prefix>-summary.html`) with severity bars, risk scoring, and print-friendly layout

The `<prefix>` is derived from the scanned folder's basename.

## External Tool Dependencies

All scripts require `jq`. Additionally `sbom-scan.sh` requires:
- **syft** — SBOM generation
- **grype** — Vulnerability scanning
- **grant** — License checking

## Conventions

- All scripts use `set -euo pipefail` (strict Bash mode).
- Output files are written to the current working directory, not alongside the source.
- JSON outputs are pretty-printed via `jq .` after generation.
- The HTML report includes a simple risk heuristic: Critical vulns → Critical risk, High vulns → High risk, >5 Medium vulns → Medium risk, otherwise Low.
