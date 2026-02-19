# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A Software Composition Analysis (SCA) toolchain. The `scat` Go CLI generates SBOMs, scans for vulnerabilities, checks licenses, and produces reports in JSON, Markdown, and HTML formats.

## Repository Layout

```
main.go                         Entry point
cmd/                            Cobra CLI commands
  root.go                       Global flags (--output-dir, --format, --verbose, --quiet)
  analyze.go                    Full pipeline command
  version.go                    Version from ldflags
internal/
  scan/                         Pipeline orchestration (calls syft/grype/grant)
  model/                        Data types (SBOM, VulnReport, LicenseReport, RiskScore)
  report/                       Markdown + HTML report generation
    templates/                  go:embed HTML template
  output/                       JSON writer and file helpers
.goreleaser.yaml                Cross-platform builds + Homebrew tap
.github/workflows/              CI + Release pipelines
```

## Build & Run

```bash
go build -o scat .
./scat analyze <folder>
./scat version
```

## Pipeline

`scat analyze <folder>` runs three phases:

1. **Scan** — Calls Syft, Grype, Grant to produce `<prefix>-sbom.json`, `<prefix>-vulns.json`, `<prefix>-licenses.json`
2. **Markdown Reports** — Generates `*-report-sbom.md`, `*-report-vulns.md`, `*-report-licenses.md`
3. **HTML Dashboard** — Generates `<prefix>-summary.html` with severity bars, risk scoring, print-friendly layout

The `<prefix>` is derived from the scanned folder's basename.

## External Tool Dependencies

The scan phase requires these tools on PATH:
- **syft** — SBOM generation
- **grype** — Vulnerability scanning
- **grant** — License checking

Report generation (Markdown + HTML) is pure Go with no external dependencies.

## Conventions

- Go code follows standard `internal/` package layout
- Model types in `internal/model/` mirror the JSON schemas from Syft/Grype/Grant output
- HTML template uses `go:embed` for self-contained binary
- Risk heuristic: Critical vulns → Critical risk, High vulns → High risk, >5 Medium vulns → Medium risk, otherwise Low
- Output files written to `--output-dir` (default: current directory)
- Version injected via ldflags at build time
