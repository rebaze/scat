# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A Software Composition Analysis (SCA) toolchain. The `scat` Go CLI generates SBOMs, scans for vulnerabilities, checks licenses, and produces reports in JSON, Markdown, and HTML formats.

## Repository Layout

```
main.go                         Entry point
Makefile                        Build helpers (build, run, vet, tidy, clean)
cmd/                            Cobra CLI commands
  root.go                       Global flags (--output-dir, --format, --verbose, --quiet)
  analyze.go                    Full pipeline command (--clear-cache flag)
  version.go                    Version from ldflags
internal/
  scan/                         Pipeline orchestration (uses syft/grype Go libraries)
  model/                        Data types (SBOM, VulnReport, LicenseReport, RiskLevel)
  report/                       Markdown + HTML report generation
    templates/                  go:embed HTML template
  output/                       JSON writer and file helpers
  tui/                          Bubble Tea progress bar for pipeline steps
.goreleaser.yaml                Cross-platform builds + Homebrew tap
.github/workflows/              CI + Release pipelines
```

## Build & Run

```bash
go build -o scat .              # or: make build (injects version via ldflags)
./scat analyze <folder>
./scat analyze --clear-cache <folder>   # re-download Grype vulnerability DB
./scat version
```

## Pipeline

`scat analyze <folder>` runs three phases:

1. **Scan** — Uses Syft library for SBOM, Grype library for vulns, custom Go logic for licenses; produces `<prefix>-sbom.json`, `<prefix>-vulns.json`, `<prefix>-licenses.json`
2. **Markdown Reports** — Generates `*-report-sbom.md`, `*-report-vulns.md`, `*-report-licenses.md`
3. **HTML Dashboard** — Generates `<prefix>-summary.html` with severity bars, risk scoring, print-friendly layout

The `<prefix>` is derived from the scanned folder's basename.

## Go Library Dependencies

The scan phase uses these Go libraries (no external tools required on PATH):
- **github.com/anchore/syft** — SBOM generation
- **github.com/anchore/grype** — Vulnerability scanning (DB cached in `<UserCacheDir>/scat/grype-db`, e.g. `~/.cache` on Linux)
- **github.com/charmbracelet/bubbletea** + **bubbles** — TUI progress bar during pipeline execution
- License checking is a pure Go implementation (no external dependency)

The binary is fully self-contained.

## Conventions

- Go code follows standard `internal/` package layout
- Model types in `internal/model/` mirror CycloneDX and Grype data structures
- HTML template uses `go:embed` for self-contained binary
- Risk heuristic: Critical vulns → Critical risk, High vulns → High risk, >5 Medium vulns → Medium risk, otherwise Low
- Output files written to `--output-dir` (default: current directory)
- Version injected via ldflags at build time

## Release Rules

- **NEVER delete tags** — tags are immutable, even if a release is broken
- **NEVER re-create releases** on existing tags — instead, bump the version and create a new release
- When fixing a broken release, increment the micro (patch) version by default (e.g. `v0.1.0` → `v0.1.1`) unless told otherwise
