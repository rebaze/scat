# scat

[![CI](https://github.com/rebaze/scat/actions/workflows/ci.yaml/badge.svg)](https://github.com/rebaze/scat/actions/workflows/ci.yaml)
[![Release](https://github.com/rebaze/scat/actions/workflows/release.yaml/badge.svg)](https://github.com/rebaze/scat/actions/workflows/release.yaml)
[![GitHub Release](https://img.shields.io/github/v/release/rebaze/scat)](https://github.com/rebaze/scat/releases/latest)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Go](https://img.shields.io/github/go-mod/go-version/rebaze/scat)](go.mod)

**Software Composition Analysis Tool** — that's what scat stands for.

An opinionated, self-contained CLI that answers the questions that matter: what's in your software, what's vulnerable, and what are the license obligations? One command, one HTML dashboard — not a pile of artifacts you need another tool to interpret.

## Features

- **CycloneDX SBOM** — industry-standard software bill of materials
- **Vulnerability scanning** — matches packages against known CVEs with severity scoring
- **License compliance** — detects and evaluates open-source licenses
- **HTML dashboard** — interactive report with severity bars, risk heatmap, and print-friendly layout
- **Single binary** — no external tools required on PATH; Syft, Grype, and license checking are embedded as Go libraries
- **Multiple output formats** — JSON, Markdown, and HTML in one run

## Installation

### Homebrew (recommended)

```bash
brew install rebaze/tap/scat
```

### Go install

```bash
go install github.com/rebaze/scat@latest
```

### From source

```bash
git clone https://github.com/rebaze/scat.git
cd scat
make build    # injects version, commit, and build date via ldflags
```

## Quick Start

```bash
scat analyze /path/to/my-project
```

This runs the full pipeline and writes JSON data files, Markdown reports, and an HTML dashboard to the current directory. Open `my-project-summary.html` in a browser to explore results.

## CLI Reference

### Commands

| Command | Description |
|---------|-------------|
| `scat analyze <folder>` | Run the full scan-and-report pipeline |
| `scat version` | Print version information |

### Global Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--output-dir` | `-o` | `.` | Directory for output files |
| `--format` | `-f` | `all` | Output format: `json`, `markdown`, `html`, `all` |
| `--verbose` | `-v` | `false` | Verbose output |
| `--quiet` | `-q` | `false` | Suppress non-error output |

### Analyze Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--clear-cache` | `false` | Delete the cached Grype vulnerability database before scanning |

## Output Files

For a project named `my-project`, `scat analyze` produces:

| File | Format | Description |
|------|--------|-------------|
| `my-project-sbom.json` | JSON | CycloneDX SBOM |
| `my-project-vulns.json` | JSON | Vulnerability matches |
| `my-project-licenses.json` | JSON | License evaluation |
| `my-project-report-sbom.md` | Markdown | SBOM inventory report |
| `my-project-report-vulns.md` | Markdown | Vulnerability details |
| `my-project-report-licenses.md` | Markdown | License compliance report |
| `my-project-summary.html` | HTML | Dashboard with severity bars, risk scoring, and print layout |

## Pipeline

```
  source folder
       │
       ▼
  scat analyze        ← Single command
       │
       ├── <prefix>-sbom.json        (CycloneDX SBOM via Syft)
       ├── <prefix>-vulns.json       (vulnerability matches via Grype)
       ├── <prefix>-licenses.json    (license evaluation)
       │
       ├── <prefix>-report-sbom.md
       ├── <prefix>-report-vulns.md
       ├── <prefix>-report-licenses.md
       │
       └── <prefix>-summary.html     (HTML dashboard)
```

## License

[Apache-2.0](LICENSE)
