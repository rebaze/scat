# starter-sbom-toolchain

A lightweight shell-based toolchain for Software Composition Analysis (SCA). It generates a CycloneDX SBOM from a source directory, scans for known vulnerabilities, checks license compliance, and produces human-readable reports in Markdown and HTML.

## Pipeline

The toolchain runs in two stages:

```
  source folder
       │
       ▼
  sbom-scan.sh        ← Stage 1: Scan
       │
       ├── <prefix>-sbom.json        (CycloneDX SBOM)
       ├── <prefix>-vulns.json       (vulnerability matches)
       └── <prefix>-licenses.json    (license evaluation)
               │
       ┌───────┴───────┐
       ▼               ▼
  sbom-report.sh   sbom-summary.sh   ← Stage 2: Report
       │               │
       ├── *-report-sbom.md        <prefix>-summary.html
       ├── *-report-vulns.md
       └── *-report-licenses.md
```

### Stage 1: Scan

`sbom-scan.sh` takes a folder path, derives a prefix from its basename, and runs three tools in sequence:

1. **Syft** generates a CycloneDX JSON SBOM from the directory contents
2. **Grype** scans the SBOM for known vulnerabilities
3. **Grant** evaluates license compliance against the SBOM

All three JSON outputs are written to the current working directory.

```bash
./sbom-scan.sh /path/to/my-project
# produces: my-project-sbom.json, my-project-vulns.json, my-project-licenses.json
```

### Stage 2: Report

Two scripts consume the JSON files from Stage 1. Both take the prefix as their only argument.

**`sbom-report.sh`** generates three Markdown files covering the SBOM inventory, vulnerability details, and license status:

```bash
./sbom-report.sh my-project
# produces: my-project-report-sbom.md, my-project-report-vulns.md, my-project-report-licenses.md
```

**`sbom-summary.sh`** generates a single-page HTML dashboard with executive summary cards, a severity distribution bar, top vulnerabilities, ecosystem breakdown, and license distribution:

```bash
./sbom-summary.sh my-project
# produces: my-project-summary.html
```

The HTML report includes a risk level heuristic based on vulnerability severity counts.

## Prerequisites

The following tools must be available on `PATH`:

| Tool | Purpose |
|------|---------|
| [Syft](https://github.com/anchore/syft) | SBOM generation |
| [Grype](https://github.com/anchore/grype) | Vulnerability scanning |
| [Grant](https://github.com/anchore/grant) | License compliance |
| [jq](https://jqlang.github.io/jq/) | JSON processing |

## Quick Start

```bash
# 1. Scan a project
./sbom-scan.sh ./my-project

# 2. Generate reports (pick one or both)
./sbom-report.sh my-project      # Markdown reports
./sbom-summary.sh my-project     # HTML dashboard

# 3. View the HTML summary
open my-project-summary.html     # macOS
xdg-open my-project-summary.html # Linux
```
