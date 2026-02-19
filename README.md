# scat

A Software Composition Analysis (SCA) toolchain. It generates a CycloneDX SBOM from a source directory, scans for known vulnerabilities, checks license compliance, and produces reports in JSON, Markdown, and HTML.

## scat CLI

`scat` is a single Go binary that runs the full pipeline in one command.

### Installation

**From source:**

```bash
go build -o scat .
```

**With Go install:**

```bash
go install github.com/rebaze/scat@latest
```

### Usage

```bash
# Full pipeline: scan → JSON → Markdown → HTML
scat analyze /path/to/my-project

# Output only JSON artifacts
scat analyze /path/to/my-project --format json

# Custom output directory
scat analyze /path/to/my-project -o ./reports

# Print version
scat version
```

### Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--output-dir` | `-o` | `.` | Directory for output files |
| `--format` | `-f` | `all` | Output format: `json`, `markdown`, `html`, `all` |
| `--verbose` | `-v` | `false` | Verbose output |
| `--quiet` | `-q` | `false` | Suppress non-error output |

### Output Files

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
       ├── <prefix>-licenses.json    (license evaluation via Grant)
       │
       ├── <prefix>-report-sbom.md
       ├── <prefix>-report-vulns.md
       ├── <prefix>-report-licenses.md
       │
       └── <prefix>-summary.html     (HTML dashboard)
```

## Prerequisites

The following tools must be available on `PATH`:

| Tool | Purpose |
|------|---------|
| [Syft](https://github.com/anchore/syft) | SBOM generation |
| [Grype](https://github.com/anchore/grype) | Vulnerability scanning |
| [Grant](https://github.com/anchore/grant) | License compliance |

