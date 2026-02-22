---
name: scat
description: >
  Scan a project for vulnerabilities, license obligations, and generate an SBOM.
  Use when the user asks about software composition analysis, dependency security,
  CVEs, license compliance, or supply chain risks.
allowed-tools: Bash, Read
---

# scat — Software Composition Analysis Tool

SBOM + vulnerability scanning + license compliance in one command. Produces structured Markdown on stdout, ready for agent consumption.

## Prerequisites

`scat` must be on PATH. Install via:

```bash
brew install rebaze/tap/scat
```

or:

```bash
go install github.com/rebaze/scat@latest
```

## How to invoke

For agent use, always run with quiet mode and markdown output:

```bash
scat -f markdown -q <path>
```

This suppresses the TUI progress bar and writes clean Markdown to stdout.

## Flags reference

| Flag | Short | Description |
|------|-------|-------------|
| `--format` | `-f` | Output format: `markdown` (stdout) or `html` (file) |
| `--quiet` | `-q` | Suppress TUI progress bar |
| `--output-dir` | `-o` | Directory for HTML output files (default: `.`) |
| `--clear-cache` | | Re-download the Grype vulnerability database before scanning |

## Interpreting the output

The Markdown report contains these sections in order:

1. **SBOM** — table of all detected packages with name, version, type, and license
2. **Vulnerabilities** — table with CVE ID, package, installed version, fixed version, severity (Critical/High/Medium/Low), EPSS probability, and CISA KEV status
3. **License summary** — grouped by license type with risk assessment
4. **Risk assessment** — overall risk level (Critical, High, Medium, Low) based on vulnerability findings

## Examples

Scan the current project:

```bash
scat -f markdown -q .
```

Scan and save to a file:

```bash
scat -f markdown -q . > sca-report.md
```

HTML dashboard for human review:

```bash
scat .
```
