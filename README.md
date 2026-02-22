# scat

[![CI](https://github.com/rebaze/scat/actions/workflows/ci.yaml/badge.svg)](https://github.com/rebaze/scat/actions/workflows/ci.yaml)
[![Release](https://github.com/rebaze/scat/actions/workflows/release.yaml/badge.svg)](https://github.com/rebaze/scat/actions/workflows/release.yaml)
[![GitHub Release](https://img.shields.io/github/v/release/rebaze/scat)](https://github.com/rebaze/scat/releases/latest)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Go](https://img.shields.io/github/go-mod/go-version/rebaze/scat)](go.mod)

**Software Composition Analysis Tool** — that's what scat stands for.

An opinionated, self-contained CLI that answers the questions that matter: what's in your software, what's vulnerable, and what are the license obligations? One command, one output — an HTML dashboard for humans or Markdown for pipelines and LLMs.

## Features

- **CycloneDX SBOM** — industry-standard software bill of materials
- **Vulnerability scanning** — matches packages against known CVEs with severity scoring, enriched with EPSS exploit probability and CISA KEV (Known Exploited Vulnerabilities) data
- **License compliance** — detects and evaluates open-source licenses
- **HTML dashboard** — beautiful out-of-the-box light and dark mode report ready to share, with severity bars, risk heatmap, and print-friendly layout
- **Single binary** — no external tools required on PATH; Syft, Grype, and license checking are embedded as Go libraries
- **Two output formats** — HTML dashboard (default, file) or Markdown (stdout, pipe-friendly)

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

This runs the full pipeline and writes an HTML dashboard to the current directory. Open `my-project-summary.html` in a browser to explore results.

For pipeline or LLM consumption, use Markdown output on stdout:

```bash
scat analyze -f markdown /path/to/my-project | llm "summarize critical vulnerabilities"
scat analyze -f markdown /path/to/my-project > report.md
```

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
| `--format` | `-f` | `html` | Output format: `html` (file), `markdown` (stdout) |
| `--verbose` | `-v` | `false` | Verbose output |
| `--quiet` | `-q` | `false` | Suppress non-error output |

### Analyze Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--clear-cache` | `false` | Delete the cached Grype vulnerability database before scanning |

## Output

Each invocation produces **one output** — the format flag determines both the shape and the destination:

| Format | Destination | TUI progress | Files created |
|--------|-------------|--------------|---------------|
| `html` (default) | `<prefix>-summary.html` in `--output-dir` | stdout | `<prefix>-summary.html` |
| `markdown` | stdout | stderr | none |

The `<prefix>` is the basename of the scanned folder (e.g. `my-project` for `/path/to/my-project`).

`--output-dir` only applies to HTML output. For Markdown, use shell redirection (`> file.md`) to write to a file — this is simpler and more composable than a dedicated flag.

When using `-f markdown`, the TUI progress bar is routed to stderr so it stays visible in the terminal while stdout carries clean Markdown suitable for piping.

### Examples

```bash
# Default: HTML dashboard
scat analyze myproject
# → writes ./myproject-summary.html, TUI progress on terminal

# HTML to a specific directory
scat analyze -o /tmp myproject
# → writes /tmp/myproject-summary.html

# Markdown to terminal
scat analyze -f markdown myproject
# → TUI on stderr, Markdown on stdout

# Pipe to an LLM
scat analyze -f markdown myproject | llm "summarize critical vulnerabilities"

# Save Markdown to a file
scat analyze -f markdown myproject > report.md

# Quiet mode (no TUI)
scat analyze -q myproject
scat analyze -f markdown -q myproject
```

## Pipeline

```
  source folder
       │
       ▼
  scat analyze             → <prefix>-summary.html   (default)
  scat analyze -f markdown → stdout                   (pipe-friendly)
```

## License

[Apache-2.0](LICENSE)
