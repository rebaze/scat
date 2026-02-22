# Pipe Detection — Stay Explicit, No Auto-Detection

Status: CLOSED

## Summary

Investigated whether scat should auto-detect when stdout is piped and switch from HTML to Markdown automatically. Decision: no — the `-f` flag controls everything.

## Context

After implementing single-output-per-invocation (format flag determines output shape and destination), the question arose: should scat auto-detect when stdout is piped and switch from HTML to Markdown automatically?

## Findings

- **scat has no TTY detection** — behavior is entirely driven by the explicit `-f` flag
- **BubbleTea detects TTY internally** — calls `term.IsTerminal()` and degrades gracefully when stdout is not a terminal, so TUI escape codes won't garble a pipe
- **Dependencies already available** — `golang.org/x/term` (v0.40.0, indirect) and `mattn/go-isatty` (v0.0.20, indirect) are both in the dependency tree via BubbleTea, so adding detection would be zero new deps
- The gap: `scat analyze dir | llm` sends nothing useful into the pipe (HTML goes to file, pipe gets empty/degraded TUI text) — the user probably wanted `-f markdown`

## Decision: No code changes

Stay explicit — no auto-detection.

**Rationale:**
- Predictable — same command always produces the same output regardless of context
- Matches grype, trivy, jq, syft — explicit format flags, no pipe inference
- The README already documents `scat analyze -f markdown dir | ...` clearly
- Zero error surface from implicit behavior
