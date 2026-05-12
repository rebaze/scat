# Contributing to scat

Thanks for your interest in improving scat. This document describes how to propose changes and what makes a contribution acceptable.

## Reporting issues

Use [GitHub Issues](https://github.com/rebaze/scat/issues) for bug reports and feature requests. For security vulnerabilities, follow the disclosure process in [SECURITY.md](SECURITY.md) instead — please do not file public issues for security problems.

## Proposing changes

scat uses a fork + pull-request workflow:

1. Fork the repository and create a topic branch off `main`.
2. Make your change in small, focused commits.
3. Open a pull request against `main`.

Direct pushes to `main` are not permitted. Every change lands through a PR.

## Acceptable-contribution requirements

A PR is ready for review once **all** of the following hold:

- **Formatted** — Go code is `gofmt`-clean (`gofmt -l .` returns no output).
- **Vetted** — `go vet ./...` is clean.
- **Tested** — `go test ./...` passes. New behaviour ships with tests; bug fixes ship with a regression test where practical.
- **Builds** — `go build ./...` succeeds on the Go toolchain pinned in `go.mod`.
- **GoReleaser config valid** — if you touch `.goreleaser.yaml`, run `goreleaser check` locally.
- **Scoped** — keep PRs focused on a single change. Unrelated refactors and formatting churn belong in separate PRs.
- **Conventional in spirit** — commit messages explain the *why*, not just the *what*. Reference any related issue or `tasks/SCAT_NNN.md` task file.

CI enforces the first four automatically: `build` and `Analyze Go` (CodeQL) are required status checks on `main`, and the branch must be up to date before merging. Merges use squash or rebase — merge commits on `main` are disallowed by the repository ruleset.

## Project layout

See [CLAUDE.md](CLAUDE.md) for a tour of the repository structure, the scan pipeline, conventions for the `internal/` packages, and release rules. It is written for AI assistants but is also the most concise human-readable orientation to the codebase.

## Task tracking

Larger pieces of work are tracked as files under `tasks/` (`SCAT_NNN.md`). The format is documented in [CLAUDE.md](CLAUDE.md#task-tracking). You don't need to create a task file for small changes; reference an existing one in your PR if it applies.

## Licensing

By submitting a contribution you agree to license it under the terms of the project's [Apache License 2.0](LICENSE). No CLA or DCO sign-off is required.
