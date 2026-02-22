# Harden repo for OpenSSF Scorecard

Status: CLOSED

## Summary

Improve the OpenSSF Scorecard score by addressing five failing checks that can be fixed entirely from repo-level changes.

## Motivation

The Scorecard workflow and badge were added but the repo scores poorly out of the box. Proactively fixing these checks should raise the score from ~4-5 to ~7-8.

## Scope

| Check | Fix |
|-------|-----|
| Security-Policy | Create `SECURITY.md` |
| Dependency-Update-Tool | Create `.github/dependabot.yml` |
| SAST | Create `.github/workflows/codeql.yaml` |
| Token-Permissions | Add `permissions` blocks to workflows |
| Pinned-Dependencies | SHA-pin all GitHub Actions |

Out of scope: Branch-Protection, Code-Review (require GitHub UI settings), Signed-Releases, Fuzzing (deeper infrastructure).
