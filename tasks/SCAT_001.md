# Policy Gate and Configuration File

Status: OPEN

## Summary

Add a policy engine with non-zero exit codes and a `.scat.yaml` project configuration file. This transforms scat from a reporter into a CI/CD enforcer.

## Motivation

grype offers a bare `--fail-on` severity flag but has no license policy, no ignore list, and no config file. scat currently always exits 0 regardless of findings and has a hardcoded permissive license policy. Teams adopting scat in CI need the tool to *block* a build when policy is violated.

## Scope

- **Config file** (`.scat.yaml`): project-level settings for severity thresholds, license deny/allow lists, and ignored CVEs with justification.
- **Exit codes**: `scat analyze` returns non-zero when policy violations are found.
- **License enforcement**: Deny specific SPDX identifiers (e.g., GPL-3.0, AGPL-3.0), optionally fail on unlicensed packages.
- **Vulnerability threshold**: Fail on configurable minimum severity (e.g., `high` means any High or Critical vuln fails the gate).
- **Ignore list**: Suppress specific CVEs by ID with required justification text.
- **Unfixed filter**: Option to only fail on vulnerabilities that have a known fix.

## Example Configuration

```yaml
fail-on:
  severity: high
  unfixed: false
licenses:
  deny: [GPL-3.0-only, GPL-3.0-or-later, AGPL-3.0-only]
  allow-unlicensed: false
ignore:
  - id: CVE-2024-1234
    reason: "Accepted risk, tracked in JIRA-567"
  - id: CVE-2024-5678
    reason: "Not reachable in our usage"
```

## Implementation Notes

- New `internal/config/` package to load and validate `.scat.yaml`.
- New `internal/policy/` package to evaluate scan results against config.
- `cmd/analyze.go` wires policy evaluation after scan, sets exit code.
- Dashboard and markdown reports should indicate policy pass/fail status.
- When no `.scat.yaml` is present, behaviour remains unchanged (exit 0, permissive).
