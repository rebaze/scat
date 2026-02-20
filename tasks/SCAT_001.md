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

## Design Decision: Policy Format

We considered using an established policy standard such as OPA/Rego or CEL instead of a custom YAML format. Trade-offs:

- **OPA/Rego**: Industry standard, highly expressive, but adds a heavy Go dependency, increases binary size, and has a steep learning curve for simple use cases (e.g., "block GPL, fail on critical").
- **CEL (Common Expression Language)**: Lighter than Rego, used by Kubernetes, but still an extra dependency and added complexity for straightforward threshold-based policies.
- **CycloneDX Policy**: Draft-stage work in the CycloneDX ecosystem; not mature enough to adopt yet.

**Decision**: Start with the simple declarative YAML format described above. It covers the majority of real-world use cases with zero learning curve. However, the internal policy evaluation should be designed behind a clean interface (`internal/policy/`) so that an OPA or CEL backend can be added later without changing the model or CLI surface.

## Implementation Notes

- New `internal/config/` package to load and validate `.scat.yaml`.
- New `internal/policy/` package to evaluate scan results against config. Design as an interface so alternative backends (OPA, CEL) can be plugged in later.
- `cmd/analyze.go` wires policy evaluation after scan, sets exit code.
- Dashboard and markdown reports should indicate policy pass/fail status.
- When no `.scat.yaml` is present, behaviour remains unchanged (exit 0, permissive).
