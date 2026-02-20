# Scan Diff and Trend Comparison

Status: OPEN

## Summary

Add a `scat diff` command that compares two scan results and reports what changed: new vulnerabilities, fixed vulnerabilities, new components, removed components, and license changes. This makes scat useful across time rather than only as a point-in-time snapshot.

## Motivation

Teams running scat in CI see the full vulnerability list on every run and must manually determine what changed. grype and syft have no diff capability. Commercial SCA tools (Snyk, Dependabot) provide PR-level delta views, but they require SaaS accounts. A local, offline diff command would be a strong differentiator for CLI-first workflows.

## Scope

- **`scat diff <old-dir> <new-dir>`**: Compare two sets of scat JSON output files and produce a delta report.
- **Alternatively `scat diff --baseline <old-sbom.json> --current <new-sbom.json>`**: Compare specific JSON files.
- **Delta categories**:
  - New vulnerabilities (present in current, absent in baseline)
  - Fixed vulnerabilities (present in baseline, absent in current)
  - New components added
  - Components removed
  - Components with version changes (upgrades/downgrades)
  - License changes (component changed license between versions)
- **Output formats**: JSON diff, Markdown summary, optional HTML delta view.
- **Exit codes**: When combined with policy gate (SCAT_001), fail only on *new* violations rather than pre-existing ones. This enables incremental adoption.

## Example Output

```
Scan Diff: baseline (2024-01-15) → current (2024-01-22)

Vulnerabilities:
  + 3 new      (1 Critical, 2 Medium)
  - 2 fixed    (1 High, 1 Low)
  = 47 unchanged

Components:
  + 4 added    (lodash@4.17.21, axios@1.6.0, ...)
  - 1 removed  (moment@2.29.4)
  ~ 2 upgraded (react 18.2.0 → 18.3.1, express 4.18.2 → 4.19.0)
```

## Implementation Notes

- New `cmd/diff.go` with the `scat diff` Cobra command.
- New `internal/diff/` package with comparison logic for SBOM, vulns, and licenses.
- Matching is by CVE ID for vulns, by package name + PURL for components.
- Version comparison uses the PURL and component version fields, not semver parsing (ecosystems vary).
- The diff JSON output should be a standalone schema that other tools can consume.
- Consider storing a `.scat-baseline.json` in the project for easy `scat diff --against-baseline` usage.
