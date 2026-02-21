# EPSS and KEV Vulnerability Enrichment

Status: CLOSED

## Summary

Enrich vulnerability findings with EPSS (Exploit Prediction Scoring System) scores and CISA KEV (Known Exploited Vulnerabilities) data to enable prioritisation based on real-world exploitability rather than CVSS severity alone.

## Motivation

A Medium-severity vulnerability with a 94% EPSS probability of exploitation is more urgent than a High-severity one with 0.1%. CISA KEV flags vulnerabilities actively exploited in the wild. No CLI-based SCA scanner integrates these signals today — grype, syft, and trivy all report raw CVSS severity only. This would be a clear differentiator.

## Scope

- **EPSS enrichment**: Fetch the EPSS CSV dataset from FIRST.org and match by CVE ID. Add EPSS probability (0.0–1.0) and percentile to each vulnerability.
- **KEV enrichment**: Fetch the CISA KEV JSON catalog and flag matching CVE IDs. Surface the due date and required action where available.
- **Dashboard integration**: Add EPSS score column and KEV badge to the HTML vulnerability table. Allow sorting by EPSS score.
- **Markdown integration**: Add EPSS and KEV columns to the vulnerability report.
- **Risk heuristic update**: Factor EPSS/KEV into the risk scoring — e.g., a Medium vuln in KEV could elevate overall risk to High.
- **Caching**: Cache EPSS and KEV data locally alongside the Grype DB to avoid re-downloading on every scan.

## Data Sources

- EPSS: `https://epss.cyentia.com/epss_scores-YYYY-MM-DD.csv.gz` (updated daily, ~30 MB compressed)
- KEV: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` (~300 KB)

## Implementation Notes

- New `internal/enrich/` package with `epss.go` and `kev.go`.
- Extend `model.Vulnerability` with `EPSS *float64`, `EPSSPercentile *float64`, `InKEV bool`, `KEVDueDate *string`.
- Enrichment runs as a pipeline step after vulnerability scanning, before report generation.
- New TUI step: "Enriching with exploit intelligence".
- Offline mode: if fetch fails, proceed without enrichment and note it in the report.
