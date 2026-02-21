package report

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/rebaze/scat/internal/model"
)

func generateVulnReport(vulns *model.VulnReport, outPath, prefix, generatedAt string) error {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("# Vulnerability Report — %s\n\n", prefix))
	b.WriteString(fmt.Sprintf("**Generated:** %s\n", generatedAt))
	b.WriteString(fmt.Sprintf("**Source:** %s-vulns.json\n\n", prefix))

	counts := vulns.CountSeverities()

	// Summary table
	b.WriteString("## Summary\n\n")
	b.WriteString("| Severity | Count |\n")
	b.WriteString("|----------|-------|\n")
	b.WriteString(fmt.Sprintf("| Critical | %d |\n", counts.Critical))
	b.WriteString(fmt.Sprintf("| High | %d |\n", counts.High))
	b.WriteString(fmt.Sprintf("| Medium | %d |\n", counts.Medium))
	b.WriteString(fmt.Sprintf("| Low | %d |\n", counts.Low))
	b.WriteString(fmt.Sprintf("| Negligible | %d |\n", counts.Negligible))
	b.WriteString(fmt.Sprintf("| Unknown | %d |\n", counts.Unknown))
	b.WriteString(fmt.Sprintf("| **Total** | %d |\n\n", counts.Total))

	// Exploit intelligence summary
	kevCount, highEPSSCount := countExploitIntelligence(vulns)
	if kevCount > 0 || highEPSSCount > 0 {
		b.WriteString("## Exploit Intelligence\n\n")
		if kevCount > 0 {
			b.WriteString(fmt.Sprintf("- **CISA KEV:** %d vulnerabilit%s actively exploited in the wild\n", kevCount, pluralSuffix(kevCount)))
		}
		if highEPSSCount > 0 {
			b.WriteString(fmt.Sprintf("- **High EPSS:** %d vulnerabilit%s with exploit probability >= 70%%\n", highEPSSCount, pluralSuffix(highEPSSCount)))
		}
		b.WriteString("\n")
	}

	// Vulnerabilities by Severity
	b.WriteString("## Vulnerabilities by Severity\n\n")

	sorted := make([]model.Match, len(vulns.Matches))
	copy(sorted, vulns.Matches)
	sort.Slice(sorted, func(i, j int) bool {
		return severityOrder(sorted[i].Vulnerability.Severity) < severityOrder(sorted[j].Vulnerability.Severity)
	})

	for _, m := range sorted {
		b.WriteString(fmt.Sprintf("### %s — %s\n\n", m.Vulnerability.ID, m.Vulnerability.Severity))
		b.WriteString(fmt.Sprintf("- **Package:** %s %s\n", m.Artifact.Name, m.Artifact.Version))

		fixState := m.Vulnerability.Fix.State
		if fixState == "" {
			fixState = "unknown"
		}
		b.WriteString(fmt.Sprintf("- **Fix available:** %s\n", fixState))

		if m.Vulnerability.EPSS != nil {
			b.WriteString(fmt.Sprintf("- **EPSS score:** %.1f%%", *m.Vulnerability.EPSS*100))
			if m.Vulnerability.EPSSPercentile != nil {
				b.WriteString(fmt.Sprintf(" (percentile: %.1f%%)", *m.Vulnerability.EPSSPercentile*100))
			}
			b.WriteString("\n")
		}

		if m.Vulnerability.InKEV {
			b.WriteString("- **CISA KEV:** Yes — actively exploited in the wild\n")
			if m.Vulnerability.KEVDueDate != "" {
				b.WriteString(fmt.Sprintf("- **KEV due date:** %s\n", m.Vulnerability.KEVDueDate))
			}
		}

		desc := m.Vulnerability.Description
		if desc == "" {
			desc = "n/a"
		} else if len(desc) > 200 {
			desc = desc[:200]
		}
		b.WriteString(fmt.Sprintf("- **Description:** %s\n", desc))

		if m.Vulnerability.DataSource != "" {
			b.WriteString(fmt.Sprintf("- **Reference:** %s\n", m.Vulnerability.DataSource))
		}
		b.WriteString("\n")
	}

	return os.WriteFile(outPath, []byte(b.String()), 0o644)
}

func countExploitIntelligence(vulns *model.VulnReport) (kevCount, highEPSSCount int) {
	for _, m := range vulns.Matches {
		if m.Vulnerability.InKEV {
			kevCount++
		}
		if m.Vulnerability.EPSS != nil && *m.Vulnerability.EPSS >= 0.7 {
			highEPSSCount++
		}
	}
	return
}

func pluralSuffix(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

func severityOrder(sev string) int {
	switch sev {
	case "Critical":
		return 0
	case "High":
		return 1
	case "Medium":
		return 2
	case "Low":
		return 3
	case "Negligible":
		return 4
	default:
		return 5
	}
}
