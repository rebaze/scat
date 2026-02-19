package report

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"

	"github.com/rebaze/starter-sbom-toolchain/internal/model"
)

//go:embed templates/summary.html.tmpl
var templateFS embed.FS

type htmlData struct {
	Prefix          string
	GeneratedAt     string
	TotalComponents int
	Sev             model.SeverityCounts
	Risk            model.RiskLevel

	// Vulnerability percentages for severity bar
	PctCritical   string
	PctHigh       string
	PctMedium     string
	PctLow        string
	PctNegligible string
	NegligibleTotal int // Negligible + Unknown combined (matches bash behavior)

	CritHighVulns []vulnRow

	// License summary
	LicDenied     int
	LicUnlicensed int
	LicUnique     int
	LicNonSPDX    int

	Ecosystems  []keyCount
	LicenseDist []keyCount

	DeniedTotal int
	DeniedPkgs  []deniedRow
}

type vulnRow struct {
	ID       string
	Severity string
	SevClass string
	Package  string
	Version  string
	Fix      string
}

type deniedRow struct {
	Name     string
	Version  string
	Licenses string
}

// GenerateHTML produces the HTML summary dashboard.
func GenerateHTML(result *model.ScanResult, prefix, outDir, generatedAt string) (string, error) {
	outPath := filepath.Join(outDir, prefix+"-summary.html")

	sev := result.Vulns.CountSeverities()
	risk := model.ComputeRisk(sev)

	// Combine Negligible + Unknown to match bash script behavior
	negligibleTotal := sev.Negligible + sev.Unknown

	data := htmlData{
		Prefix:          prefix,
		GeneratedAt:     generatedAt,
		TotalComponents: len(result.SBOM.Components),
		Sev:             sev,
		Risk:            risk,
		NegligibleTotal: negligibleTotal,
	}

	// Severity bar percentages
	if sev.Total > 0 {
		data.PctCritical = pct(sev.Critical, sev.Total)
		data.PctHigh = pct(sev.High, sev.Total)
		data.PctMedium = pct(sev.Medium, sev.Total)
		data.PctLow = pct(sev.Low, sev.Total)
		data.PctNegligible = pct(negligibleTotal, sev.Total)
	}

	// Critical + High vulns table
	data.CritHighVulns = buildCritHighVulns(result.Vulns)

	// License summary (from first target)
	if len(result.License.Run.Targets) > 0 {
		t := result.License.Run.Targets[0]
		data.LicDenied = t.Evaluation.Summary.Packages.Denied
		data.LicUnlicensed = t.Evaluation.Summary.Packages.Unlicensed
		data.LicUnique = t.Evaluation.Summary.Licenses.Unique
		data.LicNonSPDX = t.Evaluation.Summary.Licenses.NonSPDX
	}

	// Ecosystems
	data.Ecosystems = countByField(result.SBOM.Components, func(c model.Component) string {
		return extractPURLScheme(c.PURL)
	})

	// License distribution
	data.LicenseDist = gatherLicenseDistribution(result.License)

	// Denied packages
	denied := gatherDeniedPackages(result.License)
	data.DeniedTotal = len(denied)
	limit := 20
	if len(denied) < limit {
		limit = len(denied)
	}
	for _, p := range denied[:limit] {
		name := p.Name
		if name == "" {
			name = "unknown"
		}
		version := p.Version
		if version == "" {
			version = "-"
		}
		licenses := strings.Join(p.Licenses, ", ")
		if licenses == "" {
			licenses = "n/a"
		}
		data.DeniedPkgs = append(data.DeniedPkgs, deniedRow{
			Name:     name,
			Version:  version,
			Licenses: licenses,
		})
	}

	tmpl, err := template.ParseFS(templateFS, "templates/summary.html.tmpl")
	if err != nil {
		return "", fmt.Errorf("parsing HTML template: %w", err)
	}

	f, err := os.Create(outPath)
	if err != nil {
		return "", fmt.Errorf("creating HTML file: %w", err)
	}
	defer f.Close()

	if err := tmpl.Execute(f, data); err != nil {
		return "", fmt.Errorf("executing HTML template: %w", err)
	}

	return outPath, nil
}

func pct(count, total int) string {
	if total == 0 {
		return "0"
	}
	return fmt.Sprintf("%.1f", float64(count)*100.0/float64(total))
}

func buildCritHighVulns(vulns *model.VulnReport) []vulnRow {
	var rows []vulnRow
	for _, m := range vulns.Matches {
		sev := m.Vulnerability.Severity
		if sev != "Critical" && sev != "High" {
			continue
		}
		fix := m.Vulnerability.Fix.State
		if fix == "" {
			fix = "unknown"
		}
		version := m.Artifact.Version
		if version == "" {
			version = "-"
		}
		rows = append(rows, vulnRow{
			ID:       m.Vulnerability.ID,
			Severity: sev,
			SevClass: strings.ToLower(sev),
			Package:  m.Artifact.Name,
			Version:  version,
			Fix:      fix,
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		return severityOrder(rows[i].Severity) < severityOrder(rows[j].Severity)
	})
	return rows
}
