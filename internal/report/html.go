package report

import (
	"embed"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"

	"github.com/rebaze/scat/internal/model"
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

	AllVulns []vulnRow

	// Enrichment
	EPSSAvailable bool
	KEVAvailable  bool
	KEVCount      int
	MaxEPSS       string // formatted: "33.3%" (highest EPSS across all vulns)
	FixedCount    int    // vulns where Fix == "fixed"
	UnfixedCount  int    // vulns where Fix != "fixed"

	// License summary
	LicDenied     int
	LicUnlicensed int
	LicUnique     int
	LicNonSPDX    int

	Ecosystems  []keyCount
	EcoMax      int // largest ecosystem count (for bar chart scaling)
	LicenseDist []keyCount

	DeniedTotal int
	DeniedPkgs  []deniedRow

	Components []componentRow

	// Donut chart arc data (circumference = 314.16 for r=50)
	DonutCriticalDash string
	DonutCriticalOff  string
	DonutHighDash     string
	DonutHighOff      string
	DonutMediumDash   string
	DonutMediumOff    string
	DonutLowDash      string
	DonutLowOff       string
	DonutNegDash      string
	DonutNegOff       string
}

type vulnRow struct {
	ID       string
	Severity string
	SevClass string
	SevOrder int
	Package  string
	Version  string
	Fix      string
	EPSS     string  // formatted display string
	EPSSPct  string  // percentage for micro-bar width (e.g. "12.3")
	EPSSRaw  float64 // raw value for sorting
	InKEV    bool
	KEVDueDate string
}

type deniedRow struct {
	Name     string
	Version  string
	Licenses string
}

type componentRow struct {
	Name      string
	Version   string
	Ecosystem string
	Locations string
}

// GenerateHTML produces the HTML summary dashboard.
func GenerateHTML(result *model.ScanResult, prefix, outDir, generatedAt string) (string, error) {
	outPath := filepath.Join(outDir, prefix+"-summary.html")

	sev := result.Vulns.CountSeverities()
	risk := model.ComputeRisk(sev, result.Vulns)

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

	// Donut chart arcs (circumference = 2 * π * 50 = 314.159...)
	if sev.Total > 0 {
		const circ = 2 * math.Pi * 50
		offset := 0.0
		arcLen := func(count int) float64 { return float64(count) / float64(sev.Total) * circ }

		cArc := arcLen(sev.Critical)
		data.DonutCriticalDash = fmt.Sprintf("%.2f %.2f", cArc, circ-cArc)
		data.DonutCriticalOff = fmt.Sprintf("%.2f", -offset)
		offset += cArc

		hArc := arcLen(sev.High)
		data.DonutHighDash = fmt.Sprintf("%.2f %.2f", hArc, circ-hArc)
		data.DonutHighOff = fmt.Sprintf("%.2f", -offset)
		offset += hArc

		mArc := arcLen(sev.Medium)
		data.DonutMediumDash = fmt.Sprintf("%.2f %.2f", mArc, circ-mArc)
		data.DonutMediumOff = fmt.Sprintf("%.2f", -offset)
		offset += mArc

		lArc := arcLen(sev.Low)
		data.DonutLowDash = fmt.Sprintf("%.2f %.2f", lArc, circ-lArc)
		data.DonutLowOff = fmt.Sprintf("%.2f", -offset)
		offset += lArc

		nArc := arcLen(negligibleTotal)
		data.DonutNegDash = fmt.Sprintf("%.2f %.2f", nArc, circ-nArc)
		data.DonutNegOff = fmt.Sprintf("%.2f", -offset)
	}

	// Enrichment flags
	data.EPSSAvailable = result.EPSSAvailable
	data.KEVAvailable = result.KEVAvailable

	// All vulns table
	data.AllVulns = buildAllVulns(result.Vulns)

	// Single-pass: count KEV entries, track max EPSS, count fix status
	var maxEPSS float64
	for _, row := range data.AllVulns {
		if row.InKEV {
			data.KEVCount++
		}
		if row.EPSSRaw > maxEPSS {
			maxEPSS = row.EPSSRaw
		}
		if row.Fix == "fixed" {
			data.FixedCount++
		} else {
			data.UnfixedCount++
		}
	}
	if maxEPSS > 0 {
		data.MaxEPSS = fmt.Sprintf("%.1f%%", maxEPSS*100)
	}

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
	for _, ec := range data.Ecosystems {
		if ec.Count > data.EcoMax {
			data.EcoMax = ec.Count
		}
	}

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

	// Component inventory with source locations
	for _, c := range result.SBOM.Components {
		loc := strings.Join(c.Locations, ", ")
		if loc == "" {
			loc = "-"
		}
		data.Components = append(data.Components, componentRow{
			Name:      c.Name,
			Version:   c.Version,
			Ecosystem: extractPURLScheme(c.PURL),
			Locations: loc,
		})
	}

	funcMap := template.FuncMap{
		"pctOf": func(count, max int) string {
			if max == 0 {
				return "0"
			}
			return fmt.Sprintf("%.1f", float64(count)*100.0/float64(max))
		},
	}

	tmpl, err := template.New("summary.html.tmpl").Funcs(funcMap).ParseFS(templateFS, "templates/summary.html.tmpl")
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

func buildAllVulns(vulns *model.VulnReport) []vulnRow {
	var rows []vulnRow
	for _, m := range vulns.Matches {
		sev := m.Vulnerability.Severity
		if sev == "" {
			sev = "Unknown"
		}
		fix := m.Vulnerability.Fix.State
		if fix == "" {
			fix = "unknown"
		}
		version := m.Artifact.Version
		if version == "" {
			version = "-"
		}
		row := vulnRow{
			ID:       m.Vulnerability.ID,
			Severity: sev,
			SevClass: strings.ToLower(sev),
			SevOrder: severityOrder(sev),
			Package:  m.Artifact.Name,
			Version:  version,
			Fix:      fix,
			InKEV:    m.Vulnerability.InKEV,
			KEVDueDate: m.Vulnerability.KEVDueDate,
		}
		if m.Vulnerability.EPSS != nil {
			row.EPSSRaw = *m.Vulnerability.EPSS
			row.EPSS = fmt.Sprintf("%.1f%%", *m.Vulnerability.EPSS*100)
			row.EPSSPct = fmt.Sprintf("%.1f", *m.Vulnerability.EPSS*100)
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool {
		return severityOrder(rows[i].Severity) < severityOrder(rows[j].Severity)
	})
	return rows
}
