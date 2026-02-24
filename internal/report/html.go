package report

import (
	"embed"
	"encoding/base64"
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

//go:embed assets/Rebaze_hlogo_bw_tbg.png
var logoHeaderPNG []byte

//go:embed assets/Rebaze_icon_bw_tbg.png
var logoFooterPNG []byte

type htmlData struct {
	Prefix          string
	GeneratedAt     string
	TotalComponents int
	Sev             model.SeverityCounts
	Risk            model.RiskLevel

	// Unbranded mode: omit Rebaze logos, show project attribution in footer
	Unbranded bool
	Version   string // e.g. "v0.3.2" — shown in unbranded footer

	// Embedded logos as base64 data URIs
	LogoHeader string
	LogoFooter string

	// Scan metadata
	TargetPath string
	FileCount  int
	TotalSize  string // pre-formatted: "12.4 MB"
	Hash       string // short hash: first 12 chars

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

	// Unified component details (master table)
	ComponentDetails    []componentDetail
	ComponentsWithVulns int
	ComponentsWithDenied int
	ComponentsClean     int

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

// componentDetail is a unified row merging SBOM + vulns + licenses per component.
type componentDetail struct {
	Name      string
	Version   string
	Ecosystem string
	Locations string

	// Vulnerability summary
	Vulns         []vulnRow
	VulnCritical  int
	VulnHigh      int
	VulnMedium    int
	VulnLow       int
	VulnOther     int
	VulnTotal     int
	WorstSevOrder int    // 0=Critical..5=Unknown (for sorting)
	WorstSevClass string // CSS class of worst severity

	// License info
	Licenses      []licenseDetail
	LicenseStatus string // "allowed", "denied", "unlicensed", "unknown"

	// EOL placeholder
	EOLStatus      string // always "unknown" for now
	VersionsBehind string // always "n/a" for now
}

type licenseDetail struct {
	Name       string
	StatusClass string // "allowed", "denied", "unlicensed"
}

// GenerateHTML produces the HTML summary dashboard.
func GenerateHTML(result *model.ScanResult, prefix, outDir, generatedAt, version string, unbranded bool) (string, error) {
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
		Unbranded:       unbranded,
		Version:         version,
	}

	if !unbranded {
		data.LogoHeader = "data:image/png;base64," + base64.StdEncoding.EncodeToString(logoHeaderPNG)
		data.LogoFooter = "data:image/png;base64," + base64.StdEncoding.EncodeToString(logoFooterPNG)
	}

	if result.Metadata != nil {
		data.TargetPath = result.Metadata.TargetPath
		data.FileCount = result.Metadata.FileCount
		data.TotalSize = humanSize(result.Metadata.TotalSize)
		data.Hash = result.Metadata.Hash
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

	// Unified component details (master table)
	data.ComponentDetails = buildComponentDetails(result)
	for _, cd := range data.ComponentDetails {
		switch {
		case cd.VulnTotal > 0:
			data.ComponentsWithVulns++
		case cd.LicenseStatus == "denied" || cd.LicenseStatus == "unlicensed":
			data.ComponentsWithDenied++
		default:
			data.ComponentsClean++
		}
	}

	funcMap := template.FuncMap{
		"pctOf": func(count, max int) string {
			if max == 0 {
				return "0"
			}
			return fmt.Sprintf("%.1f", float64(count)*100.0/float64(max))
		},
		"commaInt": func(n int) string {
			s := fmt.Sprintf("%d", n)
			if len(s) <= 3 {
				return s
			}
			var result []byte
			for i, c := range s {
				if i > 0 && (len(s)-i)%3 == 0 {
					result = append(result, ',')
				}
				result = append(result, byte(c))
			}
			return string(result)
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

func humanSize(b int64) string {
	const (
		kb = 1024
		mb = 1024 * kb
		gb = 1024 * mb
	)
	switch {
	case b >= gb:
		return fmt.Sprintf("%.1f GB", float64(b)/float64(gb))
	case b >= mb:
		return fmt.Sprintf("%.1f MB", float64(b)/float64(mb))
	case b >= kb:
		return fmt.Sprintf("%.1f KB", float64(b)/float64(kb))
	default:
		return fmt.Sprintf("%d B", b)
	}
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

// buildComponentDetails performs a three-way join of SBOM components, vuln matches,
// and license findings into a unified per-component view.
func buildComponentDetails(result *model.ScanResult) []componentDetail {
	// Index vuln matches by lowercase(name)@version
	vulnIndex := map[string][]vulnRow{}
	for _, m := range result.Vulns.Matches {
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
			ID:         m.Vulnerability.ID,
			Severity:   sev,
			SevClass:   strings.ToLower(sev),
			SevOrder:   severityOrder(sev),
			Package:    m.Artifact.Name,
			Version:    version,
			Fix:        fix,
			InKEV:      m.Vulnerability.InKEV,
			KEVDueDate: m.Vulnerability.KEVDueDate,
		}
		if m.Vulnerability.EPSS != nil {
			row.EPSSRaw = *m.Vulnerability.EPSS
			row.EPSS = fmt.Sprintf("%.1f%%", *m.Vulnerability.EPSS*100)
			row.EPSSPct = fmt.Sprintf("%.1f", *m.Vulnerability.EPSS*100)
		}
		key := strings.ToLower(m.Artifact.Name) + "@" + m.Artifact.Version
		vulnIndex[key] = append(vulnIndex[key], row)
	}

	// Index license findings by lowercase(name)@version
	type licInfo struct {
		Licenses []licenseDetail
		Status   string // worst status: denied > unlicensed > allowed
	}
	licIndex := map[string]licInfo{}
	for _, target := range result.License.Run.Targets {
		for _, pkg := range target.Evaluation.Findings.Packages {
			key := strings.ToLower(pkg.Name) + "@" + pkg.Version
			var details []licenseDetail
			for _, l := range pkg.Licenses {
				sc := "allowed"
				if pkg.Status == "denied" {
					sc = "denied"
				}
				details = append(details, licenseDetail{Name: l, StatusClass: sc})
			}
			if len(pkg.Licenses) == 0 {
				details = append(details, licenseDetail{Name: "UNLICENSED", StatusClass: "unlicensed"})
			}
			status := pkg.Status
			if status == "" {
				if len(pkg.Licenses) == 0 {
					status = "unlicensed"
				} else {
					status = "allowed"
				}
			}
			licIndex[key] = licInfo{Licenses: details, Status: status}
		}
	}

	// Build unified list from SBOM components
	var details []componentDetail
	for _, c := range result.SBOM.Components {
		loc := strings.Join(c.Locations, ", ")
		if loc == "" {
			loc = "-"
		}
		eco := extractPURLScheme(c.PURL)

		d := componentDetail{
			Name:           c.Name,
			Version:        c.Version,
			Ecosystem:      eco,
			Locations:      loc,
			WorstSevOrder:  6, // higher than any severity = no vulns
			WorstSevClass:  "",
			LicenseStatus:  "unknown",
			EOLStatus:      "unknown",
			VersionsBehind: "n/a",
		}

		// Merge vulns
		key := strings.ToLower(c.Name) + "@" + c.Version
		if vulns, ok := vulnIndex[key]; ok {
			// Sort vulns by severity
			sort.Slice(vulns, func(i, j int) bool {
				return vulns[i].SevOrder < vulns[j].SevOrder
			})
			d.Vulns = vulns
			d.VulnTotal = len(vulns)
			for _, v := range vulns {
				switch v.Severity {
				case "Critical":
					d.VulnCritical++
				case "High":
					d.VulnHigh++
				case "Medium":
					d.VulnMedium++
				case "Low":
					d.VulnLow++
				default:
					d.VulnOther++
				}
				if v.SevOrder < d.WorstSevOrder {
					d.WorstSevOrder = v.SevOrder
					d.WorstSevClass = v.SevClass
				}
			}
		}

		// Merge licenses
		if li, ok := licIndex[key]; ok {
			d.Licenses = li.Licenses
			d.LicenseStatus = li.Status
		}

		details = append(details, d)
	}

	// Sort: worst severity first (lower order = worse), then alphabetical
	sort.Slice(details, func(i, j int) bool {
		if details[i].WorstSevOrder != details[j].WorstSevOrder {
			return details[i].WorstSevOrder < details[j].WorstSevOrder
		}
		return strings.ToLower(details[i].Name) < strings.ToLower(details[j].Name)
	})

	return details
}
