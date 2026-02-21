package model

// CycloneDX SBOM (subset of fields we use for reporting)

type SBOM struct {
	BOMFormat    string      `json:"bomFormat"`
	SpecVersion  string      `json:"specVersion"`
	SerialNumber string      `json:"serialNumber"`
	Components   []Component `json:"components"`
}

type Component struct {
	Name      string   `json:"name"`
	Version   string   `json:"version"`
	Type      string   `json:"type"`
	PURL      string   `json:"purl"`
	Locations []string `json:"-"` // populated from CycloneDX syft:location properties
}

// Grype vulnerability report

type VulnReport struct {
	Matches []Match `json:"matches"`
}

type Match struct {
	Vulnerability Vulnerability `json:"vulnerability"`
	Artifact      Artifact      `json:"artifact"`
}

type Vulnerability struct {
	ID          string   `json:"id"`
	Severity    string   `json:"severity"`
	Description string   `json:"description"`
	DataSource  string   `json:"dataSource"`
	RelatedCVEs []string `json:"relatedCVEs,omitempty"` // CVE IDs from Grype RelatedVulnerabilities
	Fix         VulnFix  `json:"fix"`

	// Enrichment fields (populated by enrich package)
	EPSS              *float64 `json:"epss,omitempty"`
	EPSSPercentile    *float64 `json:"epssPercentile,omitempty"`
	InKEV             bool     `json:"inKEV,omitempty"`
	KEVDueDate        string   `json:"kevDueDate,omitempty"`
	KEVRequiredAction string   `json:"kevRequiredAction,omitempty"`
}

type VulnFix struct {
	State string `json:"state"`
}

type Artifact struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Grant license report

type LicenseReport struct {
	Run LicenseRun `json:"run"`
}

type LicenseRun struct {
	Targets []LicenseTarget `json:"targets"`
}

type LicenseTarget struct {
	Source     LicenseSource     `json:"source"`
	Evaluation LicenseEvaluation `json:"evaluation"`
}

type LicenseSource struct {
	Ref string `json:"ref"`
}

type LicenseEvaluation struct {
	Status   string          `json:"status"`
	Summary  LicenseSummary  `json:"summary"`
	Findings LicenseFindings `json:"findings"`
}

type LicenseSummary struct {
	Packages PackageSummary `json:"packages"`
	Licenses LicenseMetrics `json:"licenses"`
}

type PackageSummary struct {
	Total      int `json:"total"`
	Allowed    int `json:"allowed"`
	Denied     int `json:"denied"`
	Ignored    int `json:"ignored"`
	Unlicensed int `json:"unlicensed"`
}

type LicenseMetrics struct {
	Unique  int `json:"unique"`
	Allowed int `json:"allowed"`
	Denied  int `json:"denied"`
	NonSPDX int `json:"nonSPDX"`
}

type LicenseFindings struct {
	Packages []LicensePackage `json:"packages"`
}

type LicensePackage struct {
	Name     string   `json:"name"`
	Version  string   `json:"version"`
	Licenses []string `json:"licenses"`
	Status   string   `json:"status"`
}

// Aggregate scan result

type ScanResult struct {
	SBOM    *SBOM
	Vulns   *VulnReport
	License *LicenseReport

	SBOMPath    string
	VulnPath    string
	LicensePath string

	EPSSAvailable bool
	KEVAvailable  bool
}

// Severity counts for reporting

type SeverityCounts struct {
	Critical   int
	High       int
	Medium     int
	Low        int
	Negligible int
	Unknown    int
	Total      int
}

func (r *VulnReport) CountSeverities() SeverityCounts {
	var c SeverityCounts
	for _, m := range r.Matches {
		switch m.Vulnerability.Severity {
		case "Critical":
			c.Critical++
		case "High":
			c.High++
		case "Medium":
			c.Medium++
		case "Low":
			c.Low++
		case "Negligible":
			c.Negligible++
		default:
			c.Unknown++
		}
		c.Total++
	}
	return c
}

// Risk scoring heuristic (matches bash script logic)

type RiskLevel struct {
	Label string
	Color string
}

func ComputeRisk(counts SeverityCounts, vulns *VulnReport) RiskLevel {
	// Base heuristic from severity counts
	base := riskLabel(counts)

	// Escalate based on EPSS/KEV enrichment
	if vulns != nil {
		for _, m := range vulns.Matches {
			sev := m.Vulnerability.Severity
			if sev != "Critical" && sev != "High" && sev != "Medium" {
				continue
			}
			// KEV vuln with severity >= Medium escalates to at least High
			if m.Vulnerability.InKEV && riskOrd(base) > riskOrd("High") {
				base = "High"
			}
			// EPSS >= 0.7 with severity >= Medium escalates to at least High
			if m.Vulnerability.EPSS != nil && *m.Vulnerability.EPSS >= 0.7 && riskOrd(base) > riskOrd("High") {
				base = "High"
			}
		}
	}

	return riskLevelFromLabel(base)
}

func riskLabel(counts SeverityCounts) string {
	switch {
	case counts.Critical > 0:
		return "Critical"
	case counts.High > 0:
		return "High"
	case counts.Medium > 5:
		return "Medium"
	default:
		return "Low"
	}
}

func riskOrd(label string) int {
	switch label {
	case "Critical":
		return 0
	case "High":
		return 1
	case "Medium":
		return 2
	default:
		return 3
	}
}

func riskLevelFromLabel(label string) RiskLevel {
	switch label {
	case "Critical":
		return RiskLevel{Label: "Critical", Color: "#c0392b"}
	case "High":
		return RiskLevel{Label: "High", Color: "#e67e22"}
	case "Medium":
		return RiskLevel{Label: "Medium", Color: "#f39c12"}
	default:
		return RiskLevel{Label: "Low", Color: "#2d8a4e"}
	}
}
