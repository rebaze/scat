package scan

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/rebaze/scat/internal/model"
	"github.com/rebaze/scat/internal/output"
)

// cycloneDX types used only for license extraction from the SBOM JSON.
type cdxSBOM struct {
	Components []cdxComponent `json:"components"`
}

type cdxComponent struct {
	Name     string       `json:"name"`
	Version  string       `json:"version"`
	Licenses []cdxLicense `json:"licenses"`
}

type cdxLicense struct {
	License cdxLicenseRef `json:"license"`
}

type cdxLicenseRef struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

// CheckLicenses extracts license information from a CycloneDX SBOM and produces a license report.
// Uses a permissive policy (all licenses allowed, report-only).
func CheckLicenses(sbomPath, outPath string, verbose bool) error {
	data, err := os.ReadFile(sbomPath)
	if err != nil {
		return fmt.Errorf("reading SBOM: %w", err)
	}

	var sbom cdxSBOM
	if err := json.Unmarshal(data, &sbom); err != nil {
		return fmt.Errorf("parsing SBOM: %w", err)
	}

	report := buildLicenseReport(sbomPath, sbom.Components)
	return output.WriteJSON(outPath, report)
}

func buildLicenseReport(sbomRef string, components []cdxComponent) model.LicenseReport {
	var packages []model.LicensePackage
	uniqueLicenses := map[string]struct{}{}
	var unlicensed int

	for _, c := range components {
		var licenses []string
		for _, l := range c.Licenses {
			name := l.License.ID
			if name == "" {
				name = l.License.Name
			}
			if name != "" {
				licenses = append(licenses, name)
				uniqueLicenses[name] = struct{}{}
			}
		}

		status := "allowed"
		if len(licenses) == 0 {
			unlicensed++
		}

		packages = append(packages, model.LicensePackage{
			Name:     c.Name,
			Version:  c.Version,
			Licenses: licenses,
			Status:   status,
		})
	}

	total := len(components)
	return model.LicenseReport{
		Run: model.LicenseRun{
			Targets: []model.LicenseTarget{
				{
					Source: model.LicenseSource{Ref: sbomRef},
					Evaluation: model.LicenseEvaluation{
						Status: "compliant",
						Summary: model.LicenseSummary{
							Packages: model.PackageSummary{
								Total:      total,
								Allowed:    total - unlicensed,
								Denied:     0,
								Ignored:    0,
								Unlicensed: unlicensed,
							},
							Licenses: model.LicenseMetrics{
								Unique:  len(uniqueLicenses),
								Allowed: len(uniqueLicenses),
								Denied:  0,
							},
						},
						Findings: model.LicenseFindings{
							Packages: packages,
						},
					},
				},
			},
		},
	}
}
