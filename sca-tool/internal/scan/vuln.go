package scan

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype"
	v6dist "github.com/anchore/grype/grype/db/v6/distribution"
	v6inst "github.com/anchore/grype/grype/db/v6/installation"
	grypeMatch "github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher"
	grypePkg "github.com/anchore/grype/grype/pkg"
	"github.com/rebaze/starter-sbom-toolchain/sca-tool/internal/model"
	"github.com/rebaze/starter-sbom-toolchain/sca-tool/internal/output"
)

// FindVulnerabilities uses the Grype library to scan an SBOM for vulnerability matches.
func FindVulnerabilities(sbomPath, outPath string, verbose bool) error {
	// Determine DB cache directory
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		cacheDir = os.TempDir()
	}
	dbDir := filepath.Join(cacheDir, "sca-tool", "grype-db")

	// Load vulnerability database (auto-downloads on first run)
	id := clio.Identification{Name: "sca-tool", Version: "dev"}

	distCfg := v6dist.DefaultConfig()
	installCfg := v6inst.DefaultConfig(id)
	installCfg.DBRootDir = dbDir

	provider, _, err := grype.LoadVulnerabilityDB(distCfg, installCfg, true)
	if err != nil {
		return fmt.Errorf("loading vulnerability database: %w", err)
	}

	// Load packages from SBOM
	providerCfg := grypePkg.ProviderConfig{}
	packages, pkgContext, _, err := grypePkg.Provide("sbom:"+sbomPath, providerCfg)
	if err != nil {
		return fmt.Errorf("loading packages from SBOM: %w", err)
	}

	// Run vulnerability matching
	matchers := matcher.NewDefaultMatchers(matcher.Config{})
	vm := grype.VulnerabilityMatcher{
		VulnerabilityProvider: provider,
		Matchers:              matchers,
	}

	remainingMatches, _, err := vm.FindMatches(packages, pkgContext)
	if err != nil {
		return fmt.Errorf("matching vulnerabilities: %w", err)
	}

	report := convertGrypeMatches(remainingMatches)
	return output.WriteJSON(outPath, report)
}

func convertGrypeMatches(matches *grypeMatch.Matches) model.VulnReport {
	var report model.VulnReport
	if matches == nil {
		return report
	}
	for _, m := range matches.Sorted() {
		severity := ""
		dataSource := ""
		if m.Vulnerability.Metadata != nil {
			severity = m.Vulnerability.Metadata.Severity
			dataSource = m.Vulnerability.Metadata.DataSource
		}
		report.Matches = append(report.Matches, model.Match{
			Vulnerability: model.Vulnerability{
				ID:         m.Vulnerability.ID,
				Severity:   severity,
				DataSource: dataSource,
				Fix: model.VulnFix{
					State: string(m.Vulnerability.Fix.State),
				},
			},
			Artifact: model.Artifact{
				Name:    m.Package.Name,
				Version: m.Package.Version,
			},
		})
	}
	return report
}
