package report

import (
	"path/filepath"

	"github.com/rebaze/starter-sbom-toolchain/sca-tool/internal/model"
)

// GenerateMarkdown produces all three markdown report files.
// Returns the list of generated file paths.
func GenerateMarkdown(result *model.ScanResult, prefix, outDir, generatedAt string) ([]string, error) {
	sbomPath := filepath.Join(outDir, prefix+"-report-sbom.md")
	vulnPath := filepath.Join(outDir, prefix+"-report-vulns.md")
	licensePath := filepath.Join(outDir, prefix+"-report-licenses.md")

	if err := generateSBOMReport(result.SBOM, sbomPath, prefix, generatedAt); err != nil {
		return nil, err
	}

	if err := generateVulnReport(result.Vulns, vulnPath, prefix, generatedAt); err != nil {
		return nil, err
	}

	if err := generateLicenseReport(result.License, licensePath, prefix, generatedAt); err != nil {
		return nil, err
	}

	return []string{sbomPath, vulnPath, licensePath}, nil
}
