package scan

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/rebaze/starter-sbom-toolchain/sca-tool/internal/model"
)

// RunPipeline executes the full scan pipeline: Syft → Grype → Grant.
// It returns a ScanResult with parsed data and file paths.
func RunPipeline(sourceDir, prefix, outDir string, verbose bool) (*model.ScanResult, error) {
	sbomPath := filepath.Join(outDir, prefix+"-sbom.json")
	vulnPath := filepath.Join(outDir, prefix+"-vulns.json")
	licensePath := filepath.Join(outDir, prefix+"-licenses.json")

	// Step 1: Generate SBOM
	if err := CreateSBOM(sourceDir, sbomPath, verbose); err != nil {
		return nil, fmt.Errorf("SBOM generation: %w", err)
	}

	// Step 2: Scan for vulnerabilities
	if err := FindVulnerabilities(sbomPath, vulnPath, verbose); err != nil {
		return nil, fmt.Errorf("vulnerability scan: %w", err)
	}

	// Step 3: Check licenses
	if err := CheckLicenses(sbomPath, licensePath, verbose); err != nil {
		return nil, fmt.Errorf("license check: %w", err)
	}

	// Parse JSON results
	sbom, err := loadJSON[model.SBOM](sbomPath)
	if err != nil {
		return nil, fmt.Errorf("parsing SBOM: %w", err)
	}

	vulns, err := loadJSON[model.VulnReport](vulnPath)
	if err != nil {
		return nil, fmt.Errorf("parsing vulnerability report: %w", err)
	}

	license, err := loadJSON[model.LicenseReport](licensePath)
	if err != nil {
		return nil, fmt.Errorf("parsing license report: %w", err)
	}

	return &model.ScanResult{
		SBOM:        sbom,
		Vulns:       vulns,
		License:     license,
		SBOMPath:    sbomPath,
		VulnPath:    vulnPath,
		LicensePath: licensePath,
	}, nil
}

func loadJSON[T any](path string) (*T, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var v T
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, err
	}
	return &v, nil
}
