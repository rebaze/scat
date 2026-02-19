package scan

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/rebaze/scat/internal/model"
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

	// Step 2: Load vulnerability DB and scan
	vulnDB, err := LoadVulnDB()
	if err != nil {
		return nil, fmt.Errorf("loading vulnerability database: %w", err)
	}
	if err := vulnDB.Scan(sbomPath, vulnPath, verbose); err != nil {
		return nil, fmt.Errorf("vulnerability scan: %w", err)
	}

	// Step 3: Check licenses
	if err := CheckLicenses(sbomPath, licensePath, verbose); err != nil {
		return nil, fmt.Errorf("license check: %w", err)
	}

	// Parse JSON results
	sbom, err := LoadSBOM(sbomPath)
	if err != nil {
		return nil, fmt.Errorf("parsing SBOM: %w", err)
	}

	vulns, err := LoadJSON[model.VulnReport](vulnPath)
	if err != nil {
		return nil, fmt.Errorf("parsing vulnerability report: %w", err)
	}

	license, err := LoadJSON[model.LicenseReport](licensePath)
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

func LoadJSON[T any](path string) (*T, error) {
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

// cdxSBOMWithProps is an intermediate struct for extracting CycloneDX properties.
type cdxSBOMWithProps struct {
	BOMFormat    string             `json:"bomFormat"`
	SpecVersion  string             `json:"specVersion"`
	SerialNumber string             `json:"serialNumber"`
	Components   []cdxComponentProps `json:"components"`
}

type cdxComponentProps struct {
	Name       string        `json:"name"`
	Version    string        `json:"version"`
	Type       string        `json:"type"`
	PURL       string        `json:"purl"`
	Properties []cdxProperty `json:"properties"`
}

type cdxProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// LoadSBOM parses a CycloneDX SBOM JSON and extracts syft:location properties into Component.Locations.
func LoadSBOM(path string) (*model.SBOM, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var raw cdxSBOMWithProps
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	sbom := &model.SBOM{
		BOMFormat:    raw.BOMFormat,
		SpecVersion:  raw.SpecVersion,
		SerialNumber: raw.SerialNumber,
	}

	for _, c := range raw.Components {
		comp := model.Component{
			Name:    c.Name,
			Version: c.Version,
			Type:    c.Type,
			PURL:    c.PURL,
		}
		for _, p := range c.Properties {
			if strings.HasPrefix(p.Name, "syft:location:") && strings.HasSuffix(p.Name, ":path") {
				comp.Locations = append(comp.Locations, p.Value)
			}
		}
		sbom.Components = append(sbom.Components, comp)
	}

	return sbom, nil
}
