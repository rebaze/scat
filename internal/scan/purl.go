package scan

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// CreateSBOMFromPURLs reads a PURL list file and writes a synthetic CycloneDX
// JSON SBOM to outPath. The resulting file is compatible with the downstream
// pipeline (Grype vuln scan, license check, reports).
func CreateSBOMFromPURLs(purlFile, outPath string) error {
	purls, err := parsePURLFile(purlFile)
	if err != nil {
		return err
	}
	if len(purls) == 0 {
		return fmt.Errorf("no valid PURLs found in %s", purlFile)
	}
	return writeSyntheticSBOM(purls, outPath)
}

// parsePURLFile reads one PURL per line, skipping blank lines and comments.
func parsePURLFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening PURL file: %w", err)
	}
	defer f.Close()

	var purls []string
	scanner := bufio.NewScanner(f)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, "pkg:") {
			return nil, fmt.Errorf("line %d: invalid PURL (must start with pkg:): %s", lineNo, line)
		}
		purls = append(purls, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading PURL file: %w", err)
	}
	return purls, nil
}

// parsePURL extracts type, namespace+name, and version from a PURL string.
// It strips qualifiers (?) and subpath (#) before parsing.
// Example: "pkg:maven/org.apache.commons/commons-lang3@3.12.0" → "maven", "org.apache.commons/commons-lang3", "3.12.0"
func parsePURL(purl string) (typ, name, version string) {
	s := purl

	// Strip qualifiers and subpath
	if idx := strings.Index(s, "#"); idx >= 0 {
		s = s[:idx]
	}
	if idx := strings.Index(s, "?"); idx >= 0 {
		s = s[:idx]
	}

	// Remove "pkg:" prefix
	s = strings.TrimPrefix(s, "pkg:")

	// Split type from the rest
	slashIdx := strings.Index(s, "/")
	if slashIdx < 0 {
		return s, "", ""
	}
	typ = s[:slashIdx]
	remainder := s[slashIdx+1:]

	// Split version
	if atIdx := strings.LastIndex(remainder, "@"); atIdx >= 0 {
		name = remainder[:atIdx]
		version = remainder[atIdx+1:]
	} else {
		name = remainder
	}
	return typ, name, version
}

// syntheticSBOM mirrors just enough CycloneDX structure for JSON output.
type syntheticSBOM struct {
	BOMFormat   string               `json:"bomFormat"`
	SpecVersion string               `json:"specVersion"`
	Version     int                  `json:"version"`
	Components  []syntheticComponent `json:"components"`
}

type syntheticComponent struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl"`
}

func writeSyntheticSBOM(purls []string, outPath string) error {
	sbom := syntheticSBOM{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.6",
		Version:     1,
	}

	for _, purl := range purls {
		_, name, version := parsePURL(purl)
		sbom.Components = append(sbom.Components, syntheticComponent{
			Type:    "library",
			Name:    name,
			Version: version,
			PURL:    purl,
		})
	}

	data, err := json.MarshalIndent(sbom, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding synthetic SBOM: %w", err)
	}
	return os.WriteFile(outPath, data, 0o644)
}
