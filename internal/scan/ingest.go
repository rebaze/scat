package scan

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// InputKind classifies what the user passed as the positional argument.
type InputKind int

const (
	InputUnknown InputKind = iota
	InputDirectory
	InputCycloneDX
	InputSPDX
	InputPURLList
)

type sbomSniff struct {
	BOMFormat   string `json:"bomFormat"`
	SPDXVersion string `json:"spdxVersion"`
}

// DetectInputKind classifies a file path. Directories return InputDirectory.
// Regular files are sniffed: CycloneDX JSON, SPDX JSON, otherwise PURL list.
func DetectInputKind(path string) (InputKind, error) {
	info, err := os.Stat(path)
	if err != nil {
		return InputUnknown, fmt.Errorf("cannot access '%s': %w", path, err)
	}
	if info.IsDir() {
		return InputDirectory, nil
	}
	if !info.Mode().IsRegular() {
		return InputUnknown, fmt.Errorf("'%s' is neither a directory nor a regular file", path)
	}

	f, err := os.Open(path)
	if err != nil {
		return InputUnknown, fmt.Errorf("opening '%s': %w", path, err)
	}
	defer f.Close()

	// Read up to 64 KiB — enough to capture top-level keys in a pretty-printed SBOM.
	head, err := io.ReadAll(io.LimitReader(f, 64*1024))
	if err != nil {
		return InputUnknown, fmt.Errorf("reading '%s': %w", path, err)
	}

	var sniff sbomSniff
	if err := json.Unmarshal(head, &sniff); err == nil {
		if sniff.BOMFormat == "CycloneDX" {
			return InputCycloneDX, nil
		}
		if sniff.SPDXVersion != "" {
			return InputSPDX, nil
		}
	}
	return InputPURLList, nil
}

// IngestSBOM validates a CycloneDX JSON SBOM and copies it to outPath so the
// downstream pipeline (Grype, license check, report) can consume it unchanged.
func IngestSBOM(srcPath, outPath string) error {
	data, err := os.ReadFile(srcPath)
	if err != nil {
		return fmt.Errorf("reading SBOM: %w", err)
	}

	var sniff sbomSniff
	if err := json.Unmarshal(data, &sniff); err != nil {
		return fmt.Errorf("parsing SBOM JSON: %w", err)
	}
	if sniff.BOMFormat != "CycloneDX" {
		return fmt.Errorf("only CycloneDX SBOMs are supported (got bomFormat=%q)", sniff.BOMFormat)
	}

	sbom, err := LoadSBOM(srcPath)
	if err != nil {
		return fmt.Errorf("validating SBOM: %w", err)
	}
	if len(sbom.Components) == 0 {
		return fmt.Errorf("SBOM contains no components")
	}

	return os.WriteFile(outPath, data, 0o644)
}
