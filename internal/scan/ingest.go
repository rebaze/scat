package scan

import (
	"bufio"
	"encoding/json"
	"fmt"
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
// Regular files are sniffed by content:
//   - JSON object containing a top-level "bomFormat":"CycloneDX" → InputCycloneDX.
//   - JSON object containing a top-level "spdxVersion" → InputSPDX.
//   - JSON that doesn't match either schema → explicit error (NOT silent
//     fall-through to the PURL flow, which would produce a misleading message).
//   - Anything that doesn't start with '{' or '[' after whitespace → InputPURLList.
//
// The JSON path uses a streaming decoder so files much larger than any read
// buffer are still classified correctly.
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

	br := bufio.NewReader(f)
	first, err := peekFirstNonSpace(br)
	if err != nil {
		// Empty / unreadable: let the PURL flow report it with its usual error.
		return InputPURLList, nil
	}
	if first == '[' {
		return InputUnknown, fmt.Errorf("'%s' is a JSON array; SBOMs must be JSON objects (CycloneDX or SPDX)", path)
	}
	if first != '{' {
		return InputPURLList, nil
	}

	dec := json.NewDecoder(br)
	if _, err := dec.Token(); err != nil {
		return InputUnknown, fmt.Errorf("'%s' starts like JSON but is malformed: %w", path, err)
	}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return InputUnknown, fmt.Errorf("'%s' starts like JSON but is malformed: %w", path, err)
		}
		key, ok := keyTok.(string)
		if !ok {
			return InputUnknown, fmt.Errorf("'%s' starts like JSON but has an unexpected structure", path)
		}
		switch key {
		case "bomFormat":
			valTok, err := dec.Token()
			if err != nil {
				return InputUnknown, fmt.Errorf("'%s' has malformed bomFormat: %w", path, err)
			}
			s, _ := valTok.(string)
			if s == "CycloneDX" {
				return InputCycloneDX, nil
			}
			return InputUnknown, fmt.Errorf("'%s' is JSON with bomFormat=%q; only CycloneDX is supported", path, s)
		case "spdxVersion":
			return InputSPDX, nil
		default:
			if err := skipJSONValue(dec); err != nil {
				return InputUnknown, fmt.Errorf("'%s' looks like JSON but is malformed: %w", path, err)
			}
		}
	}
	return InputUnknown, fmt.Errorf("'%s' is JSON but not a recognized SBOM (no top-level 'bomFormat' or 'spdxVersion')", path)
}

func peekFirstNonSpace(br *bufio.Reader) (byte, error) {
	for {
		b, err := br.ReadByte()
		if err != nil {
			return 0, err
		}
		switch b {
		case ' ', '\t', '\n', '\r':
			continue
		default:
			if err := br.UnreadByte(); err != nil {
				return 0, err
			}
			return b, nil
		}
	}
}

// skipJSONValue advances the decoder past one complete JSON value (object,
// array, or primitive). For objects/arrays it consumes everything up to and
// including the closing delimiter.
func skipJSONValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, isDelim := tok.(json.Delim)
	if !isDelim {
		return nil
	}
	switch delim {
	case '{':
		for dec.More() {
			if _, err := dec.Token(); err != nil {
				return err
			}
			if err := skipJSONValue(dec); err != nil {
				return err
			}
		}
	case '[':
		for dec.More() {
			if err := skipJSONValue(dec); err != nil {
				return err
			}
		}
	}
	_, err = dec.Token()
	return err
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
