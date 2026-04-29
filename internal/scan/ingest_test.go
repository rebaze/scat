package scan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDetectInputKindDirectory(t *testing.T) {
	dir := t.TempDir()
	kind, err := DetectInputKind(dir)
	if err != nil {
		t.Fatal(err)
	}
	if kind != InputDirectory {
		t.Errorf("got %v, want InputDirectory", kind)
	}
}

func TestDetectInputKindCycloneDX(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cdx.json")
	body := `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	kind, err := DetectInputKind(path)
	if err != nil {
		t.Fatal(err)
	}
	if kind != InputCycloneDX {
		t.Errorf("got %v, want InputCycloneDX", kind)
	}
}

func TestDetectInputKindSPDX(t *testing.T) {
	path := filepath.Join(t.TempDir(), "spdx.json")
	body := `{"spdxVersion":"SPDX-2.3","name":"x"}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	kind, err := DetectInputKind(path)
	if err != nil {
		t.Fatal(err)
	}
	if kind != InputSPDX {
		t.Errorf("got %v, want InputSPDX", kind)
	}
}

func TestDetectInputKindPURLList(t *testing.T) {
	path := filepath.Join(t.TempDir(), "purls.txt")
	body := "pkg:npm/lodash@4.17.21\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	kind, err := DetectInputKind(path)
	if err != nil {
		t.Fatal(err)
	}
	if kind != InputPURLList {
		t.Errorf("got %v, want InputPURLList", kind)
	}
}

func TestDetectInputKindMissing(t *testing.T) {
	if _, err := DetectInputKind("/nonexistent/path"); err == nil {
		t.Fatal("expected error for missing path")
	}
}

func TestIngestSBOMHappyPath(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "in.json")
	body := `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"lodash","version":"4.17.21","type":"library","purl":"pkg:npm/lodash@4.17.21"}]}`
	if err := os.WriteFile(src, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	dst := filepath.Join(dir, "out.json")
	if err := IngestSBOM(src, dst); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadSBOM(dst)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Components) != 1 {
		t.Errorf("got %d components, want 1", len(loaded.Components))
	}
}

func TestIngestSBOMRejectsSPDX(t *testing.T) {
	src := filepath.Join(t.TempDir(), "spdx.json")
	body := `{"spdxVersion":"SPDX-2.3","packages":[]}`
	if err := os.WriteFile(src, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	err := IngestSBOM(src, filepath.Join(t.TempDir(), "out.json"))
	if err == nil {
		t.Fatal("expected error for SPDX input")
	}
}

func TestIngestSBOMRejectsEmptyComponents(t *testing.T) {
	src := filepath.Join(t.TempDir(), "empty.json")
	body := `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}`
	if err := os.WriteFile(src, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	err := IngestSBOM(src, filepath.Join(t.TempDir(), "out.json"))
	if err == nil {
		t.Fatal("expected error for SBOM with no components")
	}
}

func TestIngestSBOMRejectsInvalidJSON(t *testing.T) {
	src := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(src, []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := IngestSBOM(src, filepath.Join(t.TempDir(), "out.json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

// TestDetectInputKindLargeCycloneDX guards against the regression where the
// sniffer read only the first 64 KiB and tried to unmarshal it as a complete
// document — which fails for any real-sized SBOM and silently fell through to
// InputPURLList.
func TestDetectInputKindLargeCycloneDX(t *testing.T) {
	type component struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Type    string `json:"type"`
		Purl    string `json:"purl"`
	}
	type bom struct {
		BOMFormat   string      `json:"bomFormat"`
		SpecVersion string      `json:"specVersion"`
		Components  []component `json:"components"`
	}

	// ~150 KiB of components — comfortably past the old 64 KiB read cap.
	const n = 2000
	comps := make([]component, n)
	for i := 0; i < n; i++ {
		comps[i] = component{
			Name:    "pkg-with-a-reasonably-long-name-" + strings.Repeat("x", 20),
			Version: "1.2.3",
			Type:    "library",
			Purl:    "pkg:generic/pkg@1.2.3",
		}
	}
	body, err := json.Marshal(bom{BOMFormat: "CycloneDX", SpecVersion: "1.6", Components: comps})
	if err != nil {
		t.Fatal(err)
	}
	if len(body) < 80*1024 {
		t.Fatalf("test fixture too small (%d bytes); needs to exceed the old 64 KiB read cap", len(body))
	}

	path := filepath.Join(t.TempDir(), "large.json")
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	kind, err := DetectInputKind(path)
	if err != nil {
		t.Fatal(err)
	}
	if kind != InputCycloneDX {
		t.Errorf("got %v, want InputCycloneDX (file size: %d bytes)", kind, len(body))
	}
}

// TestDetectInputKindCycloneDXWithBOMFormatLate ensures the sniffer skips past
// large preceding values (e.g. a "components" array placed before bomFormat).
func TestDetectInputKindCycloneDXWithBOMFormatLate(t *testing.T) {
	body := `{"specVersion":"1.6","components":[` +
		strings.Repeat(`{"name":"x","version":"1","type":"library","purl":"pkg:x/x@1"},`, 1000) +
		`{"name":"y","version":"1","type":"library","purl":"pkg:y/y@1"}],"bomFormat":"CycloneDX"}`
	path := filepath.Join(t.TempDir(), "late.json")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	kind, err := DetectInputKind(path)
	if err != nil {
		t.Fatal(err)
	}
	if kind != InputCycloneDX {
		t.Errorf("got %v, want InputCycloneDX", kind)
	}
}

// TestDetectInputKindUnknownJSON ensures unknown JSON objects produce an
// explicit error rather than silently falling through to the PURL flow.
func TestDetectInputKindUnknownJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "other.json")
	body := `{"hello":"world","stuff":[1,2,3]}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	kind, err := DetectInputKind(path)
	if err == nil {
		t.Fatalf("expected error for unrecognized JSON, got kind=%v", kind)
	}
	if !strings.Contains(err.Error(), "bomFormat") || !strings.Contains(err.Error(), "spdxVersion") {
		t.Errorf("error should mention both bomFormat and spdxVersion; got: %v", err)
	}
}

// TestDetectInputKindJSONArray ensures a bare JSON array gets a clear error.
func TestDetectInputKindJSONArray(t *testing.T) {
	path := filepath.Join(t.TempDir(), "array.json")
	if err := os.WriteFile(path, []byte(`[1,2,3]`), 0o644); err != nil {
		t.Fatal(err)
	}
	kind, err := DetectInputKind(path)
	if err == nil {
		t.Fatalf("expected error for JSON array, got kind=%v", kind)
	}
	if !strings.Contains(err.Error(), "JSON array") {
		t.Errorf("error should mention 'JSON array'; got: %v", err)
	}
}

// TestDetectInputKindCycloneDXWrongFormat ensures a JSON object that declares a
// non-CycloneDX bomFormat is rejected explicitly.
func TestDetectInputKindCycloneDXWrongFormat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "other-bom.json")
	body := `{"bomFormat":"SWID","components":[]}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	kind, err := DetectInputKind(path)
	if err == nil {
		t.Fatalf("expected error for non-CycloneDX bomFormat, got kind=%v", kind)
	}
	if !strings.Contains(err.Error(), "CycloneDX") {
		t.Errorf("error should mention CycloneDX; got: %v", err)
	}
}

// TestDetectInputKindLeadingWhitespace ensures whitespace before the opening
// '{' doesn't trip the sniffer.
func TestDetectInputKindLeadingWhitespace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ws.json")
	body := "\n\n  \t" + `{"bomFormat":"CycloneDX","components":[]}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	kind, err := DetectInputKind(path)
	if err != nil {
		t.Fatal(err)
	}
	if kind != InputCycloneDX {
		t.Errorf("got %v, want InputCycloneDX", kind)
	}
}
