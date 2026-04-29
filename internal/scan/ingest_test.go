package scan

import (
	"os"
	"path/filepath"
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
