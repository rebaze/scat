package scan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestParsePURL(t *testing.T) {
	tests := []struct {
		input               string
		wantType, wantName  string
		wantVersion         string
	}{
		{"pkg:maven/org.apache.commons/commons-lang3@3.12.0", "maven", "org.apache.commons/commons-lang3", "3.12.0"},
		{"pkg:npm/lodash@4.17.21", "npm", "lodash", "4.17.21"},
		{"pkg:pypi/requests@2.31.0", "pypi", "requests", "2.31.0"},
		{"pkg:golang/github.com/spf13/cobra@1.8.0", "golang", "github.com/spf13/cobra", "1.8.0"},
		{"pkg:maven/com.example/lib@1.0?classifier=sources", "maven", "com.example/lib", "1.0"},
		{"pkg:npm/scope/pkg@2.0#sub/path", "npm", "scope/pkg", "2.0"},
		{"pkg:npm/lodash", "npm", "lodash", ""},
	}
	for _, tt := range tests {
		typ, name, version := parsePURL(tt.input)
		if typ != tt.wantType || name != tt.wantName || version != tt.wantVersion {
			t.Errorf("parsePURL(%q) = (%q, %q, %q), want (%q, %q, %q)",
				tt.input, typ, name, version, tt.wantType, tt.wantName, tt.wantVersion)
		}
	}
}

func TestParsePURLFile(t *testing.T) {
	content := `# This is a comment
pkg:maven/org.apache.commons/commons-lang3@3.12.0

pkg:npm/lodash@4.17.21
# Another comment
pkg:pypi/requests@2.31.0
`
	tmp := filepath.Join(t.TempDir(), "purls.txt")
	if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	purls, err := parsePURLFile(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if len(purls) != 3 {
		t.Fatalf("got %d PURLs, want 3", len(purls))
	}
	if purls[0] != "pkg:maven/org.apache.commons/commons-lang3@3.12.0" {
		t.Errorf("purls[0] = %q", purls[0])
	}
}

func TestParsePURLFileInvalidLine(t *testing.T) {
	content := "not-a-purl\n"
	tmp := filepath.Join(t.TempDir(), "bad.txt")
	if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := parsePURLFile(tmp)
	if err == nil {
		t.Fatal("expected error for invalid PURL line")
	}
}

func TestParsePURLFileMissing(t *testing.T) {
	_, err := parsePURLFile("/nonexistent/file.txt")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestCreateSBOMFromPURLsRoundTrip(t *testing.T) {
	purlContent := `pkg:maven/org.apache.commons/commons-lang3@3.12.0
pkg:npm/lodash@4.17.21
pkg:golang/github.com/spf13/cobra@1.8.0
`
	dir := t.TempDir()
	purlFile := filepath.Join(dir, "deps.txt")
	if err := os.WriteFile(purlFile, []byte(purlContent), 0o644); err != nil {
		t.Fatal(err)
	}

	sbomPath := filepath.Join(dir, "deps-sbom.json")
	if err := CreateSBOMFromPURLs(purlFile, sbomPath); err != nil {
		t.Fatal(err)
	}

	// Verify we can read the output as JSON
	data, err := os.ReadFile(sbomPath)
	if err != nil {
		t.Fatal(err)
	}

	var sbom syntheticSBOM
	if err := json.Unmarshal(data, &sbom); err != nil {
		t.Fatal(err)
	}

	if sbom.BOMFormat != "CycloneDX" {
		t.Errorf("bomFormat = %q, want CycloneDX", sbom.BOMFormat)
	}
	if sbom.SpecVersion != "1.6" {
		t.Errorf("specVersion = %q, want 1.6", sbom.SpecVersion)
	}
	if len(sbom.Components) != 3 {
		t.Fatalf("got %d components, want 3", len(sbom.Components))
	}

	// Check first component
	c := sbom.Components[0]
	if c.Name != "org.apache.commons/commons-lang3" {
		t.Errorf("components[0].name = %q", c.Name)
	}
	if c.Version != "3.12.0" {
		t.Errorf("components[0].version = %q", c.Version)
	}
	if c.PURL != "pkg:maven/org.apache.commons/commons-lang3@3.12.0" {
		t.Errorf("components[0].purl = %q", c.PURL)
	}
	if c.Type != "library" {
		t.Errorf("components[0].type = %q", c.Type)
	}

	// Verify LoadSBOM can parse the synthetic SBOM
	loaded, err := LoadSBOM(sbomPath)
	if err != nil {
		t.Fatalf("LoadSBOM failed on synthetic SBOM: %v", err)
	}
	if len(loaded.Components) != 3 {
		t.Errorf("LoadSBOM returned %d components, want 3", len(loaded.Components))
	}
}

func TestCreateSBOMFromPURLsEmptyFile(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "empty.txt")
	if err := os.WriteFile(tmp, []byte("# only comments\n\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	err := CreateSBOMFromPURLs(tmp, filepath.Join(t.TempDir(), "out.json"))
	if err == nil {
		t.Fatal("expected error for empty PURL file")
	}
}
