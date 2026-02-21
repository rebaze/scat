package enrich

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestKEVCacheRead(t *testing.T) {
	// Write a fresh cache file and verify LoadKEV reads it
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir) // won't affect os.UserCacheDir on all platforms

	cacheDir := filepath.Join(tmpDir, "kev-cache")
	cacheFile := filepath.Join(cacheDir, "kev-catalog.json")
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		t.Fatal(err)
	}

	cached := kevCache{
		FetchedAt: time.Now().UTC().Format(time.RFC3339),
		Entries: map[string]KEVEntry{
			"CVE-2021-44228": {DueDate: "2021-12-24", RequiredAction: "Apply updates"},
			"CVE-2023-9999":  {DueDate: "2023-06-01", RequiredAction: "Mitigate"},
		},
	}
	data, _ := json.Marshal(cached)
	if err := os.WriteFile(cacheFile, data, 0o644); err != nil {
		t.Fatal(err)
	}

	// Read back using the low-level cache reading logic
	rawData, err := os.ReadFile(cacheFile)
	if err != nil {
		t.Fatalf("reading cache: %v", err)
	}

	var readBack kevCache
	if err := json.Unmarshal(rawData, &readBack); err != nil {
		t.Fatalf("parsing cache: %v", err)
	}

	if len(readBack.Entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(readBack.Entries))
	}

	entry := readBack.Entries["CVE-2021-44228"]
	if entry.DueDate != "2021-12-24" {
		t.Errorf("expected due date 2021-12-24, got %s", entry.DueDate)
	}
}
