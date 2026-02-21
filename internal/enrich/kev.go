package enrich

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const kevURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

// KEVEntry holds data for a single KEV catalog entry.
type KEVEntry struct {
	DueDate        string `json:"dueDate"`
	RequiredAction string `json:"requiredAction"`
}

type kevCatalog struct {
	Vulnerabilities []kevVuln `json:"vulnerabilities"`
}

type kevVuln struct {
	CVEID          string `json:"cveID"`
	DueDate        string `json:"dueDate"`
	RequiredAction string `json:"requiredAction"`
}

type kevCache struct {
	FetchedAt string              `json:"fetchedAt"`
	Entries   map[string]KEVEntry `json:"entries"`
}

// KEVCacheDir returns the directory used for caching KEV data.
func KEVCacheDir() string {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		cacheDir = os.TempDir()
	}
	return filepath.Join(cacheDir, "scat", "kev")
}

// LoadKEV returns KEV entries keyed by CVE ID, using a 24h cache.
// On network failure it falls back to a stale cache. Returns nil, nil if
// no data is available at all.
func LoadKEV() (map[string]KEVEntry, error) {
	cacheFile := filepath.Join(KEVCacheDir(), "kev-catalog.json")

	// Try cached data first
	if data, err := os.ReadFile(cacheFile); err == nil {
		var cached kevCache
		if json.Unmarshal(data, &cached) == nil {
			if t, err := time.Parse(time.RFC3339, cached.FetchedAt); err == nil {
				if time.Since(t) < 24*time.Hour {
					return cached.Entries, nil
				}
			}
			// Cache is stale — try to refresh, fall back to stale on failure
			entries, err := fetchKEV()
			if err != nil {
				return cached.Entries, nil
			}
			_ = writeKEVCache(cacheFile, entries)
			return entries, nil
		}
	}

	// No valid cache — fetch fresh
	entries, err := fetchKEV()
	if err != nil {
		return nil, nil // graceful degradation
	}
	_ = writeKEVCache(cacheFile, entries)
	return entries, nil
}

func fetchKEV() (map[string]KEVEntry, error) {
	resp, err := http.Get(kevURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from KEV feed", resp.StatusCode)
	}

	var catalog kevCatalog
	if err := json.NewDecoder(resp.Body).Decode(&catalog); err != nil {
		return nil, fmt.Errorf("parsing KEV JSON: %w", err)
	}

	entries := make(map[string]KEVEntry, len(catalog.Vulnerabilities))
	for _, v := range catalog.Vulnerabilities {
		entries[v.CVEID] = KEVEntry{
			DueDate:        v.DueDate,
			RequiredAction: v.RequiredAction,
		}
	}
	return entries, nil
}

func writeKEVCache(path string, entries map[string]KEVEntry) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	cached := kevCache{
		FetchedAt: time.Now().UTC().Format(time.RFC3339),
		Entries:   entries,
	}
	data, err := json.Marshal(cached)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
