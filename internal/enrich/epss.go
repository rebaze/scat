package enrich

import (
	"compress/gzip"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// EPSSEntry holds the EPSS score and percentile for a single CVE.
type EPSSEntry struct {
	EPSS       float64 `json:"epss"`
	Percentile float64 `json:"percentile"`
}

type epssCache struct {
	FetchedAt string               `json:"fetchedAt"`
	Entries   map[string]EPSSEntry `json:"entries"`
}

// EPSSCacheDir returns the directory used for caching EPSS data.
func EPSSCacheDir() string {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		cacheDir = os.TempDir()
	}
	return filepath.Join(cacheDir, "scat", "epss")
}

// LoadEPSS returns EPSS scores keyed by CVE ID, using a 24h cache.
// On network failure it falls back to a stale cache. Returns nil, nil if
// no data is available at all.
func LoadEPSS() (map[string]EPSSEntry, error) {
	cacheFile := filepath.Join(EPSSCacheDir(), "epss-scores.json")

	// Try cached data first
	if data, err := os.ReadFile(cacheFile); err == nil {
		var cached epssCache
		if json.Unmarshal(data, &cached) == nil {
			if t, err := time.Parse(time.RFC3339, cached.FetchedAt); err == nil {
				if time.Since(t) < 24*time.Hour {
					return cached.Entries, nil
				}
			}
			// Cache is stale — try to refresh, fall back to stale on failure
			entries, err := fetchEPSS()
			if err != nil {
				return cached.Entries, nil
			}
			_ = writeEPSSCache(cacheFile, entries)
			return entries, nil
		}
	}

	// No valid cache — fetch fresh
	entries, err := fetchEPSS()
	if err != nil {
		return nil, nil // graceful degradation
	}
	_ = writeEPSSCache(cacheFile, entries)
	return entries, nil
}

func fetchEPSS() (map[string]EPSSEntry, error) {
	now := time.Now().UTC()
	// Try today's date first, then yesterday (file may not be published yet)
	for _, d := range []time.Time{now, now.AddDate(0, 0, -1)} {
		url := fmt.Sprintf("https://epss.cyentia.com/epss_scores-%s.csv.gz", d.Format("2006-01-02"))
		entries, err := downloadEPSS(url)
		if err == nil {
			return entries, nil
		}
	}
	return nil, fmt.Errorf("failed to download EPSS data")
}

func downloadEPSS(url string) (map[string]EPSSEntry, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}

	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("decompressing EPSS data: %w", err)
	}
	defer gz.Close()

	return parseEPSSCSV(gz)
}

// parseEPSSCSV parses the EPSS CSV format. It skips lines starting with #
// and expects columns: cve, epss, percentile.
func parseEPSSCSV(r io.Reader) (map[string]EPSSEntry, error) {
	// The EPSS CSV has a comment line starting with # before the header.
	// We need to skip it before handing to the CSV reader.
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("reading EPSS CSV: %w", err)
	}

	// Strip comment lines (lines starting with #)
	lines := strings.Split(string(data), "\n")
	var clean []string
	for _, line := range lines {
		if !strings.HasPrefix(line, "#") {
			clean = append(clean, line)
		}
	}

	cr := csv.NewReader(strings.NewReader(strings.Join(clean, "\n")))
	// Read header
	header, err := cr.Read()
	if err != nil {
		return nil, fmt.Errorf("reading EPSS CSV header: %w", err)
	}

	// Find column indices
	cveIdx, epssIdx, pctIdx := -1, -1, -1
	for i, col := range header {
		switch strings.TrimSpace(strings.ToLower(col)) {
		case "cve":
			cveIdx = i
		case "epss":
			epssIdx = i
		case "percentile":
			pctIdx = i
		}
	}
	if cveIdx < 0 || epssIdx < 0 || pctIdx < 0 {
		return nil, fmt.Errorf("EPSS CSV missing required columns (cve, epss, percentile)")
	}

	entries := make(map[string]EPSSEntry)
	for {
		record, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue // skip malformed rows
		}
		if len(record) <= cveIdx || len(record) <= epssIdx || len(record) <= pctIdx {
			continue
		}
		cve := strings.TrimSpace(record[cveIdx])
		epss, err1 := strconv.ParseFloat(strings.TrimSpace(record[epssIdx]), 64)
		pct, err2 := strconv.ParseFloat(strings.TrimSpace(record[pctIdx]), 64)
		if err1 != nil || err2 != nil {
			continue
		}
		entries[cve] = EPSSEntry{EPSS: epss, Percentile: pct}
	}

	return entries, nil
}

func writeEPSSCache(path string, entries map[string]EPSSEntry) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	cached := epssCache{
		FetchedAt: time.Now().UTC().Format(time.RFC3339),
		Entries:   entries,
	}
	data, err := json.Marshal(cached)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
