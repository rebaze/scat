package enrich

import (
	"strings"
	"testing"
)

func TestParseEPSSCSV(t *testing.T) {
	csv := `#model_version:v2023.03.01,score_date:2024-01-15
cve,epss,percentile
CVE-2021-44228,0.97565,0.99961
CVE-2023-1234,0.00150,0.45000
CVE-2022-9999,0.70000,0.95000
`
	entries, err := parseEPSSCSV(strings.NewReader(csv))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}

	e := entries["CVE-2021-44228"]
	if e.EPSS != 0.97565 {
		t.Errorf("expected EPSS 0.97565, got %f", e.EPSS)
	}
	if e.Percentile != 0.99961 {
		t.Errorf("expected percentile 0.99961, got %f", e.Percentile)
	}

	e2 := entries["CVE-2023-1234"]
	if e2.EPSS != 0.00150 {
		t.Errorf("expected EPSS 0.00150, got %f", e2.EPSS)
	}
}

func TestParseEPSSCSVEmpty(t *testing.T) {
	csv := `#comment
cve,epss,percentile
`
	entries, err := parseEPSSCSV(strings.NewReader(csv))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(entries))
	}
}

func TestParseEPSSCSVMalformedRows(t *testing.T) {
	csv := `#comment
cve,epss,percentile
CVE-2021-44228,0.97565,0.99961
bad-row
CVE-2023-1234,notanumber,0.45000
CVE-2022-5678,0.50000,0.80000
`
	entries, err := parseEPSSCSV(strings.NewReader(csv))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should skip the bad rows and parse the valid ones
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if _, ok := entries["CVE-2021-44228"]; !ok {
		t.Error("missing CVE-2021-44228")
	}
	if _, ok := entries["CVE-2022-5678"]; !ok {
		t.Error("missing CVE-2022-5678")
	}
}
