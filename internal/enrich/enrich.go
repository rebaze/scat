package enrich

import (
	"os"
	"strings"

	"github.com/rebaze/scat/internal/model"
)

// EnrichmentResult holds metadata about the enrichment run.
type EnrichmentResult struct {
	EPSSAvailable bool
	KEVAvailable  bool
	KEVCount      int
}

// Enrich loads EPSS and KEV data and annotates each vulnerability in the report.
func Enrich(vulns *model.VulnReport) EnrichmentResult {
	var result EnrichmentResult

	epss, _ := LoadEPSS()
	kev, _ := LoadKEV()

	result.EPSSAvailable = epss != nil
	result.KEVAvailable = kev != nil

	if vulns == nil {
		return result
	}

	for i := range vulns.Matches {
		v := &vulns.Matches[i].Vulnerability

		// Resolve CVE ID: use v.ID if it's a CVE, otherwise check RelatedCVEs
		cveID := ""
		if strings.HasPrefix(v.ID, "CVE-") {
			cveID = v.ID
		} else {
			for _, rc := range v.RelatedCVEs {
				if strings.HasPrefix(rc, "CVE-") {
					cveID = rc
					break
				}
			}
		}
		if cveID == "" {
			continue
		}

		if epss != nil {
			if entry, ok := epss[cveID]; ok {
				score := entry.EPSS
				pct := entry.Percentile
				v.EPSS = &score
				v.EPSSPercentile = &pct
			}
		}

		if kev != nil {
			if entry, ok := kev[cveID]; ok {
				v.InKEV = true
				v.KEVDueDate = entry.DueDate
				v.KEVRequiredAction = entry.RequiredAction
				result.KEVCount++
			}
		}
	}

	return result
}

// ClearCache removes both EPSS and KEV cache directories.
func ClearCache() error {
	for _, dir := range []string{EPSSCacheDir(), KEVCacheDir()} {
		if err := os.RemoveAll(dir); err != nil {
			return err
		}
	}
	return nil
}
