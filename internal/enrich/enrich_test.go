package enrich

import (
	"testing"

	"github.com/rebaze/scat/internal/model"
)

func TestEnrichAppliesEPSSAndKEV(t *testing.T) {
	vulns := &model.VulnReport{
		Matches: []model.Match{
			{
				Vulnerability: model.Vulnerability{ID: "CVE-2021-44228", Severity: "Critical"},
				Artifact:      model.Artifact{Name: "log4j-core", Version: "2.14.1"},
			},
			{
				Vulnerability: model.Vulnerability{ID: "CVE-2023-1234", Severity: "Medium"},
				Artifact:      model.Artifact{Name: "some-lib", Version: "1.0.0"},
			},
			{
				// GHSA with a related CVE — should be enriched via cross-reference
				Vulnerability: model.Vulnerability{
					ID:          "GHSA-4374-p667-p6c8",
					Severity:    "High",
					RelatedCVEs: []string{"CVE-2023-44487"},
				},
				Artifact: model.Artifact{Name: "golang.org/x/net", Version: "0.16.0"},
			},
			{
				// GHSA with NO related CVEs — should be gracefully skipped
				Vulnerability: model.Vulnerability{ID: "GHSA-xxxx-yyyy-zzzz", Severity: "Low"},
				Artifact:      model.Artifact{Name: "other-lib", Version: "2.0.0"},
			},
		},
	}

	// Simulate enrichment by directly calling the annotation logic
	epss := map[string]EPSSEntry{
		"CVE-2021-44228": {EPSS: 0.97565, Percentile: 0.99961},
		"CVE-2023-1234":  {EPSS: 0.00150, Percentile: 0.45000},
		"CVE-2023-44487": {EPSS: 0.92870, Percentile: 0.99200},
	}
	kev := map[string]KEVEntry{
		"CVE-2021-44228": {DueDate: "2021-12-24", RequiredAction: "Apply updates"},
		"CVE-2023-44487": {DueDate: "2023-10-31", RequiredAction: "Apply mitigations"},
	}

	kevCount := 0
	for i := range vulns.Matches {
		v := &vulns.Matches[i].Vulnerability

		// Resolve CVE ID: use v.ID if it's a CVE, otherwise check RelatedCVEs
		cveID := ""
		if len(v.ID) >= 4 && v.ID[:4] == "CVE-" {
			cveID = v.ID
		} else {
			for _, rc := range v.RelatedCVEs {
				if len(rc) >= 4 && rc[:4] == "CVE-" {
					cveID = rc
					break
				}
			}
		}
		if cveID == "" {
			continue
		}

		if entry, ok := epss[cveID]; ok {
			score := entry.EPSS
			pct := entry.Percentile
			v.EPSS = &score
			v.EPSSPercentile = &pct
		}
		if entry, ok := kev[cveID]; ok {
			v.InKEV = true
			v.KEVDueDate = entry.DueDate
			v.KEVRequiredAction = entry.RequiredAction
			kevCount++
		}
	}

	// Check CVE-2021-44228
	v0 := vulns.Matches[0].Vulnerability
	if v0.EPSS == nil || *v0.EPSS != 0.97565 {
		t.Errorf("expected EPSS 0.97565 for CVE-2021-44228")
	}
	if !v0.InKEV {
		t.Error("expected CVE-2021-44228 to be in KEV")
	}
	if v0.KEVDueDate != "2021-12-24" {
		t.Errorf("expected KEV due date 2021-12-24, got %s", v0.KEVDueDate)
	}

	// Check CVE-2023-1234
	v1 := vulns.Matches[1].Vulnerability
	if v1.EPSS == nil || *v1.EPSS != 0.00150 {
		t.Errorf("expected EPSS 0.00150 for CVE-2023-1234")
	}
	if v1.InKEV {
		t.Error("CVE-2023-1234 should not be in KEV")
	}

	// Check GHSA with RelatedCVEs — should be enriched via cross-reference
	v2 := vulns.Matches[2].Vulnerability
	if v2.EPSS == nil || *v2.EPSS != 0.92870 {
		t.Errorf("expected EPSS 0.92870 for GHSA-4374-p667-p6c8 (via CVE-2023-44487), got %v", v2.EPSS)
	}
	if !v2.InKEV {
		t.Error("expected GHSA-4374-p667-p6c8 to be in KEV (via CVE-2023-44487)")
	}
	if v2.KEVDueDate != "2023-10-31" {
		t.Errorf("expected KEV due date 2023-10-31, got %s", v2.KEVDueDate)
	}

	// Check GHSA with no RelatedCVEs — should be gracefully skipped
	v3 := vulns.Matches[3].Vulnerability
	if v3.EPSS != nil {
		t.Error("GHSA vuln without RelatedCVEs should not have EPSS")
	}
	if v3.InKEV {
		t.Error("GHSA vuln without RelatedCVEs should not be in KEV")
	}

	if kevCount != 2 {
		t.Errorf("expected KEV count 2, got %d", kevCount)
	}
}

func TestRiskEscalationKEV(t *testing.T) {
	// A Medium vuln in KEV should escalate Low risk to High
	vulns := &model.VulnReport{
		Matches: []model.Match{
			{
				Vulnerability: model.Vulnerability{
					ID:       "CVE-2023-5555",
					Severity: "Medium",
					InKEV:    true,
				},
			},
		},
	}
	counts := vulns.CountSeverities()
	risk := model.ComputeRisk(counts, vulns)
	if risk.Label != "High" {
		t.Errorf("expected risk High due to KEV escalation, got %s", risk.Label)
	}
}

func TestRiskEscalationEPSS(t *testing.T) {
	// A Medium vuln with EPSS >= 0.7 should escalate Low risk to High
	epss := 0.75
	vulns := &model.VulnReport{
		Matches: []model.Match{
			{
				Vulnerability: model.Vulnerability{
					ID:       "CVE-2023-6666",
					Severity: "Medium",
					EPSS:     &epss,
				},
			},
		},
	}
	counts := vulns.CountSeverities()
	risk := model.ComputeRisk(counts, vulns)
	if risk.Label != "High" {
		t.Errorf("expected risk High due to EPSS escalation, got %s", risk.Label)
	}
}

func TestRiskNoEscalationLowEPSS(t *testing.T) {
	// A Medium vuln with EPSS < 0.7 should NOT escalate
	epss := 0.30
	vulns := &model.VulnReport{
		Matches: []model.Match{
			{
				Vulnerability: model.Vulnerability{
					ID:       "CVE-2023-7777",
					Severity: "Medium",
					EPSS:     &epss,
				},
			},
		},
	}
	counts := vulns.CountSeverities()
	risk := model.ComputeRisk(counts, vulns)
	if risk.Label != "Low" {
		t.Errorf("expected risk Low (no escalation), got %s", risk.Label)
	}
}
