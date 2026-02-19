package report

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/rebaze/scat/internal/model"
)

func generateLicenseReport(lic *model.LicenseReport, outPath, prefix, generatedAt string) error {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("# License Report — %s\n\n", prefix))
	b.WriteString(fmt.Sprintf("**Generated:** %s\n", generatedAt))
	b.WriteString(fmt.Sprintf("**Source:** %s-licenses.json\n\n", prefix))

	// Evaluation Summary (for each target)
	b.WriteString("## Evaluation Summary\n\n")

	for _, target := range lic.Run.Targets {
		ref := target.Source.Ref
		if ref == "" {
			ref = "n/a"
		}
		status := target.Evaluation.Status
		if status == "" {
			status = "n/a"
		}

		b.WriteString(fmt.Sprintf("**Source:** %s  \n", ref))
		b.WriteString(fmt.Sprintf("**Status:** %s  \n\n", status))

		pkg := target.Evaluation.Summary.Packages
		b.WriteString("| Metric | Count |\n")
		b.WriteString("|--------|-------|\n")
		b.WriteString(fmt.Sprintf("| Total Packages | %d |\n", pkg.Total))
		b.WriteString(fmt.Sprintf("| Allowed | %d |\n", pkg.Allowed))
		b.WriteString(fmt.Sprintf("| Denied | %d |\n", pkg.Denied))
		b.WriteString(fmt.Sprintf("| Ignored | %d |\n", pkg.Ignored))
		b.WriteString(fmt.Sprintf("| Unlicensed | %d |\n\n", pkg.Unlicensed))

		lm := target.Evaluation.Summary.Licenses
		b.WriteString("| License Metric | Count |\n")
		b.WriteString("|----------------|-------|\n")
		b.WriteString(fmt.Sprintf("| Unique Licenses | %d |\n", lm.Unique))
		b.WriteString(fmt.Sprintf("| Allowed | %d |\n", lm.Allowed))
		b.WriteString(fmt.Sprintf("| Denied | %d |\n", lm.Denied))
		b.WriteString(fmt.Sprintf("| Non-SPDX | %d |\n\n", lm.NonSPDX))
	}

	// License Distribution
	b.WriteString("## License Distribution\n\n")
	b.WriteString("| License | Packages |\n")
	b.WriteString("|---------|----------|\n")

	licenseDist := gatherLicenseDistribution(lic)
	if len(licenseDist) == 0 {
		b.WriteString("| (no license data found) | - |\n")
	} else {
		for _, kv := range licenseDist {
			b.WriteString(fmt.Sprintf("| %s | %d |\n", kv.Key, kv.Count))
		}
	}
	b.WriteString("\n")

	// Denied Components
	b.WriteString("## Denied Components\n\n")
	b.WriteString("| Package | Version | License |\n")
	b.WriteString("|---------|---------|----------|\n")

	denied := gatherDeniedPackages(lic)
	if len(denied) == 0 {
		b.WriteString("| (no denied packages found) | - | - |\n")
	} else {
		for _, p := range denied {
			version := p.Version
			if version == "" {
				version = "-"
			}
			licenses := strings.Join(p.Licenses, ", ")
			if licenses == "" {
				licenses = "n/a"
			}
			name := p.Name
			if name == "" {
				name = "unknown"
			}
			b.WriteString(fmt.Sprintf("| %s | %s | %s |\n", name, version, licenses))
		}
	}
	b.WriteString("\n")

	// Package Details
	b.WriteString("## Package Details\n\n")
	b.WriteString("| Package | Version | License | Status |\n")
	b.WriteString("|---------|---------|---------|--------|\n")

	allPkgs := gatherAllPackages(lic)
	if len(allPkgs) == 0 {
		b.WriteString("| (no packages found) | - | - | - |\n")
	} else {
		for _, p := range allPkgs {
			name := p.Name
			if name == "" {
				name = "unknown"
			}
			version := p.Version
			if version == "" {
				version = "-"
			}
			licenses := strings.Join(p.Licenses, ", ")
			if licenses == "" {
				licenses = "n/a"
			}
			status := p.Status
			if status == "" {
				status = "-"
			}
			b.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n", name, version, licenses, status))
		}
	}

	return os.WriteFile(outPath, []byte(b.String()), 0o644)
}

func gatherLicenseDistribution(lic *model.LicenseReport) []keyCount {
	counts := map[string]int{}
	for _, target := range lic.Run.Targets {
		for _, pkg := range target.Evaluation.Findings.Packages {
			if len(pkg.Licenses) == 0 {
				counts["UNLICENSED"]++
			} else {
				for _, l := range pkg.Licenses {
					counts[l]++
				}
			}
		}
	}

	result := make([]keyCount, 0, len(counts))
	for k, v := range counts {
		result = append(result, keyCount{Key: k, Count: v})
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Count > result[j].Count
	})
	return result
}

func gatherDeniedPackages(lic *model.LicenseReport) []model.LicensePackage {
	var denied []model.LicensePackage
	for _, target := range lic.Run.Targets {
		for _, pkg := range target.Evaluation.Findings.Packages {
			if pkg.Status == "denied" {
				denied = append(denied, pkg)
			}
		}
	}
	sort.Slice(denied, func(i, j int) bool {
		return strings.ToLower(denied[i].Name) < strings.ToLower(denied[j].Name)
	})
	return denied
}

func gatherAllPackages(lic *model.LicenseReport) []model.LicensePackage {
	var all []model.LicensePackage
	for _, target := range lic.Run.Targets {
		all = append(all, target.Evaluation.Findings.Packages...)
	}
	return all
}
