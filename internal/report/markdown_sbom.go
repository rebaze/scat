package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/rebaze/scat/internal/model"
)

func writeSBOMSection(b *strings.Builder, sbom *model.SBOM) {
	b.WriteString("## Component Inventory\n\n")

	// Overview table
	b.WriteString("### Overview\n\n")
	b.WriteString("| Metric | Value |\n")
	b.WriteString("|--------|-------|\n")
	b.WriteString(fmt.Sprintf("| Total Components | %d |\n", len(sbom.Components)))

	bomFormat := sbom.BOMFormat
	if bomFormat == "" {
		bomFormat = "n/a"
	}
	formatStr := bomFormat
	if sbom.SpecVersion != "" {
		formatStr += " " + sbom.SpecVersion
	}
	b.WriteString(fmt.Sprintf("| SBOM Format | %s |\n", formatStr))

	serial := sbom.SerialNumber
	if serial == "" {
		serial = "n/a"
	}
	b.WriteString(fmt.Sprintf("| Serial Number | %s |\n\n", serial))

	// Components by Type
	b.WriteString("### Components by Type\n\n")
	b.WriteString("| Type | Count |\n")
	b.WriteString("|------|-------|\n")

	typeCounts := countByField(sbom.Components, func(c model.Component) string { return c.Type })
	for _, kv := range typeCounts {
		b.WriteString(fmt.Sprintf("| %s | %d |\n", kv.Key, kv.Count))
	}
	b.WriteString("\n")

	// Components by Package Manager (PURL scheme)
	b.WriteString("### Components by Package Manager (PURL scheme)\n\n")
	b.WriteString("| Ecosystem | Count |\n")
	b.WriteString("|-----------|-------|\n")

	schemeCounts := countByField(sbom.Components, func(c model.Component) string {
		return extractPURLScheme(c.PURL)
	})
	for _, kv := range schemeCounts {
		if kv.Key != "" {
			b.WriteString(fmt.Sprintf("| %s | %d |\n", kv.Key, kv.Count))
		}
	}
	b.WriteString("\n")

	// Component List
	b.WriteString("### Component List\n\n")
	b.WriteString("| Name | Version | Type | PURL |\n")
	b.WriteString("|------|---------|------|------|\n")

	sorted := make([]model.Component, len(sbom.Components))
	copy(sorted, sbom.Components)
	sort.Slice(sorted, func(i, j int) bool {
		return strings.ToLower(sorted[i].Name) < strings.ToLower(sorted[j].Name)
	})
	for _, c := range sorted {
		version := c.Version
		if version == "" {
			version = "-"
		}
		typ := c.Type
		if typ == "" {
			typ = "-"
		}
		purl := c.PURL
		if purl == "" {
			purl = "-"
		}
		b.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n", c.Name, version, typ, purl))
	}
	b.WriteString("\n")
}

type keyCount struct {
	Key   string
	Count int
}

func countByField(components []model.Component, extract func(model.Component) string) []keyCount {
	counts := map[string]int{}
	for _, c := range components {
		key := extract(c)
		if key != "" {
			counts[key]++
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

func extractPURLScheme(purl string) string {
	if !strings.HasPrefix(purl, "pkg:") {
		return ""
	}
	rest := purl[4:]
	idx := strings.Index(rest, "/")
	if idx < 0 {
		return rest
	}
	return rest[:idx]
}
