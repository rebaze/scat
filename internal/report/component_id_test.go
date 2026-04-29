package report

import "testing"

func TestFormatComponentID(t *testing.T) {
	cases := []struct {
		name      string
		namespace string
		comp      string
		purl      string
		want      string
	}{
		{"maven with group", "org.glassfish.jaxb", "jaxb-runtime", "pkg:maven/org.glassfish.jaxb/jaxb-runtime@2.3.2?type=jar", "org.glassfish.jaxb:jaxb-runtime"},
		{"npm scoped", "@types", "node", "pkg:npm/%40types/node@20.0.0", "@types/node"},
		{"golang module", "github.com/spf13", "cobra", "pkg:golang/github.com/spf13/cobra@v1.8.0", "github.com/spf13/cobra"},
		{"pypi no namespace", "", "requests", "pkg:pypi/requests@2.31.0", "requests"},
		{"empty namespace and no purl", "", "core", "", "core"},
		{"unknown ecosystem with namespace", "ns", "thing", "pkg:weird/ns/thing@1.0", "ns/thing"},
		{"namespace present but no purl falls back to slash", "ns", "thing", "", "ns/thing"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := FormatComponentID(tc.namespace, tc.comp, tc.purl)
			if got != tc.want {
				t.Errorf("FormatComponentID(%q,%q,%q) = %q; want %q", tc.namespace, tc.comp, tc.purl, got, tc.want)
			}
		})
	}
}
