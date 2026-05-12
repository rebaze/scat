package scan

import (
	"strings"
	"testing"
)

func FuzzParsePURL(f *testing.F) {
	seeds := []string{
		"pkg:maven/org.apache.commons/commons-lang3@3.12.0",
		"pkg:npm/lodash@4.17.21",
		"pkg:npm/@types/node@20.0.0",
		"pkg:pypi/requests@2.31.0",
		"pkg:golang/github.com/spf13/cobra@1.8.0",
		"pkg:maven/com.example/lib@1.0?classifier=sources",
		"pkg:npm/scope/pkg@2.0#sub/path",
		"pkg:npm/lodash",
		"pkg:",
		"pkg:/",
		"pkg:@",
		"pkg:type/@1.0",
		"pkg:type//@",
		"",
		"@",
		"/",
		"#?",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, input string) {
		typ, name, version := parsePURL(input)

		joined := typ + name + version
		if strings.ContainsAny(joined, "?#") {
			t.Fatalf("parsePURL(%q) leaked qualifier/subpath separator into output: type=%q name=%q version=%q", input, typ, name, version)
		}
	})
}
