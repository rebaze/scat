package report

import "strings"

// FormatComponentID returns a human-readable identifier for a component,
// using ecosystem-aware separators derived from the PURL scheme:
//
//	maven  org.glassfish.jaxb + jaxb-runtime  -> "org.glassfish.jaxb:jaxb-runtime"
//	npm    @types + node                      -> "@types/node"
//	golang github.com/spf13 + cobra           -> "github.com/spf13/cobra"
//	pypi   "" + requests                      -> "requests"
//
// Empty namespaces and unknown ecosystems fall back to the bare name.
func FormatComponentID(namespace, name, purl string) string {
	if namespace == "" {
		return name
	}
	switch extractPURLScheme(purl) {
	case "maven":
		return namespace + ":" + name
	case "npm", "golang", "github", "bitbucket", "docker", "oci", "generic", "composer", "nuget", "gem", "cargo", "swift", "hex", "deb", "rpm", "apk", "conan", "cran", "pub", "hackage":
		return namespace + "/" + name
	default:
		// Unknown ecosystem: use "/" as a neutral separator so the namespace is still visible.
		return namespace + "/" + name
	}
}

// FormatComponentIDLower returns FormatComponentID lowercased — useful for
// case-insensitive sort and join keys.
func FormatComponentIDLower(namespace, name, purl string) string {
	return strings.ToLower(FormatComponentID(namespace, name, purl))
}
