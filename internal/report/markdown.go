package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/rebaze/scat/internal/model"
)

// RenderMarkdown writes a consolidated markdown report to the given writer.
func RenderMarkdown(w io.Writer, result *model.ScanResult, prefix, generatedAt string) error {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("# SCA Report — %s\n\n", prefix))
	b.WriteString(fmt.Sprintf("**Generated:** %s\n\n", generatedAt))

	writeSBOMSection(&b, result.SBOM)
	writeVulnSection(&b, result.Vulns)
	writeLicenseSection(&b, result.License)

	_, err := io.WriteString(w, b.String())
	return err
}
