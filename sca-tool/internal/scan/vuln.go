package scan

import (
	"fmt"
	"os/exec"
)

// FindVulnerabilities runs grype against an SBOM file to find vulnerability matches.
func FindVulnerabilities(sbomPath, outPath string, verbose bool) error {
	if _, err := exec.LookPath("grype"); err != nil {
		return fmt.Errorf("grype not found in PATH: %w", err)
	}

	args := []string{
		"sbom:" + sbomPath,
		"-o", "json",
		"--file", outPath,
	}
	if !verbose {
		args = append(args, "-q")
	}

	cmd := exec.Command("grype", args...)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("grype scan failed: %w", err)
	}

	return nil
}
