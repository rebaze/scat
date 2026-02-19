package scan

import (
	"fmt"
	"os/exec"
)

// CreateSBOM runs syft to generate a CycloneDX JSON SBOM.
func CreateSBOM(sourceDir, outPath string, verbose bool) error {
	if _, err := exec.LookPath("syft"); err != nil {
		return fmt.Errorf("syft not found in PATH: %w", err)
	}

	args := []string{
		"dir:" + sourceDir,
		"-o", "cyclonedx-json=" + outPath,
	}
	if quiet := !verbose; quiet {
		args = append(args, "-q")
	}

	cmd := exec.Command("syft", args...)
	if verbose {
		cmd.Stdout = nil // syft writes JSON to file via -o flag
		cmd.Stderr = nil
	}

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("syft scan failed: %w", err)
	}

	return nil
}
