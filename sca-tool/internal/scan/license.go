package scan

import (
	"fmt"
	"os"
	"os/exec"
)

// CheckLicenses runs grant to evaluate license compliance against an SBOM.
func CheckLicenses(sbomPath, outPath string, verbose bool) error {
	if _, err := exec.LookPath("grant"); err != nil {
		return fmt.Errorf("grant not found in PATH: %w", err)
	}

	args := []string{
		"check", sbomPath,
		"-o", "json",
	}
	if !verbose {
		args = append(args, "-q")
	}

	cmd := exec.Command("grant", args...)
	out, err := cmd.Output()
	if err != nil {
		// grant returns non-zero when denied licenses are found, but still produces valid output
		if len(out) == 0 {
			return fmt.Errorf("grant check failed: %w", err)
		}
	}

	if err := os.WriteFile(outPath, out, 0o644); err != nil {
		return fmt.Errorf("writing license report: %w", err)
	}

	return nil
}
