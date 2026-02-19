package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/rebaze/starter-sbom-toolchain/sca-tool/internal/output"
	"github.com/rebaze/starter-sbom-toolchain/sca-tool/internal/report"
	"github.com/rebaze/starter-sbom-toolchain/sca-tool/internal/scan"
	"github.com/spf13/cobra"
)

var analyzeCmd = &cobra.Command{
	Use:   "analyze <folder>",
	Short: "Run full SCA pipeline: scan, report, and summarize",
	Long:  "Scans a source directory for components, vulnerabilities, and license issues, then generates JSON, Markdown, and HTML reports.",
	Args:  cobra.ExactArgs(1),
	RunE:  runAnalyze,
}

func init() {
	rootCmd.AddCommand(analyzeCmd)
}

func runAnalyze(cmd *cobra.Command, args []string) error {
	folder := args[0]

	info, err := os.Stat(folder)
	if err != nil || !info.IsDir() {
		return fmt.Errorf("'%s' is not a directory", folder)
	}

	absFolder, err := filepath.Abs(folder)
	if err != nil {
		return fmt.Errorf("resolving path: %w", err)
	}

	prefix := filepath.Base(absFolder)
	outDir := outputDir

	if err := output.EnsureDir(outDir); err != nil {
		return fmt.Errorf("creating output directory: %w", err)
	}

	log := func(msg string, args ...any) {
		if !quiet {
			fmt.Fprintf(os.Stderr, msg+"\n", args...)
		}
	}

	log("=== SCA Pipeline ===")
	log("Source:     %s", absFolder)
	log("Prefix:     %s", prefix)
	log("Output:     %s", outDir)
	log("Format:     %s", format)
	log("")

	wantJSON := format == "all" || format == "json"
	wantMarkdown := format == "all" || format == "markdown"
	wantHTML := format == "all" || format == "html"

	// Phase 1: Scan (always needed — reports depend on JSON)
	log("[1/3] Scanning with Syft, Grype, Grant...")
	result, err := scan.RunPipeline(absFolder, prefix, outDir, verbose)
	if err != nil {
		return fmt.Errorf("scan pipeline: %w", err)
	}

	if wantJSON {
		log("  -> %s", result.SBOMPath)
		log("  -> %s", result.VulnPath)
		log("  -> %s", result.LicensePath)
	}

	generatedAt := time.Now().UTC().Format("2006-01-02 15:04:05 UTC")

	// Phase 2: Markdown reports
	if wantMarkdown {
		log("[2/3] Generating Markdown reports...")
		paths, err := report.GenerateMarkdown(result, prefix, outDir, generatedAt)
		if err != nil {
			return fmt.Errorf("markdown reports: %w", err)
		}
		for _, p := range paths {
			log("  -> %s", p)
		}
	} else {
		log("[2/3] Skipping Markdown reports (format=%s)", format)
	}

	// Phase 3: HTML dashboard
	if wantHTML {
		log("[3/3] Generating HTML dashboard...")
		htmlPath, err := report.GenerateHTML(result, prefix, outDir, generatedAt)
		if err != nil {
			return fmt.Errorf("html report: %w", err)
		}
		log("  -> %s", htmlPath)
	} else {
		log("[3/3] Skipping HTML dashboard (format=%s)", format)
	}

	if !wantJSON {
		// Clean up JSON files if not requested
		os.Remove(result.SBOMPath)
		os.Remove(result.VulnPath)
		os.Remove(result.LicensePath)
	}

	log("")
	log("=== Done ===")
	return nil
}
