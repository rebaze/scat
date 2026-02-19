package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/rebaze/starter-sbom-toolchain/internal/model"
	"github.com/rebaze/starter-sbom-toolchain/internal/output"
	"github.com/rebaze/starter-sbom-toolchain/internal/report"
	"github.com/rebaze/starter-sbom-toolchain/internal/scan"
	"github.com/rebaze/starter-sbom-toolchain/internal/tui"
	"github.com/spf13/cobra"
)

var clearCache bool

var analyzeCmd = &cobra.Command{
	Use:   "analyze <folder>",
	Short: "Run full SCA pipeline: scan, report, and summarize",
	Long:  "Scans a source directory for components, vulnerabilities, and license issues, then generates JSON, Markdown, and HTML reports.",
	Args:  cobra.ExactArgs(1),
	RunE:  runAnalyze,
}

func init() {
	analyzeCmd.Flags().BoolVar(&clearCache, "clear-cache", false, "Delete the cached Grype vulnerability database before scanning")
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

	if clearCache {
		cacheDir := scan.DBCacheDir()
		if !quiet {
			fmt.Fprintf(os.Stderr, "Clearing vulnerability database cache: %s\n", cacheDir)
		}
		if err := os.RemoveAll(cacheDir); err != nil {
			return fmt.Errorf("clearing cache: %w", err)
		}
	}

	wantJSON := format == "all" || format == "json"
	wantMarkdown := format == "all" || format == "markdown"
	wantHTML := format == "all" || format == "html"

	sbomPath := filepath.Join(outDir, prefix+"-sbom.json")
	vulnPath := filepath.Join(outDir, prefix+"-vulns.json")
	licensePath := filepath.Join(outDir, prefix+"-licenses.json")

	var result model.ScanResult
	var generatedAt string
	var vulnDB *scan.VulnDB

	steps := []tui.Step{
		{
			Name: "Generating component inventory",
			Run: func() error {
				return scan.CreateSBOM(absFolder, sbomPath, verbose)
			},
		},
		{
			Name: "Updating vulnerability database",
			Run: func() error {
				var err error
				vulnDB, err = scan.LoadVulnDB()
				return err
			},
		},
		{
			Name: "Scanning for vulnerabilities",
			Run: func() error {
				return vulnDB.Scan(sbomPath, vulnPath, verbose)
			},
		},
		{
			Name: "Checking licenses",
			Run: func() error {
				if err := scan.CheckLicenses(sbomPath, licensePath, verbose); err != nil {
					return err
				}
				sbom, err := scan.LoadJSON[model.SBOM](sbomPath)
				if err != nil {
					return fmt.Errorf("parsing SBOM: %w", err)
				}
				vulns, err := scan.LoadJSON[model.VulnReport](vulnPath)
				if err != nil {
					return fmt.Errorf("parsing vulnerability report: %w", err)
				}
				license, err := scan.LoadJSON[model.LicenseReport](licensePath)
				if err != nil {
					return fmt.Errorf("parsing license report: %w", err)
				}
				result = model.ScanResult{
					SBOM:        sbom,
					Vulns:       vulns,
					License:     license,
					SBOMPath:    sbomPath,
					VulnPath:    vulnPath,
					LicensePath: licensePath,
				}
				generatedAt = time.Now().UTC().Format("2006-01-02 15:04:05 UTC")
				return nil
			},
		},
	}

	if wantMarkdown {
		steps = append(steps, tui.Step{
			Name: "Generating reports",
			Run: func() error {
				_, err := report.GenerateMarkdown(&result, prefix, outDir, generatedAt)
				return err
			},
		})
	}

	if wantHTML {
		steps = append(steps, tui.Step{
			Name: "Building dashboard",
			Run: func() error {
				_, err := report.GenerateHTML(&result, prefix, outDir, generatedAt)
				return err
			},
		})
	}

	if quiet {
		for _, s := range steps {
			if err := s.Run(); err != nil {
				return err
			}
		}
	} else {
		m := tui.New(steps)
		p := tea.NewProgram(m)
		finalModel, err := p.Run()
		if err != nil {
			return fmt.Errorf("progress UI: %w", err)
		}
		if fm, ok := finalModel.(tui.Model); ok {
			if fm.Err() != nil {
				return fm.Err()
			}
		}
	}

	if !wantJSON {
		os.Remove(sbomPath)
		os.Remove(vulnPath)
		os.Remove(licensePath)
	}

	return nil
}
