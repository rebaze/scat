package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/rebaze/scat/internal/enrich"
	"github.com/rebaze/scat/internal/model"
	"github.com/rebaze/scat/internal/output"
	"github.com/rebaze/scat/internal/report"
	"github.com/rebaze/scat/internal/scan"
	"github.com/rebaze/scat/internal/tui"
	"github.com/spf13/cobra"
)

var clearCache bool

var analyzeCmd = &cobra.Command{
	Use:   "analyze <path>",
	Short: "Run full SCA pipeline: scan, report, and summarize",
	Long:  "Scans a source directory or PURL list file for components, vulnerabilities, and license issues, then generates JSON, Markdown, and HTML reports.\nWhen <path> is a directory, components are discovered via Syft.\nWhen <path> is a text file containing Package URLs (one per line), a synthetic SBOM is created from those PURLs.",
	Args:  cobra.ExactArgs(1),
	RunE:  runAnalyze,
}

func init() {
	analyzeCmd.Flags().BoolVar(&clearCache, "clear-cache", false, "Delete the cached Grype vulnerability database before scanning")
	rootCmd.AddCommand(analyzeCmd)
}

func runAnalyze(cmd *cobra.Command, args []string) error {
	target := args[0]
	info, err := os.Stat(target)
	if err != nil {
		return fmt.Errorf("cannot access '%s': %w", target, err)
	}

	var absFolder string
	var purlFile string
	var prefix string

	if info.IsDir() {
		af, err := filepath.Abs(target)
		if err != nil {
			return fmt.Errorf("resolving path: %w", err)
		}
		absFolder = af
		prefix = filepath.Base(absFolder)
	} else if info.Mode().IsRegular() {
		purlFile = target
		base := filepath.Base(purlFile)
		prefix = strings.TrimSuffix(base, filepath.Ext(base))
	} else {
		return fmt.Errorf("'%s' is neither a directory nor a regular file", target)
	}

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
		if err := enrich.ClearCache(); err != nil {
			return fmt.Errorf("clearing enrichment cache: %w", err)
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

	var sbomStep tui.Step
	if purlFile != "" {
		sbomStep = tui.Step{
			Name: "Creating inventory from PURLs",
			Run: func() error {
				return scan.CreateSBOMFromPURLs(purlFile, sbomPath)
			},
		}
	} else {
		sbomStep = tui.Step{
			Name: "Generating component inventory",
			Run: func() error {
				return scan.CreateSBOM(absFolder, sbomPath, verbose)
			},
		}
	}

	steps := []tui.Step{
		sbomStep,
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
				sbom, err := scan.LoadSBOM(sbomPath)
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
		{
			Name: "Enriching with exploit intelligence",
			Run: func() error {
				er := enrich.Enrich(result.Vulns)
				result.EPSSAvailable = er.EPSSAvailable
				result.KEVAvailable = er.KEVAvailable
				// Re-write enriched vulns JSON
				if er.EPSSAvailable || er.KEVAvailable {
					if err := output.WriteJSON(vulnPath, result.Vulns); err != nil {
						return fmt.Errorf("writing enriched vulns: %w", err)
					}
				}
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
