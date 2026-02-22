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

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

var (
	outputDir  string
	format     string
	verbose    bool
	quiet      bool
	clearCache bool
)

var rootCmd = &cobra.Command{
	Use:   "scat <path>",
	Short: "Software Composition Analysis CLI",
	Long:  "A single-command tool for SBOM generation, vulnerability scanning, license checking, and reporting.",
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return fmt.Errorf("requires a path to a project directory or a PURL list file")
		}
		if len(args) > 1 {
			return fmt.Errorf("accepts only one path, but received %d", len(args))
		}
		return nil
	},
	RunE:  runAnalyze,
}

func init() {
	rootCmd.Version = version
	rootCmd.SetVersionTemplate(fmt.Sprintf("scat %s (commit: %s, built: %s)\n", version, commit, date))

	rootCmd.Flags().BoolVar(&clearCache, "clear-cache", false, "Delete the cached Grype vulnerability database before scanning")
	rootCmd.PersistentFlags().StringVarP(&outputDir, "output-dir", "o", ".", "Directory for output files")
	rootCmd.PersistentFlags().StringVarP(&format, "format", "f", "html", "Output format: html (file, default), markdown (stdout)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	rootCmd.PersistentFlags().BoolVarP(&quiet, "quiet", "q", false, "Suppress non-error output")
}

func Execute() error {
	return rootCmd.Execute()
}

func runAnalyze(cmd *cobra.Command, args []string) error {
	target := args[0]
	info, err := os.Stat(target)
	if err != nil {
		return fmt.Errorf("cannot access '%s': %w", target, err)
	}

	switch format {
	case "html", "markdown":
	default:
		return fmt.Errorf("unsupported format %q; valid: html, markdown", format)
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

	sbomPath := filepath.Join(outDir, prefix+"-sbom.json")
	vulnPath := filepath.Join(outDir, prefix+"-vulns.json")
	licensePath := filepath.Join(outDir, prefix+"-licenses.json")

	var result model.ScanResult
	var generatedAt string
	var vulnDB *scan.VulnDB
	var htmlPath string

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

	if format == "html" {
		steps = append(steps, tui.Step{
			Name: "Building dashboard",
			Run: func() error {
				htmlPath, err = report.GenerateHTML(&result, prefix, outDir, generatedAt)
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
		var opts []tea.ProgramOption
		if format == "markdown" {
			opts = append(opts, tea.WithOutput(os.Stderr))
		}
		p := tea.NewProgram(m, opts...)
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

	if format == "html" {
		absPath, err := filepath.Abs(htmlPath)
		if err == nil {
			htmlPath = absPath
		}
		fmt.Fprintf(os.Stderr, "\nReport written to %s\n", htmlPath)
	}

	// Always clean up intermediate JSON files
	os.Remove(sbomPath)
	os.Remove(vulnPath)
	os.Remove(licensePath)

	if format == "markdown" {
		return report.RenderMarkdown(os.Stdout, &result, prefix, generatedAt)
	}

	return nil
}
