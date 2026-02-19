package cmd

import (
	"github.com/spf13/cobra"
)

var (
	outputDir string
	format    string
	verbose   bool
	quiet     bool
)

var rootCmd = &cobra.Command{
	Use:   "sca-tool",
	Short: "Software Composition Analysis CLI",
	Long:  "A single-command tool for SBOM generation, vulnerability scanning, license checking, and reporting.",
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&outputDir, "output-dir", "o", ".", "Directory for output files")
	rootCmd.PersistentFlags().StringVarP(&format, "format", "f", "all", "Output format: json, markdown, html, all")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	rootCmd.PersistentFlags().BoolVarP(&quiet, "quiet", "q", false, "Suppress non-error output")
}

func Execute() error {
	return rootCmd.Execute()
}
