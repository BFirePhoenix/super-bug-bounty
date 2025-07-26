package cmd

import (
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/bugbounty-tool/internal/report"
)

var reportCmd = &cobra.Command{
	Use:   "report [scan-id]",
	Short: "Generate comprehensive reports from scan results",
	Long: `Generate professional security reports from scan results in multiple formats:
- HTML report with embedded screenshots and interactive elements
- PDF report for executive summaries
- JSON export for integration with other tools
- CSV export for spreadsheet analysis
- Markdown report for documentation

Examples:
  bugbounty report scan-123456
  bugbounty report scan-123456 --format html,pdf
  bugbounty report scan-123456 --template executive
  bugbounty report scan-123456 --output /tmp/reports`,
	Args: cobra.ExactArgs(1),
	RunE: runReport,
}

func init() {
	rootCmd.AddCommand(reportCmd)

	// Report-specific flags
	reportCmd.Flags().StringSlice("format", []string{"html"}, "report formats (html,pdf,json,csv,markdown)")
	reportCmd.Flags().String("template", "default", "report template (default,executive,technical,hackerone)")
	reportCmd.Flags().Bool("include-screenshots", true, "include vulnerability screenshots")
	reportCmd.Flags().Bool("include-poc", true, "include proof-of-concept code")
	reportCmd.Flags().Bool("include-timeline", true, "include scan timeline")
	reportCmd.Flags().Bool("include-risk-matrix", true, "include risk assessment matrix")
	reportCmd.Flags().StringSlice("severity", []string{"critical", "high", "medium", "low", "info"}, "severity levels to include")
	reportCmd.Flags().StringSlice("categories", []string{}, "vulnerability categories to include")
	reportCmd.Flags().Bool("executive-summary", false, "generate executive summary only")
	reportCmd.Flags().String("company", "", "company name for report header")
	reportCmd.Flags().String("pentester", "", "penetration tester name")
	reportCmd.Flags().Bool("anonymize", false, "anonymize sensitive data in reports")
	reportCmd.Flags().Bool("compress", false, "compress output files")

	// Bind flags
	viper.BindPFlag("report.format", reportCmd.Flags().Lookup("format"))
	viper.BindPFlag("report.template", reportCmd.Flags().Lookup("template"))
	viper.BindPFlag("report.include-screenshots", reportCmd.Flags().Lookup("include-screenshots"))
	viper.BindPFlag("report.include-poc", reportCmd.Flags().Lookup("include-poc"))
}

func runReport(cmd *cobra.Command, args []string) error {
	scanID := args[0]

	// Create report configuration
	reportConfig := &report.Config{
		ScanID:             scanID,
		Formats:            viper.GetStringSlice("report.format"),
		Template:           viper.GetString("report.template"),
		IncludeScreenshots: viper.GetBool("report.include-screenshots"),
		IncludePOC:         viper.GetBool("report.include-poc"),
		IncludeTimeline:    viper.GetBool("report.include-timeline"),
		IncludeRiskMatrix:  viper.GetBool("report.include-risk-matrix"),
		Severities:         viper.GetStringSlice("severity"),
		Categories:         viper.GetStringSlice("categories"),
		ExecutiveSummary:   viper.GetBool("executive-summary"),
		Company:            viper.GetString("company"),
		Pentester:          viper.GetString("pentester"),
		Anonymize:          viper.GetBool("anonymize"),
		Compress:           viper.GetBool("compress"),
		OutputDir:          viper.GetString("output"),
	}

	// Initialize report generator
	generator, err := report.NewGenerator(cfg, log)
	if err != nil {
		return fmt.Errorf("failed to initialize report generator: %w", err)
	}

	log.Info("Generating reports", 
		"scan_id", scanID,
		"formats", reportConfig.Formats,
		"template", reportConfig.Template)

	// Generate reports
	outputFiles, err := generator.Generate(reportConfig)
	if err != nil {
		return fmt.Errorf("failed to generate reports: %w", err)
	}

	// Display generated files
	fmt.Printf("\n📋 Report Generation Complete\n")
	fmt.Printf("═══════════════════════════════════\n")
	for format, path := range outputFiles {
		absPath, _ := filepath.Abs(path)
		fmt.Printf("📄 %s: %s\n", format, absPath)
	}

	fmt.Printf("\n✅ %d report(s) generated successfully\n", len(outputFiles))

	return nil
}
