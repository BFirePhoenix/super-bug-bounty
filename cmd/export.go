package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/bugbounty-tool/internal/export"
)

var exportCmd = &cobra.Command{
	Use:   "export [scan-id]",
	Short: "Export scan results to various formats",
	Long: `Export scan results to various formats for integration with other tools
and platforms:

- JSON export for API integration
- CSV export for spreadsheet analysis  
- YAML export for configuration
- XML export for legacy systems
- SARIF export for security tools
- HackerOne format for bug bounty platforms
- Jira integration for ticket creation
- Slack/Discord webhooks for notifications

Examples:
  bugbounty export scan-123456 --format json
  bugbounty export scan-123456 --format csv --filter critical,high
  bugbounty export scan-123456 --hackerone --template bounty
  bugbounty export scan-123456 --jira --project SECURITY`,
	Args: cobra.ExactArgs(1),
	RunE: runExport,
}

func init() {
	rootCmd.AddCommand(exportCmd)

	// Export-specific flags
	exportCmd.Flags().String("format", "json", "export format (json,csv,yaml,xml,sarif)")
	exportCmd.Flags().StringSlice("filter", []string{}, "severity levels to include")
	exportCmd.Flags().StringSlice("categories", []string{}, "vulnerability categories to include")
	exportCmd.Flags().Bool("include-poc", true, "include proof-of-concept code")
	exportCmd.Flags().Bool("include-metadata", true, "include scan metadata")
	exportCmd.Flags().Bool("hackerone", false, "format for HackerOne submission")
	exportCmd.Flags().String("template", "standard", "export template")
	exportCmd.Flags().Bool("jira", false, "create Jira tickets")
	exportCmd.Flags().String("project", "", "Jira project key")
	exportCmd.Flags().String("webhook", "", "webhook URL for notifications")
	exportCmd.Flags().Bool("slack", false, "send to Slack")
	exportCmd.Flags().Bool("discord", false, "send to Discord")
	exportCmd.Flags().Bool("compress", false, "compress exported files")

	// Bind flags
	viper.BindPFlag("export.format", exportCmd.Flags().Lookup("format"))
	viper.BindPFlag("export.include-poc", exportCmd.Flags().Lookup("include-poc"))
	viper.BindPFlag("export.hackerone", exportCmd.Flags().Lookup("hackerone"))
}

func runExport(cmd *cobra.Command, args []string) error {
	scanID := args[0]

	// Create export configuration
	exportConfig := &export.Config{
		ScanID:          scanID,
		Format:          viper.GetString("export.format"),
		Filter:          viper.GetStringSlice("filter"),
		Categories:      viper.GetStringSlice("categories"),
		IncludePOC:      viper.GetBool("export.include-poc"),
		IncludeMetadata: viper.GetBool("export.include-metadata"),
		HackerOne:       viper.GetBool("export.hackerone"),
		Template:        viper.GetString("template"),
		Jira:            viper.GetBool("jira"),
		Project:         viper.GetString("project"),
		Webhook:         viper.GetString("webhook"),
		Slack:           viper.GetBool("slack"),
		Discord:         viper.GetBool("discord"),
		Compress:        viper.GetBool("compress"),
		OutputDir:       viper.GetString("output"),
	}

	// Initialize exporter
	exporter, err := export.NewExporter(cfg, log)
	if err != nil {
		return fmt.Errorf("failed to initialize exporter: %w", err)
	}

	log.Info("Exporting scan results",
		"scan_id", scanID,
		"format", exportConfig.Format,
		"hackerone", exportConfig.HackerOne)

	// Perform export
	result, err := exporter.Export(exportConfig)
	if err != nil {
		return fmt.Errorf("export failed: %w", err)
	}

	// Display export results
	fmt.Printf("\n📤 Export Complete\n")
	fmt.Printf("═══════════════════════════════\n")
	fmt.Printf("📄 Format: %s\n", result.Format)
	fmt.Printf("📁 Output: %s\n", result.OutputPath)
	fmt.Printf("📊 Records Exported: %d\n", result.RecordCount)
	fmt.Printf("💾 File Size: %s\n", result.FileSize)

	if result.IntegrationResults != nil {
		fmt.Printf("\n🔗 Integration Results:\n")
		for platform, status := range result.IntegrationResults {
			fmt.Printf("  • %s: %s\n", platform, status)
		}
	}

	return nil
}
