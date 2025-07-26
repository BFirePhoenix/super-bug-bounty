package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/bugbounty-tool/internal/ai"
)

var triageCmd = &cobra.Command{
	Use:   "triage [scan-id]",
	Short: "AI-powered vulnerability triage and prioritization",
	Long: `Use advanced AI algorithms to automatically triage and prioritize 
vulnerabilities from scan results:

- Severity classification using machine learning
- False positive detection and filtering
- Business impact assessment
- Exploit probability scoring
- Remediation priority ranking
- Custom payload generation for verified vulnerabilities

Examples:
  bugbounty triage scan-123456
  bugbounty triage scan-123456 --auto-verify
  bugbounty triage scan-123456 --generate-payloads
  bugbounty triage scan-123456 --filter-fps`,
	Args: cobra.ExactArgs(1),
	RunE: runTriage,
}

func init() {
	rootCmd.AddCommand(triageCmd)

	// Triage-specific flags
	triageCmd.Flags().Bool("auto-verify", false, "automatically verify vulnerabilities")
	triageCmd.Flags().Bool("generate-payloads", false, "generate custom exploit payloads")
	triageCmd.Flags().Bool("filter-fps", true, "filter false positives using AI")
	triageCmd.Flags().Bool("business-impact", false, "assess business impact")
	triageCmd.Flags().Float64("confidence-threshold", 0.8, "minimum confidence threshold for classification")
	triageCmd.Flags().StringSlice("models", []string{"severity", "exploitability"}, "AI models to use")
	triageCmd.Flags().Bool("interactive", false, "interactive triage mode with manual review")
	triageCmd.Flags().String("training-data", "", "path to custom training data")
	triageCmd.Flags().Bool("learn", true, "learn from manual feedback to improve AI")

	// Bind flags
	viper.BindPFlag("triage.auto-verify", triageCmd.Flags().Lookup("auto-verify"))
	viper.BindPFlag("triage.generate-payloads", triageCmd.Flags().Lookup("generate-payloads"))
	viper.BindPFlag("triage.filter-fps", triageCmd.Flags().Lookup("filter-fps"))
}

func runTriage(cmd *cobra.Command, args []string) error {
	scanID := args[0]

	// Create triage configuration
	triageConfig := &ai.TriageConfig{
		ScanID:               scanID,
		AutoVerify:           viper.GetBool("triage.auto-verify"),
		GeneratePayloads:     viper.GetBool("triage.generate-payloads"),
		FilterFalsePositives: viper.GetBool("triage.filter-fps"),
		BusinessImpact:       viper.GetBool("business-impact"),
		ConfidenceThreshold:  viper.GetFloat64("confidence-threshold"),
		Models:               viper.GetStringSlice("models"),
		Interactive:          viper.GetBool("interactive"),
		TrainingData:         viper.GetString("training-data"),
		Learn:                viper.GetBool("learn"),
	}

	// Initialize AI triage engine
	engine, err := ai.NewTriageEngine(cfg, log)
	if err != nil {
		return fmt.Errorf("failed to initialize AI triage engine: %w", err)
	}

	log.Info("Starting AI-powered vulnerability triage",
		"scan_id", scanID,
		"auto_verify", triageConfig.AutoVerify,
		"generate_payloads", triageConfig.GeneratePayloads)

	// Perform triage
	results, err := engine.Triage(triageConfig)
	if err != nil {
		return fmt.Errorf("triage failed: %w", err)
	}

	// Display triage results
	displayTriageResults(results)

	return nil
}

func displayTriageResults(results *ai.TriageResults) {
	fmt.Printf("\n🤖 AI Triage Results\n")
	fmt.Printf("═══════════════════════════════════\n")
	fmt.Printf("📊 Total Vulnerabilities Processed: %d\n", results.TotalProcessed)
	fmt.Printf("✅ Verified Vulnerabilities: %d\n", results.VerifiedCount)
	fmt.Printf("❌ False Positives Filtered: %d\n", results.FalsePositiveCount)
	fmt.Printf("🎯 High Priority Issues: %d\n", results.HighPriorityCount)
	fmt.Printf("⏱️  Processing Time: %v\n", results.ProcessingTime)

	if len(results.Reclassifications) > 0 {
		fmt.Printf("\n🔄 Severity Reclassifications:\n")
		for _, reclass := range results.Reclassifications {
			fmt.Printf("  • %s: %s → %s (confidence: %.1f%%)\n",
				reclass.VulnID,
				reclass.OriginalSeverity,
				reclass.NewSeverity,
				reclass.Confidence*100)
		}
	}

	if len(results.GeneratedPayloads) > 0 {
		fmt.Printf("\n🎯 Custom Payloads Generated:\n")
		for vulnType, count := range results.GeneratedPayloads {
			fmt.Printf("  • %s: %d payloads\n", vulnType, count)
		}
	}

	fmt.Printf("\n💡 Recommendations:\n")
	for _, rec := range results.Recommendations {
		fmt.Printf("  • %s\n", rec)
	}
}
