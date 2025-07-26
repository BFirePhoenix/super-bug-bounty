package cmd

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/bugbounty-tool/internal/scanner"
	"github.com/bugbounty-tool/pkg/models"
)

var scanCmd = &cobra.Command{
	Use:   "scan [target]",
	Short: "Start a comprehensive security scan",
	Long: `Perform a comprehensive security scan on the target including:
- Subdomain enumeration and reconnaissance
- Technology fingerprinting  
- Vulnerability scanning (XSS, SQLi, RCE, SSRF, etc.)
- AI-powered triage and analysis
- Professional reporting

Examples:
  bugbounty scan example.com
  bugbounty scan https://example.com --profile aggressive
  bugbounty scan example.com --modules recon,vuln --output /tmp/scan-results`,
	Args: cobra.ExactArgs(1),
	RunE: runScan,
}

func init() {
	rootCmd.AddCommand(scanCmd)

	// Scan-specific flags
	scanCmd.Flags().String("profile", "default", "scan profile (default, aggressive, stealth)")
	scanCmd.Flags().StringSlice("modules", []string{"recon", "vuln", "ai"}, "modules to run (recon,vuln,ai,report)")
	scanCmd.Flags().StringSlice("exclude-modules", []string{}, "modules to exclude")
	scanCmd.Flags().Bool("recon-only", false, "perform reconnaissance only")
	scanCmd.Flags().Bool("vuln-only", false, "perform vulnerability scanning only")
	scanCmd.Flags().Bool("passive", false, "passive scanning only (no active probing)")
	scanCmd.Flags().StringSlice("exclude-vulns", []string{}, "vulnerability types to exclude")
	scanCmd.Flags().StringSlice("include-vulns", []string{}, "only scan for specific vulnerability types")
	scanCmd.Flags().Bool("screenshots", true, "capture screenshots of findings")
	scanCmd.Flags().Bool("ai-triage", true, "enable AI-powered vulnerability triage")
	scanCmd.Flags().String("scope", "", "scope file with in-scope domains/IPs")
	scanCmd.Flags().String("exclude-scope", "", "file with out-of-scope domains/IPs")
	scanCmd.Flags().Int("rate-limit", 10, "requests per second rate limit")
	scanCmd.Flags().Duration("delay", 0, "delay between requests")
	scanCmd.Flags().Bool("verify-ssl", true, "verify SSL certificates")
	scanCmd.Flags().StringSlice("headers", []string{}, "custom headers (Header: Value)")
	scanCmd.Flags().String("cookie", "", "cookie string for authenticated scanning")
	scanCmd.Flags().Bool("resume", false, "resume previous scan")
	scanCmd.Flags().String("resume-from", "", "resume scan from specific checkpoint")

	// Bind flags
	viper.BindPFlag("scan.profile", scanCmd.Flags().Lookup("profile"))
	viper.BindPFlag("scan.modules", scanCmd.Flags().Lookup("modules"))
	viper.BindPFlag("scan.exclude-modules", scanCmd.Flags().Lookup("exclude-modules"))
	viper.BindPFlag("scan.passive", scanCmd.Flags().Lookup("passive"))
	viper.BindPFlag("scan.screenshots", scanCmd.Flags().Lookup("screenshots"))
	viper.BindPFlag("scan.ai-triage", scanCmd.Flags().Lookup("ai-triage"))
	viper.BindPFlag("scan.rate-limit", scanCmd.Flags().Lookup("rate-limit"))
	viper.BindPFlag("scan.verify-ssl", scanCmd.Flags().Lookup("verify-ssl"))
}

func runScan(cmd *cobra.Command, args []string) error {
	target := args[0]
	
	// Validate target
	if !isValidTarget(target) {
		return fmt.Errorf("invalid target format: %s", target)
	}

	// Create scan configuration
	scanConfig := &models.ScanConfig{
		Target:      target,
		Profile:     viper.GetString("scan.profile"),
		Modules:     viper.GetStringSlice("scan.modules"),
		Passive:     viper.GetBool("scan.passive"),
		Screenshots: viper.GetBool("scan.screenshots"),
		AITriage:    viper.GetBool("scan.ai-triage"),
		RateLimit:   viper.GetInt("scan.rate-limit"),
		VerifySSL:   viper.GetBool("scan.verify-ssl"),
		Threads:     viper.GetInt("threads"),
		Timeout:     time.Duration(viper.GetInt("timeout")) * time.Second,
		UserAgent:   viper.GetString("user-agent"),
		Proxy:       viper.GetString("proxy"),
		UseTor:      viper.GetBool("tor"),
		OutputDir:   viper.GetString("output"),
		Verbose:     viper.GetBool("verbose"),
		Quiet:       viper.GetBool("quiet"),
	}

	// Parse custom headers
	if headers := viper.GetStringSlice("headers"); len(headers) > 0 {
		scanConfig.Headers = make(map[string]string)
		for _, header := range headers {
			parts := strings.SplitN(header, ":", 2)
			if len(parts) == 2 {
				scanConfig.Headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}
	}

	// Initialize scanner
	s, err := scanner.New(cfg, log)
	if err != nil {
		return fmt.Errorf("failed to initialize scanner: %w", err)
	}

	// Create context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log.Info("Starting comprehensive security scan", 
		"target", target, 
		"profile", scanConfig.Profile,
		"modules", strings.Join(scanConfig.Modules, ","))

	// Execute scan
	results, err := s.Scan(ctx, scanConfig)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	// Display summary
	displayScanSummary(results)

	log.Info("Scan completed successfully", 
		"vulnerabilities", len(results.Vulnerabilities),
		"duration", results.Duration,
		"output", results.OutputPath)

	return nil
}

func isValidTarget(target string) bool {
	// Basic target validation
	if target == "" {
		return false
	}
	
	// Allow domains, IPs, and URLs
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		return true
	}
	
	// Simple domain/IP validation
	return len(target) > 0 && !strings.Contains(target, " ")
}

func displayScanSummary(results *models.ScanResults) {
	fmt.Printf("\n🎯 Scan Summary for %s\n", results.Target)
	fmt.Printf("═══════════════════════════════════════\n")
	fmt.Printf("⏱️  Duration: %v\n", results.Duration)
	fmt.Printf("🔍 Subdomains Found: %d\n", len(results.Subdomains))
	fmt.Printf("🌐 Endpoints Discovered: %d\n", len(results.Endpoints))
	fmt.Printf("⚠️  Vulnerabilities: %d\n", len(results.Vulnerabilities))
	
	// Vulnerability breakdown by severity
	critical, high, medium, low, info := 0, 0, 0, 0, 0
	for _, vuln := range results.Vulnerabilities {
		switch vuln.Severity {
		case "critical":
			critical++
		case "high":
			high++
		case "medium":
			medium++
		case "low":
			low++
		case "info":
			info++
		}
	}

	if critical+high+medium+low+info > 0 {
		fmt.Printf("\n📊 Severity Breakdown:\n")
		if critical > 0 {
			fmt.Printf("  🔴 Critical: %d\n", critical)
		}
		if high > 0 {
			fmt.Printf("  🟠 High: %d\n", high)
		}
		if medium > 0 {
			fmt.Printf("  🟡 Medium: %d\n", medium)
		}
		if low > 0 {
			fmt.Printf("  🔵 Low: %d\n", low)
		}
		if info > 0 {
			fmt.Printf("  ⚪ Info: %d\n", info)
		}
	}

	fmt.Printf("\n📁 Results saved to: %s\n", results.OutputPath)
	fmt.Printf("💡 Use 'bugbounty report %s' to generate detailed reports\n", results.ScanID)
}
