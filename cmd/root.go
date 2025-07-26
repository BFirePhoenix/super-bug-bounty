package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/bugbounty-tool/internal/config"
	"github.com/bugbounty-tool/internal/logger"
)

var (
	cfgFile string
	cfg     *config.Config
	log     logger.Logger
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "bugbounty",
	Short: "Production-grade Bug Bounty CLI tool",
	Long: `A comprehensive, production-grade Bug Bounty CLI tool with advanced 
reconnaissance, AI-powered vulnerability analysis, and professional reporting 
capabilities designed for Kali Linux.

Features:
- Advanced subdomain enumeration and reconnaissance
- Comprehensive vulnerability scanning (XSS, SQLi, RCE, SSRF, etc.)
- AI-powered triage and payload generation
- Professional reporting with screenshots
- Multi-threaded parallel execution
- Plugin architecture for extensibility`,
	Version: "1.0.0",
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute(config *config.Config, logger logger.Logger) error {
	cfg = config
	log = logger
	return rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(initConfig)

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.bugbounty.yaml)")
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "verbose output")
	rootCmd.PersistentFlags().BoolP("quiet", "q", false, "quiet mode")
	rootCmd.PersistentFlags().String("proxy", "", "HTTP proxy URL (e.g., http://127.0.0.1:8080)")
	rootCmd.PersistentFlags().Bool("tor", false, "use Tor proxy")
	rootCmd.PersistentFlags().Int("threads", 50, "number of concurrent threads")
	rootCmd.PersistentFlags().Int("timeout", 30, "request timeout in seconds")
	rootCmd.PersistentFlags().String("user-agent", "", "custom User-Agent string")
	rootCmd.PersistentFlags().Bool("follow-redirects", true, "follow HTTP redirects")
	rootCmd.PersistentFlags().String("output", "", "output directory for results")

	// Bind flags to viper
	viper.BindPFlag("verbose", rootCmd.PersistentFlags().Lookup("verbose"))
	viper.BindPFlag("quiet", rootCmd.PersistentFlags().Lookup("quiet"))
	viper.BindPFlag("proxy", rootCmd.PersistentFlags().Lookup("proxy"))
	viper.BindPFlag("tor", rootCmd.PersistentFlags().Lookup("tor"))
	viper.BindPFlag("threads", rootCmd.PersistentFlags().Lookup("threads"))
	viper.BindPFlag("timeout", rootCmd.PersistentFlags().Lookup("timeout"))
	viper.BindPFlag("user-agent", rootCmd.PersistentFlags().Lookup("user-agent"))
	viper.BindPFlag("follow-redirects", rootCmd.PersistentFlags().Lookup("follow-redirects"))
	viper.BindPFlag("output", rootCmd.PersistentFlags().Lookup("output"))

	// Add completion command
	rootCmd.AddCommand(&cobra.Command{
		Use:   "completion",
		Short: "Generate completion script",
		Long: `To load completions:

Bash:
$ source <(bugbounty completion bash)

Zsh:
$ source <(bugbounty completion zsh)

Fish:
$ bugbounty completion fish | source

PowerShell:
PS> bugbounty completion powershell | Out-String | Invoke-Expression
`,
		DisableFlagsInUseLine: true,
		ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
		Args:                  cobra.ExactValidArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			switch args[0] {
			case "bash":
				cmd.Root().GenBashCompletion(os.Stdout)
			case "zsh":
				cmd.Root().GenZshCompletion(os.Stdout)
			case "fish":
				cmd.Root().GenFishCompletion(os.Stdout, true)
			case "powershell":
				cmd.Root().GenPowerShellCompletion(os.Stdout)
			}
		},
	})
}

// initConfig reads in config file and ENV variables.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		// Search config in home directory with name ".bugbounty" (without extension).
		viper.AddConfigPath(home)
		viper.AddConfigPath("./configs")
		viper.SetConfigType("yaml")
		viper.SetConfigName(".bugbounty")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}
