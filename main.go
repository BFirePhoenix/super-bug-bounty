package main

import (
	"fmt"
	"os"

	"github.com/bugbounty-tool/cmd"
	"github.com/bugbounty-tool/internal/config"
	"github.com/bugbounty-tool/internal/logger"
)

func main() {
	// Initialize configuration
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading configuration: %v\n", err)
		os.Exit(1)
	}

	// Initialize logger
	log := logger.New(cfg.LogLevel, cfg.LogFormat)

	// Check environment compatibility
	if err := checkEnvironment(); err != nil {
		log.Fatal("Environment check failed", "error", err)
	}

	// Execute command
	if err := cmd.Execute(cfg, log); err != nil {
		log.Fatal("Command execution failed", "error", err)
		os.Exit(1)
	}
}

// checkEnvironment verifies the system is compatible
func checkEnvironment() error {
	// Check for required tools
	requiredTools := []string{"nmap", "curl", "python3"}
	for _, tool := range requiredTools {
		if !isCommandAvailable(tool) {
			return fmt.Errorf("required tool not found: %s", tool)
		}
	}

	// Detect OS
	if !isSupportedOS() {
		return fmt.Errorf("unsupported operating system")
	}

	return nil
}

func isCommandAvailable(command string) bool {
	_, err := os.Stat(fmt.Sprintf("/usr/bin/%s", command))
	if err == nil {
		return true
	}
	_, err = os.Stat(fmt.Sprintf("/bin/%s", command))
	return err == nil
}

func isSupportedOS() bool {
	// Check for Kali Linux or Debian-based systems
	if _, err := os.Stat("/etc/debian_version"); err == nil {
		return true
	}
	return false
}
