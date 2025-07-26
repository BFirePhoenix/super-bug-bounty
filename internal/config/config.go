package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config represents the application configuration
type Config struct {
	// General settings
	LogLevel   string `yaml:"log_level" default:"info"`
	LogFormat  string `yaml:"log_format" default:"text"`
	DataDir    string `yaml:"data_dir" default:"~/.bugbounty"`
	CacheDir   string `yaml:"cache_dir" default:"~/.bugbounty/cache"`
	OutputDir  string `yaml:"output_dir" default:"./output"`
	
	// API Keys
	APIKeys APIKeysConfig `yaml:"api_keys"`
	
	// Scanning settings
	Scanning ScanningConfig `yaml:"scanning"`
	
	// AI settings
	AI AIConfig `yaml:"ai"`
	
	// Reporting settings
	Reporting ReportingConfig `yaml:"reporting"`
	
	// Plugin settings
	Plugins PluginsConfig `yaml:"plugins"`
	
	// Security settings
	Security SecurityConfig `yaml:"security"`
}

type APIKeysConfig struct {
	OpenAI       string `yaml:"openai"`
	Anthropic    string `yaml:"anthropic"`
	Shodan       string `yaml:"shodan"`
	Censys       string `yaml:"censys"`
	VirusTotal   string `yaml:"virustotal"`
	SecurityTrails string `yaml:"securitytrails"`
	GitHub       string `yaml:"github"`
	Slack        string `yaml:"slack"`
	Discord      string `yaml:"discord"`
}

type ScanningConfig struct {
	DefaultThreads    int    `yaml:"default_threads" default:"50"`
	DefaultTimeout    int    `yaml:"default_timeout" default:"30"`
	MaxRetries        int    `yaml:"max_retries" default:"3"`
	RateLimit         int    `yaml:"rate_limit" default:"10"`
	UserAgent         string `yaml:"user_agent" default:"BugBountyTool/1.0"`
	FollowRedirects   bool   `yaml:"follow_redirects" default:"true"`
	VerifySSL         bool   `yaml:"verify_ssl" default:"true"`
	MaxRedirects      int    `yaml:"max_redirects" default:"10"`
	MaxBodySize       int    `yaml:"max_body_size" default:"10485760"` // 10MB
	EnableScreenshots bool   `yaml:"enable_screenshots" default:"true"`
}

type AIConfig struct {
	Provider         string  `yaml:"provider" default:"openai"`
	Model            string  `yaml:"model" default:"gpt-3.5-turbo"`
	MaxTokens        int     `yaml:"max_tokens" default:"2048"`
	Temperature      float64 `yaml:"temperature" default:"0.3"`
	EnableTriage     bool    `yaml:"enable_triage" default:"true"`
	EnablePayloadGen bool    `yaml:"enable_payload_gen" default:"true"`
	EnableReporting  bool    `yaml:"enable_reporting" default:"true"`
	CacheResults     bool    `yaml:"cache_results" default:"true"`
}

type ReportingConfig struct {
	DefaultFormat     string   `yaml:"default_format" default:"html"`
	DefaultTemplate   string   `yaml:"default_template" default:"default"`
	IncludeScreenshots bool    `yaml:"include_screenshots" default:"true"`
	IncludePOC        bool     `yaml:"include_poc" default:"true"`
	CompressReports   bool     `yaml:"compress_reports" default:"false"`
	SupportedFormats  []string `yaml:"supported_formats"`
}

type PluginsConfig struct {
	EnabledPlugins   []string `yaml:"enabled_plugins"`
	PluginDir        string   `yaml:"plugin_dir" default:"~/.bugbounty/plugins"`
	AutoUpdate       bool     `yaml:"auto_update" default:"false"`
	VerifySignatures bool     `yaml:"verify_signatures" default:"true"`
}

type SecurityConfig struct {
	EnableSandbox     bool   `yaml:"enable_sandbox" default:"true"`
	TrustedSources    []string `yaml:"trusted_sources"`
	EncryptCache      bool   `yaml:"encrypt_cache" default:"true"`
	EncryptReports    bool   `yaml:"encrypt_reports" default:"false"`
	RequireSignature  bool   `yaml:"require_signature" default:"true"`
	MaxScanDuration   int    `yaml:"max_scan_duration" default:"3600"`
}

// Load loads configuration from file and environment variables
func Load() (*Config, error) {
	config := &Config{}
	
	// Set defaults
	setDefaults(config)
	
	// Load from config file
	if err := loadFromFile(config); err != nil {
		return nil, fmt.Errorf("failed to load config file: %w", err)
	}
	
	// Override with environment variables
	if err := loadFromEnv(config); err != nil {
		return nil, fmt.Errorf("failed to load environment variables: %w", err)
	}
	
	// Validate configuration
	if err := validate(config); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}
	
	return config, nil
}

func setDefaults(config *Config) {
	config.LogLevel = "info"
	config.LogFormat = "text"
	config.DataDir = expandPath("~/.bugbounty")
	config.CacheDir = expandPath("~/.bugbounty/cache")
	config.OutputDir = "./output"
	
	config.Scanning = ScanningConfig{
		DefaultThreads:    50,
		DefaultTimeout:    30,
		MaxRetries:        3,
		RateLimit:         10,
		UserAgent:         "BugBountyTool/1.0",
		FollowRedirects:   true,
		VerifySSL:         true,
		MaxRedirects:      10,
		MaxBodySize:       10485760,
		EnableScreenshots: true,
	}
	
	config.AI = AIConfig{
		Provider:         "openai",
		Model:            "gpt-3.5-turbo",
		MaxTokens:        2048,
		Temperature:      0.3,
		EnableTriage:     true,
		EnablePayloadGen: true,
		EnableReporting:  true,
		CacheResults:     true,
	}
	
	config.Reporting = ReportingConfig{
		DefaultFormat:      "html",
		DefaultTemplate:    "default",
		IncludeScreenshots: true,
		IncludePOC:         true,
		CompressReports:    false,
		SupportedFormats:   []string{"html", "pdf", "json", "csv", "markdown"},
	}
	
	config.Plugins = PluginsConfig{
		PluginDir:        expandPath("~/.bugbounty/plugins"),
		AutoUpdate:       false,
		VerifySignatures: true,
	}
	
	config.Security = SecurityConfig{
		EnableSandbox:    true,
		EncryptCache:     true,
		EncryptReports:   false,
		RequireSignature: true,
		MaxScanDuration:  3600,
	}
}

func loadFromFile(config *Config) error {
	configPaths := []string{
		"./configs/default.yaml",
		expandPath("~/.bugbounty.yaml"),
		"/etc/bugbounty/config.yaml",
	}
	
	for _, path := range configPaths {
		if _, err := os.Stat(path); err == nil {
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			
			if err := yaml.Unmarshal(data, config); err != nil {
				return fmt.Errorf("failed to parse config file %s: %w", path, err)
			}
			
			return nil
		}
	}
	
	// No config file found, use defaults
	return nil
}

func loadFromEnv(config *Config) error {
	// API Keys from environment
	if key := os.Getenv("OPENAI_API_KEY"); key != "" {
		config.APIKeys.OpenAI = key
	}
	if key := os.Getenv("ANTHROPIC_API_KEY"); key != "" {
		config.APIKeys.Anthropic = key
	}
	if key := os.Getenv("SHODAN_API_KEY"); key != "" {
		config.APIKeys.Shodan = key
	}
	if key := os.Getenv("CENSYS_API_KEY"); key != "" {
		config.APIKeys.Censys = key
	}
	if key := os.Getenv("VIRUSTOTAL_API_KEY"); key != "" {
		config.APIKeys.VirusTotal = key
	}
	if key := os.Getenv("SECURITYTRAILS_API_KEY"); key != "" {
		config.APIKeys.SecurityTrails = key
	}
	if key := os.Getenv("GITHUB_TOKEN"); key != "" {
		config.APIKeys.GitHub = key
	}
	if key := os.Getenv("SLACK_WEBHOOK"); key != "" {
		config.APIKeys.Slack = key
	}
	if key := os.Getenv("DISCORD_WEBHOOK"); key != "" {
		config.APIKeys.Discord = key
	}
	
	return nil
}

func validate(config *Config) error {
	// Create required directories
	dirs := []string{config.DataDir, config.CacheDir, config.OutputDir, config.Plugins.PluginDir}
	for _, dir := range dirs {
		if err := os.MkdirAll(expandPath(dir), 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}
	
	// Validate scanning settings
	if config.Scanning.DefaultThreads < 1 || config.Scanning.DefaultThreads > 1000 {
		return fmt.Errorf("invalid default_threads: must be between 1 and 1000")
	}
	
	if config.Scanning.DefaultTimeout < 1 || config.Scanning.DefaultTimeout > 300 {
		return fmt.Errorf("invalid default_timeout: must be between 1 and 300 seconds")
	}
	
	// Validate AI settings
	if config.AI.Temperature < 0 || config.AI.Temperature > 2 {
		return fmt.Errorf("invalid temperature: must be between 0 and 2")
	}
	
	return nil
}

func expandPath(path string) string {
	if path[:2] == "~/" {
		home, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		return filepath.Join(home, path[2:])
	}
	return path
}
