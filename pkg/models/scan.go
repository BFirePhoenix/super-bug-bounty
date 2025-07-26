package models

import (
	"time"
)

// ScanConfig represents configuration for a security scan
type ScanConfig struct {
	// Target configuration
	Target   string   `json:"target" yaml:"target"`
	Targets  []string `json:"targets,omitempty" yaml:"targets,omitempty"`
	Scope    []string `json:"scope,omitempty" yaml:"scope,omitempty"`
	Exclude  []string `json:"exclude,omitempty" yaml:"exclude,omitempty"`
	
	// Scan profile and modules
	Profile        string   `json:"profile" yaml:"profile"`
	Modules        []string `json:"modules" yaml:"modules"`
	ExcludeModules []string `json:"exclude_modules,omitempty" yaml:"exclude_modules,omitempty"`
	
	// Scanning behavior
	Passive     bool `json:"passive" yaml:"passive"`
	Aggressive  bool `json:"aggressive" yaml:"aggressive"`
	Stealth     bool `json:"stealth" yaml:"stealth"`
	DeepScan    bool `json:"deep_scan" yaml:"deep_scan"`
	QuickScan   bool `json:"quick_scan" yaml:"quick_scan"`
	
	// Authentication
	Username string `json:"username,omitempty" yaml:"username,omitempty"`
	Password string `json:"password,omitempty" yaml:"password,omitempty"`
	Cookie   string `json:"cookie,omitempty" yaml:"cookie,omitempty"`
	
	// Request configuration
	Threads       int           `json:"threads" yaml:"threads"`
	RateLimit     int           `json:"rate_limit" yaml:"rate_limit"`
	Timeout       time.Duration `json:"timeout" yaml:"timeout"`
	Delay         time.Duration `json:"delay,omitempty" yaml:"delay,omitempty"`
	UserAgent     string        `json:"user_agent" yaml:"user_agent"`
	Headers       map[string]string `json:"headers,omitempty" yaml:"headers,omitempty"`
	Proxy         string        `json:"proxy,omitempty" yaml:"proxy,omitempty"`
	UseTor        bool          `json:"use_tor" yaml:"use_tor"`
	VerifySSL     bool          `json:"verify_ssl" yaml:"verify_ssl"`
	FollowRedirects bool        `json:"follow_redirects" yaml:"follow_redirects"`
	
	// Vulnerability scanning
	VulnTypes      []string `json:"vuln_types,omitempty" yaml:"vuln_types,omitempty"`
	ExcludeVulns   []string `json:"exclude_vulns,omitempty" yaml:"exclude_vulns,omitempty"`
	PayloadFile    string   `json:"payload_file,omitempty" yaml:"payload_file,omitempty"`
	WordlistDir    string   `json:"wordlist_dir,omitempty" yaml:"wordlist_dir,omitempty"`
	
	// AI configuration
	AITriage       bool    `json:"ai_triage" yaml:"ai_triage"`
	AIPayloads     bool    `json:"ai_payloads" yaml:"ai_payloads"`
	FalsePositiveFilter bool `json:"false_positive_filter" yaml:"false_positive_filter"`
	ConfidenceThreshold float64 `json:"confidence_threshold" yaml:"confidence_threshold"`
	
	// Output configuration
	OutputDir     string   `json:"output_dir" yaml:"output_dir"`
	OutputFormat  []string `json:"output_format" yaml:"output_format"`
	Screenshots   bool     `json:"screenshots" yaml:"screenshots"`
	SaveRequests  bool     `json:"save_requests" yaml:"save_requests"`
	SaveResponses bool     `json:"save_responses" yaml:"save_responses"`
	
	// Reporting
	ReportTemplate string `json:"report_template,omitempty" yaml:"report_template,omitempty"`
	Company        string `json:"company,omitempty" yaml:"company,omitempty"`
	Pentester      string `json:"pentester,omitempty" yaml:"pentester,omitempty"`
	
	// Advanced options
	Resume         bool              `json:"resume" yaml:"resume"`
	ResumeFrom     string            `json:"resume_from,omitempty" yaml:"resume_from,omitempty"`
	MaxScanTime    time.Duration     `json:"max_scan_time,omitempty" yaml:"max_scan_time,omitempty"`
	CustomOptions  map[string]string `json:"custom_options,omitempty" yaml:"custom_options,omitempty"`
	
	// Logging
	Verbose bool `json:"verbose" yaml:"verbose"`
	Quiet   bool `json:"quiet" yaml:"quiet"`
	Debug   bool `json:"debug" yaml:"debug"`
}

// ScanResults contains the results of a security scan
type ScanResults struct {
	// Scan metadata
	ScanID        string        `json:"scan_id" yaml:"scan_id"`
	Target        string        `json:"target" yaml:"target"`
	Profile       string        `json:"profile" yaml:"profile"`
	StartTime     time.Time     `json:"start_time" yaml:"start_time"`
	EndTime       time.Time     `json:"end_time" yaml:"end_time"`
	Duration      time.Duration `json:"duration" yaml:"duration"`
	Status        string        `json:"status" yaml:"status"`
	
	// Reconnaissance results
	Subdomains    []Subdomain   `json:"subdomains,omitempty" yaml:"subdomains,omitempty"`
	Endpoints     []Endpoint    `json:"endpoints,omitempty" yaml:"endpoints,omitempty"`
	Technologies  []Technology  `json:"technologies,omitempty" yaml:"technologies,omitempty"`
	Certificates  []Certificate `json:"certificates,omitempty" yaml:"certificates,omitempty"`
	DNSRecords    []DNSRecord   `json:"dns_records,omitempty" yaml:"dns_records,omitempty"`
	Ports         []Port        `json:"ports,omitempty" yaml:"ports,omitempty"`
	
	// Vulnerability results
	Vulnerabilities    []*Vulnerability    `json:"vulnerabilities" yaml:"vulnerabilities"`
	RiskScore          float64            `json:"risk_score" yaml:"risk_score"`
	SecurityScore      float64            `json:"security_score" yaml:"security_score"`
	
	// AI analysis results
	AITriage           []AITriageResult   `json:"ai_triage,omitempty" yaml:"ai_triage,omitempty"`
	GeneratedPayloads  []GeneratedPayload `json:"generated_payloads,omitempty" yaml:"generated_payloads,omitempty"`
	Recommendations    []string           `json:"recommendations,omitempty" yaml:"recommendations,omitempty"`
	FalsePositives     []string           `json:"false_positives,omitempty" yaml:"false_positives,omitempty"`
	
	// Statistics  
	Statistics         ScanStatistics     `json:"statistics" yaml:"statistics"`
	
	// Output information
	OutputPath    string            `json:"output_path,omitempty" yaml:"output_path,omitempty"`
	ReportFiles   map[string]string `json:"report_files,omitempty" yaml:"report_files,omitempty"`
	Screenshots   []Screenshot      `json:"screenshots,omitempty" yaml:"screenshots,omitempty"`
	
	// Metadata
	Version       string            `json:"version" yaml:"version"`
	Scanner       string            `json:"scanner" yaml:"scanner"`
	Config        *ScanConfig       `json:"config,omitempty" yaml:"config,omitempty"`
	Environment   ScanEnvironment   `json:"environment" yaml:"environment"`
	
	// Additional data
	CustomData    map[string]interface{} `json:"custom_data,omitempty" yaml:"custom_data,omitempty"`
	Tags          []string               `json:"tags,omitempty" yaml:"tags,omitempty"`
	Notes         string                 `json:"notes,omitempty" yaml:"notes,omitempty"`
}

// ScanSession represents an active scan session
type ScanSession struct {
	ID         string            `json:"id"`
	Target     string            `json:"target"`
	Config     *ScanConfig       `json:"config"`
	StartTime  time.Time         `json:"start_time"`
	Status     string            `json:"status"`
	Progress   ScanProgress      `json:"progress"`
	Results    *ScanResults      `json:"results,omitempty"`
	CancelFunc context.CancelFunc `json:"-"`
	Metrics    ScanMetrics       `json:"metrics"`
}

// ScanProgress tracks scan progress
type ScanProgress struct {
	CurrentModule  string    `json:"current_module"`
	ModulesTotal   int       `json:"modules_total"`
	ModulesComplete int      `json:"modules_complete"`
	TargetsTotal   int       `json:"targets_total"`
	TargetsComplete int      `json:"targets_complete"`
	VulnsFound     int       `json:"vulns_found"`
	Percentage     float64   `json:"percentage"`
	EstimatedTime  time.Duration `json:"estimated_time"`
	LastUpdate     time.Time `json:"last_update"`
}

// ScanMetrics contains performance metrics
type ScanMetrics struct {
	RequestsSent     int64         `json:"requests_sent"`
	ResponsesReceived int64        `json:"responses_received"`
	ErrorsEncountered int64        `json:"errors_encountered"`
	AverageResponseTime time.Duration `json:"average_response_time"`
	DataTransferred  int64         `json:"data_transferred"`
	ThreadsUsed      int           `json:"threads_used"`
	MemoryUsed       int64         `json:"memory_used"`
	CPUUsage         float64       `json:"cpu_usage"`
}

// ScanStatistics contains scan statistics
type ScanStatistics struct {
	// General stats
	TotalRequests       int           `json:"total_requests"`
	TotalResponses      int           `json:"total_responses"`
	TotalErrors         int           `json:"total_errors"`
	AverageResponseTime time.Duration `json:"average_response_time"`
	
	// Discovery stats
	SubdomainsFound   int `json:"subdomains_found"`
	EndpointsFound    int `json:"endpoints_found"`
	FormsFound        int `json:"forms_found"`
	ParametersFound   int `json:"parameters_found"`
	TechnologiesFound int `json:"technologies_found"`
	
	// Vulnerability stats
	VulnerabilitiesFound int                    `json:"vulnerabilities_found"`
	VulnsBySeverity      map[string]int         `json:"vulns_by_severity"`
	VulnsByType          map[string]int         `json:"vulns_by_type"`
	VulnsByConfidence    map[string]int         `json:"vulns_by_confidence"`
	HighestSeverity      string                 `json:"highest_severity"`
	
	// Performance stats
	ScanDuration         time.Duration          `json:"scan_duration"`
	RequestsPerSecond    float64                `json:"requests_per_second"`
	DataTransferred      int64                  `json:"data_transferred"`
	
	// Module stats
	ModuleStats          map[string]ModuleStats `json:"module_stats"`
}

// ModuleStats contains statistics for individual modules
type ModuleStats struct {
	Name            string        `json:"name"`
	Duration        time.Duration `json:"duration"`
	RequestsSent    int           `json:"requests_sent"`
	VulnsFound      int           `json:"vulns_found"`
	Success         bool          `json:"success"`
	ErrorMessage    string        `json:"error_message,omitempty"`
}

// ScanEnvironment contains information about the scan environment
type ScanEnvironment struct {
	OS           string    `json:"os"`
	Architecture string    `json:"architecture"`
	GoVersion    string    `json:"go_version"`
	Hostname     string    `json:"hostname"`
	WorkingDir   string    `json:"working_dir"`
	Timestamp    time.Time `json:"timestamp"`
	UserAgent    string    `json:"user_agent"`
	ProxyUsed    bool      `json:"proxy_used"`
	TorUsed      bool      `json:"tor_used"`
}

// DNSRecord represents a DNS record
type DNSRecord struct {
	Name  string `json:"name" yaml:"name"`
	Type  string `json:"type" yaml:"type"`
	Value string `json:"value" yaml:"value"`
	TTL   int    `json:"ttl" yaml:"ttl"`
}

// AITriageResult represents AI triage analysis result
type AITriageResult struct {
	VulnID           string    `json:"vuln_id"`
	OriginalSeverity string    `json:"original_severity"`
	NewSeverity      string    `json:"new_severity"`
	Confidence       float64   `json:"confidence"`
	Reasoning        string    `json:"reasoning"`
	IsFalsePositive  bool      `json:"is_false_positive"`
	Timestamp        time.Time `json:"timestamp"`
}

// CrawlResults represents web crawling results
type CrawlResults struct {
	Target    string        `json:"target"`
	StartTime time.Time     `json:"start_time"`
	EndTime   time.Time     `json:"end_time"`
	Duration  time.Duration `json:"duration"`
	URLs      []string      `json:"urls"`
	Forms     []Form        `json:"forms"`
	Endpoints []Endpoint    `json:"endpoints"`
	JSFiles   []string      `json:"js_files"`
	CSSFiles  []string      `json:"css_files"`
	Images    []string      `json:"images"`
	Error     string        `json:"error,omitempty"`
}

// ReconResults represents reconnaissance results
type ReconResults struct {
	Domain       string        `json:"domain"`
	StartTime    time.Time     `json:"start_time"`
	EndTime      time.Time     `json:"end_time"`
	Duration     time.Duration `json:"duration"`
	Subdomains   []Subdomain   `json:"subdomains"`
	Technologies []Technology  `json:"technologies"`
	Certificates []Certificate `json:"certificates"`
	DNSRecords   []DNSRecord   `json:"dns_records"`
}

// TechnologyProfile represents technology fingerprinting results
type TechnologyProfile struct {
	Target       string        `json:"target"`
	StartTime    time.Time     `json:"start_time"`
	EndTime      time.Time     `json:"end_time"`
	Duration     time.Duration `json:"duration"`
	Technologies []Technology  `json:"technologies"`
}

// ScanProfile represents a scan configuration profile
type ScanProfile struct {
	Name        string      `json:"name" yaml:"name"`
	Description string      `json:"description" yaml:"description"`
	Config      ScanConfig  `json:"config" yaml:"config"`
	Tags        []string    `json:"tags,omitempty" yaml:"tags,omitempty"`
	CreatedAt   time.Time   `json:"created_at" yaml:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at" yaml:"updated_at"`
	CreatedBy   string      `json:"created_by,omitempty" yaml:"created_by,omitempty"`
	IsDefault   bool        `json:"is_default" yaml:"is_default"`
}

// ScanQueue represents a scan queue item
type ScanQueue struct {
	ID          string      `json:"id"`
	Target      string      `json:"target"`
	Config      ScanConfig  `json:"config"`
	Priority    int         `json:"priority"`
	Status      string      `json:"status"`
	ScheduledAt time.Time   `json:"scheduled_at"`
	StartedAt   *time.Time  `json:"started_at,omitempty"`
	CompletedAt *time.Time  `json:"completed_at,omitempty"`
	CreatedBy   string      `json:"created_by,omitempty"`
	RetryCount  int         `json:"retry_count"`
	MaxRetries  int         `json:"max_retries"`
	Error       string      `json:"error,omitempty"`
}

// Methods for ScanConfig

// Validate validates the scan configuration
func (sc *ScanConfig) Validate() error {
	if sc.Target == "" && len(sc.Targets) == 0 {
		return fmt.Errorf("no target specified")
	}
	
	if sc.Threads <= 0 {
		sc.Threads = 50
	}
	
	if sc.Timeout <= 0 {
		sc.Timeout = 30 * time.Second
	}
	
	if sc.RateLimit <= 0 {
		sc.RateLimit = 10
	}
	
	return nil
}

// SetDefaults sets default values for scan configuration
func (sc *ScanConfig) SetDefaults() {
	if sc.Profile == "" {
		sc.Profile = "default"
	}
	
	if len(sc.Modules) == 0 {
		sc.Modules = []string{"recon", "vuln"}
	}
	
	if sc.Threads == 0 {
		sc.Threads = 50
	}
	
	if sc.RateLimit == 0 {
		sc.RateLimit = 10
	}
	
	if sc.Timeout == 0 {
		sc.Timeout = 30 * time.Second
	}
	
	if sc.UserAgent == "" {
		sc.UserAgent = "BugBountyTool/1.0"
	}
	
	if len(sc.OutputFormat) == 0 {
		sc.OutputFormat = []string{"json", "html"}
	}
}

// HasModule checks if a module is enabled
func (sc *ScanConfig) HasModule(module string) bool {
	for _, m := range sc.Modules {
		if m == module {
			return true
		}
	}
	return false
}

// IsModuleExcluded checks if a module is excluded
func (sc *ScanConfig) IsModuleExcluded(module string) bool {
	for _, m := range sc.ExcludeModules {
		if m == module {
			return true
		}
	}
	return false
}

// Methods for ScanResults

// AddVulnerability adds a vulnerability to the results
func (sr *ScanResults) AddVulnerability(vuln *Vulnerability) {
	if sr.Vulnerabilities == nil {
		sr.Vulnerabilities = make([]*Vulnerability, 0)
	}
	sr.Vulnerabilities = append(sr.Vulnerabilities, vuln)
}

// GetVulnerabilitiesBySeverity returns vulnerabilities filtered by severity
func (sr *ScanResults) GetVulnerabilitiesBySeverity(severity string) []*Vulnerability {
	var filtered []*Vulnerability
	for _, vuln := range sr.Vulnerabilities {
		if vuln.Severity == severity {
			filtered = append(filtered, vuln)
		}
	}
	return filtered
}

// GetHighRiskVulnerabilities returns critical and high severity vulnerabilities
func (sr *ScanResults) GetHighRiskVulnerabilities() []*Vulnerability {
	var highRisk []*Vulnerability
	for _, vuln := range sr.Vulnerabilities {
		if vuln.IsHighRisk() {
			highRisk = append(highRisk, vuln)
		}
	}
	return highRisk
}

// CalculateRiskScore calculates overall risk score
func (sr *ScanResults) CalculateRiskScore() float64 {
	if len(sr.Vulnerabilities) == 0 {
		return 0.0
	}
	
	var totalScore float64
	weights := map[string]float64{
		"critical": 5.0,
		"high":     4.0,
		"medium":   3.0,
		"low":      2.0,
		"info":     1.0,
	}
	
	for _, vuln := range sr.Vulnerabilities {
		if weight, exists := weights[strings.ToLower(vuln.Severity)]; exists {
			confidence := float64(vuln.Confidence) / 100.0
			totalScore += weight * confidence
		}
	}
	
	// Normalize score to 0-10 scale
	maxPossibleScore := float64(len(sr.Vulnerabilities)) * 5.0
	sr.RiskScore = (totalScore / maxPossibleScore) * 10.0
	
	return sr.RiskScore
}

// UpdateStatistics updates scan statistics
func (sr *ScanResults) UpdateStatistics() {
	sr.Statistics.VulnerabilitiesFound = len(sr.Vulnerabilities)
	sr.Statistics.SubdomainsFound = len(sr.Subdomains)
	sr.Statistics.EndpointsFound = len(sr.Endpoints)
	sr.Statistics.TechnologiesFound = len(sr.Technologies)
	
	// Count vulnerabilities by severity
	sr.Statistics.VulnsBySeverity = make(map[string]int)
	sr.Statistics.VulnsByType = make(map[string]int)
	
	for _, vuln := range sr.Vulnerabilities {
		sr.Statistics.VulnsBySeverity[vuln.Severity]++
		sr.Statistics.VulnsByType[vuln.Type]++
		
		// Track highest severity
		if sr.Statistics.HighestSeverity == "" || 
		   vuln.GetSeverityScore() > getSeverityScore(sr.Statistics.HighestSeverity) {
			sr.Statistics.HighestSeverity = vuln.Severity
		}
	}
	
	sr.Statistics.ScanDuration = sr.Duration
}

// Methods for ScanSession

// UpdateProgress updates scan progress
func (ss *ScanSession) UpdateProgress(module string, moduleProgress, totalProgress float64) {
	ss.Progress.CurrentModule = module
	ss.Progress.Percentage = totalProgress
	ss.Progress.LastUpdate = time.Now()
	
	if ss.Results != nil {
		ss.Progress.VulnsFound = len(ss.Results.Vulnerabilities)
	}
}

// IsActive returns true if the scan is currently running
func (ss *ScanSession) IsActive() bool {
	return ss.Status == "running" || ss.Status == "starting"
}

// Cancel cancels the scan session
func (ss *ScanSession) Cancel() {
	if ss.CancelFunc != nil {
		ss.CancelFunc()
	}
	ss.Status = "cancelled"
}

// Helper functions

func getSeverityScore(severity string) int {
	scores := map[string]int{
		"critical": 5,
		"high":     4,
		"medium":   3,
		"low":      2,
		"info":     1,
	}
	
	if score, exists := scores[strings.ToLower(severity)]; exists {
		return score
	}
	return 0
}

// GenerateScanID generates a unique scan ID
func GenerateScanID() string {
	return fmt.Sprintf("scan-%d", time.Now().Unix())
}
