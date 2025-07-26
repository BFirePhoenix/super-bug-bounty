package report

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/bugbounty-tool/internal/config"
	"github.com/bugbounty-tool/internal/logger"
	"github.com/bugbounty-tool/pkg/models"
	"gopkg.in/yaml.v3"
)

// Generator creates comprehensive security reports
type Generator struct {
	config    *config.Config
	log       logger.Logger
	templates map[string]*template.Template
}

// Config contains report generation configuration
type Config struct {
	ScanID             string
	Formats            []string
	Template           string
	IncludeScreenshots bool
	IncludePOC         bool
	IncludeTimeline    bool
	IncludeRiskMatrix  bool
	Severities         []string
	Categories         []string
	ExecutiveSummary   bool
	Company            string
	Pentester          string
	Anonymize          bool
	Compress           bool
	OutputDir          string
}

// ReportData contains all data needed for report generation
type ReportData struct {
	ScanResults     *models.ScanResults
	ExecutiveSummary *ExecutiveSummary
	TechnicalFindings *TechnicalFindings
	RiskMatrix      *RiskMatrix
	Timeline        *Timeline
	Statistics      *Statistics
	Metadata        *ReportMetadata
}

// ExecutiveSummary contains high-level findings summary
type ExecutiveSummary struct {
	OverallRisk       string
	CriticalIssues    int
	HighIssues        int
	MediumIssues      int
	LowIssues         int
	InfoIssues        int
	TotalIssues       int
	KeyFindings       []string
	Recommendations   []string
	BusinessImpact    string
}

// TechnicalFindings contains detailed vulnerability information
type TechnicalFindings struct {
	VulnerabilitiesByCategory map[string][]*models.Vulnerability
	VulnerabilitiesBySeverity map[string][]*models.Vulnerability
	UniqueVulnTypes          []string
	AffectedEndpoints        []string
	TechnicalRecommendations []string
}

// RiskMatrix represents risk assessment visualization
type RiskMatrix struct {
	Vulnerabilities []RiskItem
	Categories      []string
	MaxRisk         int
}

// RiskItem represents a single item in the risk matrix
type RiskItem struct {
	Title       string
	Severity    string
	Likelihood  int
	Impact      int
	RiskScore   int
	Category    string
}

// Timeline shows scan progression over time
type Timeline struct {
	Events []TimelineEvent
}

// TimelineEvent represents a single event in the scan timeline
type TimelineEvent struct {
	Timestamp   time.Time
	Type        string
	Description string
	Details     map[string]interface{}
}

// Statistics contains scan and vulnerability statistics
type Statistics struct {
	ScanDuration        time.Duration
	TargetsScanned      int
	EndpointsDiscovered int
	TotalRequests       int
	VulnerabilitiesFound int
	FalsePositives      int
	VerifiedVulns       int
	TopVulnTypes        []VulnTypeStat
	SeverityDistribution map[string]int
}

// VulnTypeStat represents vulnerability type statistics
type VulnTypeStat struct {
	Type  string
	Count int
}

// ReportMetadata contains report generation metadata
type ReportMetadata struct {
	GeneratedAt    time.Time
	Generator      string
	Version        string
	ScanID         string
	Target         string
	Company        string
	Pentester      string
	Template       string
	Formats        []string
}

// NewGenerator creates a new report generator
func NewGenerator(cfg *config.Config, log logger.Logger) (*Generator, error) {
	g := &Generator{
		config:    cfg,
		log:       log,
		templates: make(map[string]*template.Template),
	}
	
	// Load report templates
	if err := g.loadTemplates(); err != nil {
		return nil, fmt.Errorf("failed to load templates: %w", err)
	}
	
	return g, nil
}

// Generate creates reports in specified formats
func (g *Generator) Generate(config *Config) (map[string]string, error) {
	g.log.Info("Generating security reports",
		"scan_id", config.ScanID,
		"formats", strings.Join(config.Formats, ","),
		"template", config.Template)
	
	// Load scan results
	scanResults, err := g.loadScanResults(config.ScanID)
	if err != nil {
		return nil, fmt.Errorf("failed to load scan results: %w", err)
	}
	
	// Filter results based on configuration
	scanResults = g.filterResults(scanResults, config)
	
	// Prepare report data
	reportData, err := g.prepareReportData(scanResults, config)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare report data: %w", err)
	}
	
	// Generate reports in each format
	outputFiles := make(map[string]string)
	
	for _, format := range config.Formats {
		outputPath, err := g.generateReport(reportData, format, config)
		if err != nil {
			g.log.Error("Failed to generate report", "format", format, "error", err)
			continue
		}
		outputFiles[format] = outputPath
	}
	
	g.log.Info("Report generation completed",
		"scan_id", config.ScanID,
		"formats_generated", len(outputFiles))
	
	return outputFiles, nil
}

// generateReport creates a single report in the specified format
func (g *Generator) generateReport(data *ReportData, format string, config *Config) (string, error) {
	switch strings.ToLower(format) {
	case "html":
		return g.generateHTMLReport(data, config)
	case "pdf":
		return g.generatePDFReport(data, config)
	case "json":
		return g.generateJSONReport(data, config)
	case "csv":
		return g.generateCSVReport(data, config)
	case "markdown":
		return g.generateMarkdownReport(data, config)
	case "yaml":
		return g.generateYAMLReport(data, config)
	case "xml":
		return g.generateXMLReport(data, config)
	default:
		return "", fmt.Errorf("unsupported format: %s", format)
	}
}

// generateHTMLReport creates an HTML report
func (g *Generator) generateHTMLReport(data *ReportData, config *Config) (string, error) {
	templateName := config.Template
	if templateName == "" {
		templateName = "default"
	}
	
	tmpl, exists := g.templates[templateName]
	if !exists {
		return "", fmt.Errorf("template not found: %s", templateName)
	}
	
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("template execution failed: %w", err)
	}
	
	// Create output file
	filename := fmt.Sprintf("security_report_%s_%s.html", 
		data.Metadata.ScanID, 
		time.Now().Format("20060102_150405"))
	
	outputPath := filepath.Join(config.OutputDir, filename)
	if err := os.WriteFile(outputPath, buf.Bytes(), 0644); err != nil {
		return "", fmt.Errorf("failed to write HTML report: %w", err)
	}
	
	return outputPath, nil
}

// generatePDFReport creates a PDF report
func (g *Generator) generatePDFReport(data *ReportData, config *Config) (string, error) {
	// First generate HTML, then convert to PDF
	htmlPath, err := g.generateHTMLReport(data, config)
	if err != nil {
		return "", err
	}
	
	// Convert HTML to PDF using wkhtmltopdf or similar tool
	pdfPath := strings.Replace(htmlPath, ".html", ".pdf", 1)
	
	// For now, return HTML path (PDF conversion would require external tool)
	return htmlPath, nil
}

// generateJSONReport creates a JSON report
func (g *Generator) generateJSONReport(data *ReportData, config *Config) (string, error) {
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return "", fmt.Errorf("JSON marshaling failed: %w", err)
	}
	
	filename := fmt.Sprintf("security_report_%s_%s.json",
		data.Metadata.ScanID,
		time.Now().Format("20060102_150405"))
	
	outputPath := filepath.Join(config.OutputDir, filename)
	if err := os.WriteFile(outputPath, jsonData, 0644); err != nil {
		return "", fmt.Errorf("failed to write JSON report: %w", err)
	}
	
	return outputPath, nil
}

// generateCSVReport creates a CSV report
func (g *Generator) generateCSVReport(data *ReportData, config *Config) (string, error) {
	filename := fmt.Sprintf("vulnerabilities_%s_%s.csv",
		data.Metadata.ScanID,
		time.Now().Format("20060102_150405"))
	
	outputPath := filepath.Join(config.OutputDir, filename)
	file, err := os.Create(outputPath)
	if err != nil {
		return "", fmt.Errorf("failed to create CSV file: %w", err)
	}
	defer file.Close()
	
	writer := csv.NewWriter(file)
	defer writer.Flush()
	
	// Write CSV header
	header := []string{
		"ID", "Type", "Severity", "Title", "URL", "Parameter", 
		"Method", "Confidence", "Risk", "Status", "Detected",
	}
	if err := writer.Write(header); err != nil {
		return "", err
	}
	
	// Write vulnerability data
	for _, vuln := range data.ScanResults.Vulnerabilities {
		record := []string{
			vuln.ID,
			vuln.Type,
			vuln.Severity,
			vuln.Title,
			vuln.URL,
			vuln.Parameter,
			vuln.Method,
			fmt.Sprintf("%d", vuln.Confidence),
			vuln.Risk,
			"Open", // Default status
			vuln.Timestamp.Format("2006-01-02 15:04:05"),
		}
		if err := writer.Write(record); err != nil {
			return "", err
		}
	}
	
	return outputPath, nil
}

// generateMarkdownReport creates a Markdown report
func (g *Generator) generateMarkdownReport(data *ReportData, config *Config) (string, error) {
	var buf bytes.Buffer
	
	// Write markdown content
	buf.WriteString(fmt.Sprintf("# Security Assessment Report\n\n"))
	buf.WriteString(fmt.Sprintf("**Target:** %s\n", data.Metadata.Target))
	buf.WriteString(fmt.Sprintf("**Generated:** %s\n", data.Metadata.GeneratedAt.Format("2006-01-02 15:04:05")))
	buf.WriteString(fmt.Sprintf("**Scan ID:** %s\n\n", data.Metadata.ScanID))
	
	// Executive Summary
	buf.WriteString("## Executive Summary\n\n")
	buf.WriteString(fmt.Sprintf("- **Overall Risk:** %s\n", data.ExecutiveSummary.OverallRisk))
	buf.WriteString(fmt.Sprintf("- **Total Issues:** %d\n", data.ExecutiveSummary.TotalIssues))
	buf.WriteString(fmt.Sprintf("- **Critical:** %d, **High:** %d, **Medium:** %d, **Low:** %d\n\n",
		data.ExecutiveSummary.CriticalIssues,
		data.ExecutiveSummary.HighIssues,
		data.ExecutiveSummary.MediumIssues,
		data.ExecutiveSummary.LowIssues))
	
	// Vulnerabilities by severity
	for severity, vulns := range data.TechnicalFindings.VulnerabilitiesBySeverity {
		if len(vulns) == 0 {
			continue
		}
		
		buf.WriteString(fmt.Sprintf("## %s Severity Issues\n\n", severity))
		for _, vuln := range vulns {
			buf.WriteString(fmt.Sprintf("### %s\n", vuln.Title))
			buf.WriteString(fmt.Sprintf("- **URL:** %s\n", vuln.URL))
			buf.WriteString(fmt.Sprintf("- **Type:** %s\n", vuln.Type))
			buf.WriteString(fmt.Sprintf("- **Confidence:** %d%%\n", vuln.Confidence))
			buf.WriteString(fmt.Sprintf("- **Description:** %s\n\n", vuln.Description))
		}
	}
	
	filename := fmt.Sprintf("security_report_%s_%s.md",
		data.Metadata.ScanID,
		time.Now().Format("20060102_150405"))
	
	outputPath := filepath.Join(config.OutputDir, filename)
	if err := os.WriteFile(outputPath, buf.Bytes(), 0644); err != nil {
		return "", fmt.Errorf("failed to write Markdown report: %w", err)
	}
	
	return outputPath, nil
}

// generateYAMLReport creates a YAML report
func (g *Generator) generateYAMLReport(data *ReportData, config *Config) (string, error) {
	yamlData, err := yaml.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("YAML marshaling failed: %w", err)
	}
	
	filename := fmt.Sprintf("security_report_%s_%s.yaml",
		data.Metadata.ScanID,
		time.Now().Format("20060102_150405"))
	
	outputPath := filepath.Join(config.OutputDir, filename)
	if err := os.WriteFile(outputPath, yamlData, 0644); err != nil {
		return "", fmt.Errorf("failed to write YAML report: %w", err)
	}
	
	return outputPath, nil
}

// generateXMLReport creates an XML report
func (g *Generator) generateXMLReport(data *ReportData, config *Config) (string, error) {
	// Basic XML structure
	var buf bytes.Buffer
	buf.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	buf.WriteString(`<security_report>` + "\n")
	buf.WriteString(fmt.Sprintf(`  <metadata scan_id="%s" target="%s" generated="%s"/>`,
		data.Metadata.ScanID,
		data.Metadata.Target,
		data.Metadata.GeneratedAt.Format(time.RFC3339)))
	buf.WriteString("\n  <vulnerabilities>\n")
	
	for _, vuln := range data.ScanResults.Vulnerabilities {
		buf.WriteString("    <vulnerability>\n")
		buf.WriteString(fmt.Sprintf("      <id>%s</id>\n", vuln.ID))
		buf.WriteString(fmt.Sprintf("      <type>%s</type>\n", vuln.Type))
		buf.WriteString(fmt.Sprintf("      <severity>%s</severity>\n", vuln.Severity))
		buf.WriteString(fmt.Sprintf("      <title><![CDATA[%s]]></title>\n", vuln.Title))
		buf.WriteString(fmt.Sprintf("      <url>%s</url>\n", vuln.URL))
		buf.WriteString(fmt.Sprintf("      <confidence>%d</confidence>\n", vuln.Confidence))
		buf.WriteString("    </vulnerability>\n")
	}
	
	buf.WriteString("  </vulnerabilities>\n")
	buf.WriteString("</security_report>\n")
	
	filename := fmt.Sprintf("security_report_%s_%s.xml",
		data.Metadata.ScanID,
		time.Now().Format("20060102_150405"))
	
	outputPath := filepath.Join(config.OutputDir, filename)
	if err := os.WriteFile(outputPath, buf.Bytes(), 0644); err != nil {
		return "", fmt.Errorf("failed to write XML report: %w", err)
	}
	
	return outputPath, nil
}

// Helper methods
func (g *Generator) loadTemplates() error {
	templateFiles := map[string]string{
		"default":     "templates/report.html",
		"executive":   "templates/executive.html",
		"technical":   "templates/technical.html",
		"hackerone":   "templates/hackerone.html",
	}
	
	for name, file := range templateFiles {
		if _, err := os.Stat(file); os.IsNotExist(err) {
			// Create default template if file doesn't exist
			g.templates[name] = g.createDefaultTemplate()
			continue
		}
		
		tmpl, err := template.ParseFiles(file)
		if err != nil {
			g.log.Warn("Failed to load template", "name", name, "error", err)
			g.templates[name] = g.createDefaultTemplate()
			continue
		}
		
		g.templates[name] = tmpl
	}
	
	return nil
}

func (g *Generator) createDefaultTemplate() *template.Template {
	// Create a basic default template
	templateContent := `<!DOCTYPE html>
<html>
<head>
    <title>Security Assessment Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { border-bottom: 2px solid #333; padding-bottom: 20px; }
        .severity-critical { color: #d73027; font-weight: bold; }
        .severity-high { color: #fc8d59; font-weight: bold; }
        .severity-medium { color: #fee08b; font-weight: bold; }
        .severity-low { color: #91bfdb; font-weight: bold; }
        .vulnerability { margin: 20px 0; padding: 15px; border-left: 4px solid #ccc; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Security Assessment Report</h1>
        <p><strong>Target:</strong> {{.Metadata.Target}}</p>
        <p><strong>Generated:</strong> {{.Metadata.GeneratedAt.Format "2006-01-02 15:04:05"}}</p>
        <p><strong>Scan ID:</strong> {{.Metadata.ScanID}}</p>
    </div>
    
    <h2>Executive Summary</h2>
    <p><strong>Total Issues:</strong> {{.ExecutiveSummary.TotalIssues}}</p>
    <p><strong>Critical:</strong> {{.ExecutiveSummary.CriticalIssues}}, 
       <strong>High:</strong> {{.ExecutiveSummary.HighIssues}}, 
       <strong>Medium:</strong> {{.ExecutiveSummary.MediumIssues}}, 
       <strong>Low:</strong> {{.ExecutiveSummary.LowIssues}}</p>
    
    <h2>Vulnerabilities</h2>
    {{range .ScanResults.Vulnerabilities}}
    <div class="vulnerability">
        <h3 class="severity-{{.Severity | lower}}">{{.Title}}</h3>
        <p><strong>Type:</strong> {{.Type}}</p>
        <p><strong>URL:</strong> {{.URL}}</p>
        <p><strong>Severity:</strong> {{.Severity}}</p>
        <p><strong>Confidence:</strong> {{.Confidence}}%</p>
        <p><strong>Description:</strong> {{.Description}}</p>
        {{if .Evidence}}<p><strong>Evidence:</strong> {{.Evidence}}</p>{{end}}
    </div>
    {{end}}
</body>
</html>`
	
	tmpl, _ := template.New("default").Funcs(template.FuncMap{
		"lower": strings.ToLower,
	}).Parse(templateContent)
	
	return tmpl
}

func (g *Generator) loadScanResults(scanID string) (*models.ScanResults, error) {
	// Implementation would load from database or file system
	// For now, return empty results
	return &models.ScanResults{
		ScanID:          scanID,
		Vulnerabilities: make([]*models.Vulnerability, 0),
	}, nil
}

func (g *Generator) filterResults(results *models.ScanResults, config *Config) *models.ScanResults {
	if len(config.Severities) == 0 && len(config.Categories) == 0 {
		return results
	}
	
	filtered := &models.ScanResults{
		ScanID:          results.ScanID,
		Target:          results.Target,
		StartTime:       results.StartTime,
		EndTime:         results.EndTime,
		Duration:        results.Duration,
		Vulnerabilities: make([]*models.Vulnerability, 0),
	}
	
	severityMap := make(map[string]bool)
	for _, sev := range config.Severities {
		severityMap[strings.ToLower(sev)] = true
	}
	
	categoryMap := make(map[string]bool)
	for _, cat := range config.Categories {
		categoryMap[strings.ToLower(cat)] = true
	}
	
	for _, vuln := range results.Vulnerabilities {
		include := true
		
		if len(severityMap) > 0 {
			if !severityMap[strings.ToLower(vuln.Severity)] {
				include = false
			}
		}
		
		if len(categoryMap) > 0 && include {
			if !categoryMap[strings.ToLower(vuln.Type)] {
				include = false
			}
		}
		
		if include {
			filtered.Vulnerabilities = append(filtered.Vulnerabilities, vuln)
		}
	}
	
	return filtered
}

func (g *Generator) prepareReportData(scanResults *models.ScanResults, config *Config) (*ReportData, error) {
	// Prepare executive summary
	execSummary := g.buildExecutiveSummary(scanResults)
	
	// Prepare technical findings
	techFindings := g.buildTechnicalFindings(scanResults)
	
	// Prepare risk matrix
	riskMatrix := g.buildRiskMatrix(scanResults)
	
	// Prepare timeline
	timeline := g.buildTimeline(scanResults)
	
	// Prepare statistics
	statistics := g.buildStatistics(scanResults)
	
	// Prepare metadata
	metadata := &ReportMetadata{
		GeneratedAt: time.Now(),
		Generator:   "BugBounty CLI Tool",
		Version:     "1.0.0",
		ScanID:      config.ScanID,
		Target:      scanResults.Target,
		Company:     config.Company,
		Pentester:   config.Pentester,
		Template:    config.Template,
		Formats:     config.Formats,
	}
	
	return &ReportData{
		ScanResults:       scanResults,
		ExecutiveSummary:  execSummary,
		TechnicalFindings: techFindings,
		RiskMatrix:        riskMatrix,
		Timeline:          timeline,
		Statistics:        statistics,
		Metadata:          metadata,
	}, nil
}

func (g *Generator) buildExecutiveSummary(results *models.ScanResults) *ExecutiveSummary {
	summary := &ExecutiveSummary{
		KeyFindings:     make([]string, 0),
		Recommendations: make([]string, 0),
	}
	
	// Count vulnerabilities by severity
	for _, vuln := range results.Vulnerabilities {
		switch strings.ToLower(vuln.Severity) {
		case "critical":
			summary.CriticalIssues++
		case "high":
			summary.HighIssues++
		case "medium":
			summary.MediumIssues++
		case "low":
			summary.LowIssues++
		case "info":
			summary.InfoIssues++
		}
	}
	
	summary.TotalIssues = len(results.Vulnerabilities)
	
	// Determine overall risk
	if summary.CriticalIssues > 0 {
		summary.OverallRisk = "Critical"
	} else if summary.HighIssues > 0 {
		summary.OverallRisk = "High"
	} else if summary.MediumIssues > 0 {
		summary.OverallRisk = "Medium"
	} else {
		summary.OverallRisk = "Low"
	}
	
	// Generate key findings
	vulnTypes := make(map[string]int)
	for _, vuln := range results.Vulnerabilities {
		vulnTypes[vuln.Type]++
	}
	
	// Sort by frequency
	type typeCount struct {
		Type  string
		Count int
	}
	var types []typeCount
	for t, c := range vulnTypes {
		types = append(types, typeCount{Type: t, Count: c})
	}
	sort.Slice(types, func(i, j int) bool {
		return types[i].Count > types[j].Count
	})
	
	// Add top 3 vulnerability types as key findings
	for i, tc := range types {
		if i >= 3 {
			break
		}
		summary.KeyFindings = append(summary.KeyFindings,
			fmt.Sprintf("%d instances of %s found", tc.Count, tc.Type))
	}
	
	// Generate recommendations
	if summary.CriticalIssues > 0 || summary.HighIssues > 0 {
		summary.Recommendations = append(summary.Recommendations,
			"Immediately address all Critical and High severity vulnerabilities")
	}
	
	if vulnTypes["Cross-Site Scripting (XSS)"] > 0 {
		summary.Recommendations = append(summary.Recommendations,
			"Implement Content Security Policy (CSP) to mitigate XSS attacks")
	}
	
	if vulnTypes["SQL Injection"] > 0 {
		summary.Recommendations = append(summary.Recommendations,
			"Use parameterized queries to prevent SQL injection")
	}
	
	return summary
}

func (g *Generator) buildTechnicalFindings(results *models.ScanResults) *TechnicalFindings {
	findings := &TechnicalFindings{
		VulnerabilitiesByCategory: make(map[string][]*models.Vulnerability),
		VulnerabilitiesBySeverity: make(map[string][]*models.Vulnerability),
		UniqueVulnTypes:          make([]string, 0),
		AffectedEndpoints:        make([]string, 0),
		TechnicalRecommendations: make([]string, 0),
	}
	
	// Group vulnerabilities
	vulnTypes := make(map[string]bool)
	endpoints := make(map[string]bool)
	
	for _, vuln := range results.Vulnerabilities {
		// By category (type)
		findings.VulnerabilitiesByCategory[vuln.Type] = append(
			findings.VulnerabilitiesByCategory[vuln.Type], vuln)
		
		// By severity
		findings.VulnerabilitiesBySeverity[vuln.Severity] = append(
			findings.VulnerabilitiesBySeverity[vuln.Severity], vuln)
		
		vulnTypes[vuln.Type] = true
		endpoints[vuln.URL] = true
	}
	
	// Convert maps to slices
	for vulnType := range vulnTypes {
		findings.UniqueVulnTypes = append(findings.UniqueVulnTypes, vulnType)
	}
	sort.Strings(findings.UniqueVulnTypes)
	
	for endpoint := range endpoints {
		findings.AffectedEndpoints = append(findings.AffectedEndpoints, endpoint)
	}
	sort.Strings(findings.AffectedEndpoints)
	
	return findings
}

func (g *Generator) buildRiskMatrix(results *models.ScanResults) *RiskMatrix {
	matrix := &RiskMatrix{
		Vulnerabilities: make([]RiskItem, 0),
		Categories:      make([]string, 0),
	}
	
	for _, vuln := range results.Vulnerabilities {
		riskItem := RiskItem{
			Title:    vuln.Title,
			Severity: vuln.Severity,
			Category: vuln.Type,
		}
		
		// Calculate likelihood and impact scores
		riskItem.Likelihood = g.calculateLikelihood(vuln)
		riskItem.Impact = g.calculateImpact(vuln)
		riskItem.RiskScore = riskItem.Likelihood * riskItem.Impact
		
		if riskItem.RiskScore > matrix.MaxRisk {
			matrix.MaxRisk = riskItem.RiskScore
		}
		
		matrix.Vulnerabilities = append(matrix.Vulnerabilities, riskItem)
	}
	
	return matrix
}

func (g *Generator) buildTimeline(results *models.ScanResults) *Timeline {
	timeline := &Timeline{
		Events: make([]TimelineEvent, 0),
	}
	
	// Add scan start event
	timeline.Events = append(timeline.Events, TimelineEvent{
		Timestamp:   results.StartTime,
		Type:        "scan_start",
		Description: "Security scan initiated",
	})
	
	// Add vulnerability discovery events
	for _, vuln := range results.Vulnerabilities {
		timeline.Events = append(timeline.Events, TimelineEvent{
			Timestamp:   vuln.Timestamp,
			Type:        "vulnerability_found",
			Description: fmt.Sprintf("%s vulnerability discovered", vuln.Type),
			Details: map[string]interface{}{
				"severity": vuln.Severity,
				"url":      vuln.URL,
			},
		})
	}
	
	// Add scan end event
	timeline.Events = append(timeline.Events, TimelineEvent{
		Timestamp:   results.EndTime,
		Type:        "scan_complete",
		Description: "Security scan completed",
	})
	
	// Sort events by timestamp
	sort.Slice(timeline.Events, func(i, j int) bool {
		return timeline.Events[i].Timestamp.Before(timeline.Events[j].Timestamp)
	})
	
	return timeline
}

func (g *Generator) buildStatistics(results *models.ScanResults) *Statistics {
	stats := &Statistics{
		ScanDuration:         results.Duration,
		TargetsScanned:       1,
		EndpointsDiscovered:  len(results.Endpoints),
		VulnerabilitiesFound: len(results.Vulnerabilities),
		SeverityDistribution: make(map[string]int),
		TopVulnTypes:         make([]VulnTypeStat, 0),
	}
	
	// Count by severity
	vulnTypes := make(map[string]int)
	for _, vuln := range results.Vulnerabilities {
		stats.SeverityDistribution[vuln.Severity]++
		vulnTypes[vuln.Type]++
	}
	
	// Convert to sorted slice
	type typeCount struct {
		Type  string
		Count int
	}
	var types []typeCount
	for t, c := range vulnTypes {
		types = append(types, typeCount{Type: t, Count: c})
	}
	sort.Slice(types, func(i, j int) bool {
		return types[i].Count > types[j].Count
	})
	
	// Take top 5
	for i, tc := range types {
		if i >= 5 {
			break
		}
		stats.TopVulnTypes = append(stats.TopVulnTypes, VulnTypeStat{
			Type:  tc.Type,
			Count: tc.Count,
		})
	}
	
	return stats
}

func (g *Generator) calculateLikelihood(vuln *models.Vulnerability) int {
	// Simple likelihood calculation based on confidence and vulnerability type
	base := vuln.Confidence / 20 // 0-5 scale
	
	// Adjust based on vulnerability type
	switch vuln.Type {
	case "Remote Code Execution":
		return min(base+2, 5)
	case "SQL Injection":
		return min(base+1, 5)
	case "Cross-Site Scripting (XSS)":
		return min(base+1, 5)
	default:
		return base
	}
}

func (g *Generator) calculateImpact(vuln *models.Vulnerability) int {
	// Simple impact calculation based on severity
	switch strings.ToLower(vuln.Severity) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	default:
		return 2
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
