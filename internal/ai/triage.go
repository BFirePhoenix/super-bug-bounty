package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/bugbounty-tool/internal/config"
	"github.com/bugbounty-tool/internal/logger"
	"github.com/bugbounty-tool/pkg/models"
)

// TriageEngine provides AI-powered vulnerability triage and analysis
type TriageEngine struct {
	config *config.Config
	log    logger.Logger
}

// TriageConfig contains configuration for AI triage operations
type TriageConfig struct {
	ScanID               string
	AutoVerify           bool
	GeneratePayloads     bool
	FilterFalsePositives bool
	BusinessImpact       bool
	ConfidenceThreshold  float64
	Models               []string
	Interactive          bool
	TrainingData         string
	Learn                bool
}

// TriageResults contains the results of AI-powered triage
type TriageResults struct {
	TotalProcessed       int
	VerifiedCount        int
	FalsePositiveCount   int
	HighPriorityCount    int
	ProcessingTime       time.Duration
	Reclassifications    []VulnReclassification
	GeneratedPayloads    map[string]int
	Recommendations      []string
	Insights             []string
}

// VulnReclassification represents a vulnerability that was reclassified by AI
type VulnReclassification struct {
	VulnID           string
	OriginalSeverity string
	NewSeverity      string
	Confidence       float64
	Reasoning        string
}

// NewTriageEngine creates a new AI triage engine
func NewTriageEngine(cfg *config.Config, log logger.Logger) (*TriageEngine, error) {
	return &TriageEngine{
		config: cfg,
		log:    log,
	}, nil
}

// Triage performs AI-powered vulnerability triage
func (te *TriageEngine) Triage(config *TriageConfig) (*TriageResults, error) {
	te.log.Info("Starting AI-powered vulnerability triage", "scan_id", config.ScanID)
	
	startTime := time.Now()
	results := &TriageResults{
		Reclassifications: make([]VulnReclassification, 0),
		GeneratedPayloads: make(map[string]int),
		Recommendations:   make([]string, 0),
		Insights:          make([]string, 0),
	}
	
	// Load scan results
	scanResults, err := te.loadScanResults(config.ScanID)
	if err != nil {
		return nil, fmt.Errorf("failed to load scan results: %w", err)
	}
	
	results.TotalProcessed = len(scanResults.Vulnerabilities)
	
	// Process each vulnerability through AI triage
	for _, vuln := range scanResults.Vulnerabilities {
		// Severity classification
		if contains(config.Models, "severity") {
			newSeverity, confidence := te.classifySeverity(vuln)
			if confidence >= config.ConfidenceThreshold && newSeverity != vuln.Severity {
				reclassification := VulnReclassification{
					VulnID:           vuln.ID,
					OriginalSeverity: vuln.Severity,
					NewSeverity:      newSeverity,
					Confidence:       confidence,
					Reasoning:        te.generateReclassificationReasoning(vuln, newSeverity),
				}
				results.Reclassifications = append(results.Reclassifications, reclassification)
				
				// Update severity
				vuln.Severity = newSeverity
				vuln.Risk = newSeverity
			}
		}
		
		// False positive detection
		if config.FilterFalsePositives {
			isFalsePositive, confidence := te.detectFalsePositive(vuln)
			if isFalsePositive && confidence >= config.ConfidenceThreshold {
				results.FalsePositiveCount++
				vuln.Confidence = int(confidence * 100)
				continue
			}
		}
		
		// Verification
		if config.AutoVerify {
			verified := te.autoVerifyVulnerability(vuln)
			if verified {
				results.VerifiedCount++
			}
		}
		
		// Payload generation
		if config.GeneratePayloads {
			payloads := te.generateCustomPayloads(vuln)
			if len(payloads) > 0 {
				results.GeneratedPayloads[vuln.Type] += len(payloads)
			}
		}
		
		// Business impact assessment
		if config.BusinessImpact {
			impact := te.assessBusinessImpact(vuln)
			vuln.Impact = impact
		}
		
		// Priority scoring
		if te.isHighPriority(vuln) {
			results.HighPriorityCount++
		}
	}
	
	// Generate insights and recommendations
	results.Insights = te.generateInsights(scanResults)
	results.Recommendations = te.generateRecommendations(scanResults, results)
	
	// Save updated results
	if err := te.saveScanResults(config.ScanID, scanResults); err != nil {
		te.log.Error("Failed to save updated scan results", "error", err)
	}
	
	results.ProcessingTime = time.Since(startTime)
	
	te.log.Info("AI triage completed",
		"scan_id", config.ScanID,
		"vulnerabilities_processed", results.TotalProcessed,
		"reclassifications", len(results.Reclassifications),
		"false_positives", results.FalsePositiveCount,
		"processing_time", results.ProcessingTime)
	
	return results, nil
}

// classifySeverity uses AI to classify vulnerability severity
func (te *TriageEngine) classifySeverity(vuln *models.Vulnerability) (string, float64) {
	// Call Python AI script for severity classification
	cmd := exec.Command("python3", "scripts/ai/triage_engine.py", 
		"--action", "classify_severity",
		"--vulnerability", te.serializeVulnerability(vuln))
	
	output, err := cmd.Output()
	if err != nil {
		te.log.Error("AI severity classification failed", "error", err)
		return vuln.Severity, 0.5
	}
	
	// Parse AI response
	var response struct {
		Severity   string  `json:"severity"`
		Confidence float64 `json:"confidence"`
	}
	
	if err := json.Unmarshal(output, &response); err != nil {
		te.log.Error("Failed to parse AI response", "error", err)
		return vuln.Severity, 0.5
	}
	
	return response.Severity, response.Confidence
}

// detectFalsePositive uses AI to detect false positive vulnerabilities
func (te *TriageEngine) detectFalsePositive(vuln *models.Vulnerability) (bool, float64) {
	cmd := exec.Command("python3", "scripts/ai/false_positive_filter.py",
		"--vulnerability", te.serializeVulnerability(vuln))
	
	output, err := cmd.Output()
	if err != nil {
		te.log.Error("AI false positive detection failed", "error", err)
		return false, 0.5
	}
	
	var response struct {
		IsFalsePositive bool    `json:"is_false_positive"`
		Confidence      float64 `json:"confidence"`
		Reasoning       string  `json:"reasoning"`
	}
	
	if err := json.Unmarshal(output, &response); err != nil {
		te.log.Error("Failed to parse AI response", "error", err)
		return false, 0.5
	}
	
	return response.IsFalsePositive, response.Confidence
}

// autoVerifyVulnerability attempts to automatically verify a vulnerability
func (te *TriageEngine) autoVerifyVulnerability(vuln *models.Vulnerability) bool {
	// Implementation depends on vulnerability type
	switch vuln.Type {
	case "Cross-Site Scripting (XSS)":
		return te.verifyXSS(vuln)
	case "SQL Injection":
		return te.verifySQLi(vuln)
	case "Remote Code Execution":
		return te.verifyRCE(vuln)
	default:
		return false
	}
}

// generateCustomPayloads creates custom payloads for a vulnerability
func (te *TriageEngine) generateCustomPayloads(vuln *models.Vulnerability) []string {
	cmd := exec.Command("python3", "scripts/ai/payload_generator.py",
		"--vulnerability_type", vuln.Type,
		"--context", te.getVulnerabilityContext(vuln))
	
	output, err := cmd.Output()
	if err != nil {
		te.log.Error("AI payload generation failed", "error", err)
		return []string{}
	}
	
	var response struct {
		Payloads []string `json:"payloads"`
	}
	
	if err := json.Unmarshal(output, &response); err != nil {
		te.log.Error("Failed to parse payload generation response", "error", err)
		return []string{}
	}
	
	return response.Payloads
}

// assessBusinessImpact evaluates the business impact of a vulnerability
func (te *TriageEngine) assessBusinessImpact(vuln *models.Vulnerability) string {
	// Use AI to assess business impact based on:
	// - Vulnerability type and severity
	// - Affected URL/endpoint
	// - Data sensitivity
	// - Business criticality
	
	factors := map[string]interface{}{
		"type":         vuln.Type,
		"severity":     vuln.Severity,
		"url":          vuln.URL,
		"parameter":    vuln.Parameter,
		"method":       vuln.Method,
		"confidence":   vuln.Confidence,
	}
	
	factorsJSON, _ := json.Marshal(factors)
	
	cmd := exec.Command("python3", "scripts/ai/triage_engine.py",
		"--action", "assess_business_impact",
		"--factors", string(factorsJSON))
	
	output, err := cmd.Output()
	if err != nil {
		te.log.Error("Business impact assessment failed", "error", err)
		return vuln.Impact
	}
	
	var response struct {
		Impact string `json:"impact"`
	}
	
	if err := json.Unmarshal(output, &response); err != nil {
		return vuln.Impact
	}
	
	return response.Impact
}

// generateInsights creates AI-powered insights about the scan results
func (te *TriageEngine) generateInsights(scanResults *models.ScanResults) []string {
	insights := make([]string, 0)
	
	// Vulnerability distribution analysis
	vulnTypes := make(map[string]int)
	severities := make(map[string]int)
	
	for _, vuln := range scanResults.Vulnerabilities {
		vulnTypes[vuln.Type]++
		severities[vuln.Severity]++
	}
	
	// Most common vulnerability type
	var mostCommonType string
	var maxCount int
	for vulnType, count := range vulnTypes {
		if count > maxCount {
			mostCommonType = vulnType
			maxCount = count
		}
	}
	
	if mostCommonType != "" {
		insights = append(insights, fmt.Sprintf("Most common vulnerability type: %s (%d occurrences)", mostCommonType, maxCount))
	}
	
	// Critical/High severity analysis
	criticalHigh := severities["Critical"] + severities["High"]
	total := len(scanResults.Vulnerabilities)
	if total > 0 {
		percentage := float64(criticalHigh) / float64(total) * 100
		insights = append(insights, fmt.Sprintf("%.1f%% of vulnerabilities are Critical or High severity", percentage))
	}
	
	// Attack surface analysis
	uniqueEndpoints := make(map[string]bool)
	for _, vuln := range scanResults.Vulnerabilities {
		uniqueEndpoints[vuln.URL] = true
	}
	insights = append(insights, fmt.Sprintf("Vulnerabilities found across %d unique endpoints", len(uniqueEndpoints)))
	
	return insights
}

// generateRecommendations creates AI-powered remediation recommendations
func (te *TriageEngine) generateRecommendations(scanResults *models.ScanResults, triageResults *TriageResults) []string {
	recommendations := make([]string, 0)
	
	// Priority recommendations based on findings
	if triageResults.HighPriorityCount > 0 {
		recommendations = append(recommendations, 
			fmt.Sprintf("Immediately address %d high-priority vulnerabilities", triageResults.HighPriorityCount))
	}
	
	if triageResults.FalsePositiveCount > 0 {
		percentage := float64(triageResults.FalsePositiveCount) / float64(triageResults.TotalProcessed) * 100
		recommendations = append(recommendations,
			fmt.Sprintf("Review and exclude %.1f%% of findings identified as likely false positives", percentage))
	}
	
	// Technology-specific recommendations
	vulnTypes := make(map[string]int)
	for _, vuln := range scanResults.Vulnerabilities {
		vulnTypes[vuln.Type]++
	}
	
	if vulnTypes["Cross-Site Scripting (XSS)"] > 0 {
		recommendations = append(recommendations, "Implement Content Security Policy (CSP) to mitigate XSS attacks")
	}
	
	if vulnTypes["SQL Injection"] > 0 {
		recommendations = append(recommendations, "Use parameterized queries and prepared statements to prevent SQL injection")
	}
	
	if vulnTypes["Remote Code Execution"] > 0 {
		recommendations = append(recommendations, "Implement input validation and sandboxing to prevent code execution")
	}
	
	return recommendations
}

// Helper methods
func (te *TriageEngine) verifyXSS(vuln *models.Vulnerability) bool {
	// Implement XSS verification logic
	return strings.Contains(vuln.Evidence, "alert") || strings.Contains(vuln.Evidence, "script")
}

func (te *TriageEngine) verifySQLi(vuln *models.Vulnerability) bool {
	// Implement SQL injection verification logic
	return strings.Contains(vuln.Evidence, "SQL") || strings.Contains(vuln.Evidence, "mysql") || strings.Contains(vuln.Evidence, "error")
}

func (te *TriageEngine) verifyRCE(vuln *models.Vulnerability) bool {
	// Implement RCE verification logic
	return strings.Contains(vuln.Evidence, "uid=") || strings.Contains(vuln.Evidence, "root:")
}

func (te *TriageEngine) isHighPriority(vuln *models.Vulnerability) bool {
	// Determine if vulnerability is high priority based on multiple factors
	return (vuln.Severity == "Critical" || vuln.Severity == "High") && vuln.Confidence >= 80
}

func (te *TriageEngine) serializeVulnerability(vuln *models.Vulnerability) string {
	data, _ := json.Marshal(vuln)
	return string(data)
}

func (te *TriageEngine) getVulnerabilityContext(vuln *models.Vulnerability) string {
	context := fmt.Sprintf("type:%s,severity:%s,url:%s", vuln.Type, vuln.Severity, vuln.URL)
	if vuln.Parameter != "" {
		context += fmt.Sprintf(",parameter:%s", vuln.Parameter)
	}
	return context
}

func (te *TriageEngine) generateReclassificationReasoning(vuln *models.Vulnerability, newSeverity string) string {
	return fmt.Sprintf("AI analysis suggests %s severity based on vulnerability characteristics, exploit complexity, and potential impact", newSeverity)
}

func (te *TriageEngine) loadScanResults(scanID string) (*models.ScanResults, error) {
	// Implementation to load scan results from storage
	// This would typically involve database or file system access
	return &models.ScanResults{
		ScanID:          scanID,
		Vulnerabilities: make([]*models.Vulnerability, 0),
	}, nil
}

func (te *TriageEngine) saveScanResults(scanID string, results *models.ScanResults) error {
	// Implementation to save updated scan results
	te.log.Debug("Saving updated scan results", "scan_id", scanID)
	return nil
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
