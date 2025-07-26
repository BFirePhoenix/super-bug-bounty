package ai

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/bugbounty-tool/internal/config"
	"github.com/bugbounty-tool/internal/logger"
	"github.com/bugbounty-tool/pkg/models"
)

// PayloadGenerator provides AI-powered custom payload generation
type PayloadGenerator struct {
	config *config.Config
	log    logger.Logger
}

// PayloadRequest contains parameters for payload generation
type PayloadRequest struct {
	VulnerabilityType string            `json:"vulnerability_type"`
	Context           string            `json:"context"`
	Target            *models.Target    `json:"target"`
	Constraints       map[string]string `json:"constraints"`
	ExistingPayloads  []string          `json:"existing_payloads"`
	CustomParams      map[string]string `json:"custom_params"`
}

// PayloadResponse contains generated payloads and metadata
type PayloadResponse struct {
	Payloads    []GeneratedPayload `json:"payloads"`
	Success     bool               `json:"success"`
	Message     string             `json:"message"`
	Confidence  float64            `json:"confidence"`
	Techniques  []string           `json:"techniques"`
}

// GeneratedPayload represents a single generated payload
type GeneratedPayload struct {
	Payload      string            `json:"payload"`
	Type         string            `json:"type"`
	Description  string            `json:"description"`
	Context      string            `json:"context"`
	Encoding     string            `json:"encoding"`
	Confidence   float64           `json:"confidence"`
	Tags         []string          `json:"tags"`
	Metadata     map[string]string `json:"metadata"`
}

// NewPayloadGenerator creates a new AI payload generator
func NewPayloadGenerator(cfg *config.Config, log logger.Logger) *PayloadGenerator {
	return &PayloadGenerator{
		config: cfg,
		log:    log,
	}
}

// GeneratePayloads creates custom payloads for specific vulnerabilities
func (pg *PayloadGenerator) GeneratePayloads(request *PayloadRequest) (*PayloadResponse, error) {
	pg.log.Info("Generating AI-powered payloads", 
		"type", request.VulnerabilityType,
		"context", request.Context)
	
	// Serialize request to JSON
	requestJSON, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize request: %w", err)
	}
	
	// Call Python AI script for payload generation
	cmd := exec.Command("python3", "scripts/ai/payload_generator.py",
		"--request", string(requestJSON))
	
	output, err := cmd.Output()
	if err != nil {
		pg.log.Error("AI payload generation failed", "error", err)
		return pg.getFallbackPayloads(request), nil
	}
	
	// Parse AI response
	var response PayloadResponse
	if err := json.Unmarshal(output, &response); err != nil {
		pg.log.Error("Failed to parse AI response", "error", err)
		return pg.getFallbackPayloads(request), nil
	}
	
	// Post-process payloads
	response.Payloads = pg.postProcessPayloads(response.Payloads, request)
	
	pg.log.Info("Payload generation completed",
		"type", request.VulnerabilityType,
		"payloads_generated", len(response.Payloads),
		"confidence", response.Confidence)
	
	return &response, nil
}

// GenerateXSSPayloads creates XSS-specific payloads
func (pg *PayloadGenerator) GenerateXSSPayloads(target *models.Target, context string) ([]GeneratedPayload, error) {
	request := &PayloadRequest{
		VulnerabilityType: "XSS",
		Context:           context,
		Target:            target,
		Constraints: map[string]string{
			"max_length": "200",
			"encoding":   "url",
		},
	}
	
	response, err := pg.GeneratePayloads(request)
	if err != nil {
		return nil, err
	}
	
	return response.Payloads, nil
}

// GenerateSQLiPayloads creates SQL injection-specific payloads
func (pg *PayloadGenerator) GenerateSQLiPayloads(target *models.Target, dbType string) ([]GeneratedPayload, error) {
	request := &PayloadRequest{
		VulnerabilityType: "SQLi",
		Context:           "database",
		Target:            target,
		CustomParams: map[string]string{
			"database_type": dbType,
			"injection_point": "parameter",
		},
	}
	
	response, err := pg.GeneratePayloads(request)
	if err != nil {
		return nil, err
	}
	
	return response.Payloads, nil
}

// GenerateRCEPayloads creates RCE-specific payloads
func (pg *PayloadGenerator) GenerateRCEPayloads(target *models.Target, platform string) ([]GeneratedPayload, error) {
	request := &PayloadRequest{
		VulnerabilityType: "RCE",
		Context:           "command",
		Target:            target,
		CustomParams: map[string]string{
			"platform": platform,
			"safe_mode": "true", // Only generate safe payloads
		},
	}
	
	response, err := pg.GeneratePayloads(request)
	if err != nil {
		return nil, err
	}
	
	return response.Payloads, nil
}

// GenerateCustomPayload creates a single custom payload based on specific requirements
func (pg *PayloadGenerator) GenerateCustomPayload(vulnType, context string, constraints map[string]string) (*GeneratedPayload, error) {
	request := &PayloadRequest{
		VulnerabilityType: vulnType,
		Context:           context,
		Constraints:       constraints,
	}
	
	response, err := pg.GeneratePayloads(request)
	if err != nil {
		return nil, err
	}
	
	if len(response.Payloads) == 0 {
		return nil, fmt.Errorf("no payloads generated")
	}
	
	return &response.Payloads[0], nil
}

// OptimizePayload uses AI to optimize an existing payload
func (pg *PayloadGenerator) OptimizePayload(originalPayload, targetContext string) (string, error) {
	cmd := exec.Command("python3", "scripts/ai/payload_generator.py",
		"--action", "optimize",
		"--payload", originalPayload,
		"--context", targetContext)
	
	output, err := cmd.Output()
	if err != nil {
		pg.log.Error("Payload optimization failed", "error", err)
		return originalPayload, err
	}
	
	var response struct {
		OptimizedPayload string  `json:"optimized_payload"`
		Confidence       float64 `json:"confidence"`
		Improvements     []string `json:"improvements"`
	}
	
	if err := json.Unmarshal(output, &response); err != nil {
		return originalPayload, err
	}
	
	if response.Confidence > 0.7 {
		pg.log.Info("Payload optimized",
			"original", originalPayload,
			"optimized", response.OptimizedPayload,
			"confidence", response.Confidence)
		return response.OptimizedPayload, nil
	}
	
	return originalPayload, nil
}

// EncodePayload applies various encoding techniques to a payload
func (pg *PayloadGenerator) EncodePayload(payload, encoding string) ([]string, error) {
	cmd := exec.Command("python3", "scripts/ai/payload_generator.py",
		"--action", "encode",
		"--payload", payload,
		"--encoding", encoding)
	
	output, err := cmd.Output()
	if err != nil {
		return []string{payload}, err
	}
	
	var response struct {
		EncodedPayloads []string `json:"encoded_payloads"`
	}
	
	if err := json.Unmarshal(output, &response); err != nil {
		return []string{payload}, err
	}
	
	return response.EncodedPayloads, nil
}

// BypassFilter generates payloads designed to bypass specific security filters
func (pg *PayloadGenerator) BypassFilter(originalPayload, filterType string) ([]GeneratedPayload, error) {
	request := &PayloadRequest{
		VulnerabilityType: "bypass",
		Context:           filterType,
		ExistingPayloads:  []string{originalPayload},
		CustomParams: map[string]string{
			"filter_type": filterType,
			"bypass_mode": "true",
		},
	}
	
	response, err := pg.GeneratePayloads(request)
	if err != nil {
		return nil, err
	}
	
	return response.Payloads, nil
}

// postProcessPayloads applies post-processing to generated payloads
func (pg *PayloadGenerator) postProcessPayloads(payloads []GeneratedPayload, request *PayloadRequest) []GeneratedPayload {
	processed := make([]GeneratedPayload, 0, len(payloads))
	
	for _, payload := range payloads {
		// Apply length constraints
		if maxLen, exists := request.Constraints["max_length"]; exists {
			if len(payload.Payload) > pg.parseInt(maxLen, 1000) {
				continue
			}
		}
		
		// Apply encoding if requested
		if encoding, exists := request.Constraints["encoding"]; exists {
			encoded, err := pg.applyEncoding(payload.Payload, encoding)
			if err == nil {
				payload.Payload = encoded
				payload.Encoding = encoding
			}
		}
		
		// Add safety tags for dangerous payloads
		if pg.isDangerousPayload(payload.Payload) {
			payload.Tags = append(payload.Tags, "dangerous", "manual_verification_required")
		}
		
		// Set context-specific metadata
		payload.Metadata = pg.buildPayloadMetadata(payload, request)
		
		processed = append(processed, payload)
	}
	
	return processed
}

// getFallbackPayloads returns basic payloads when AI generation fails
func (pg *PayloadGenerator) getFallbackPayloads(request *PayloadRequest) *PayloadResponse {
	var payloads []GeneratedPayload
	
	switch strings.ToLower(request.VulnerabilityType) {
	case "xss":
		payloads = []GeneratedPayload{
			{
				Payload:     "<script>alert('XSS')</script>",
				Type:        "XSS",
				Description: "Basic script injection",
				Context:     "HTML",
				Confidence:  0.8,
				Tags:        []string{"basic", "fallback"},
			},
			{
				Payload:     "javascript:alert('XSS')",
				Type:        "XSS",
				Description: "JavaScript URI injection",
				Context:     "href",
				Confidence:  0.7,
				Tags:        []string{"uri", "fallback"},
			},
		}
	case "sqli":
		payloads = []GeneratedPayload{
			{
				Payload:     "' OR '1'='1",
				Type:        "SQLi",
				Description: "Basic boolean injection",
				Context:     "string",
				Confidence:  0.8,
				Tags:        []string{"boolean", "fallback"},
			},
			{
				Payload:     "1' UNION SELECT 1,2,3--",
				Type:        "SQLi",
				Description: "Union-based injection",
				Context:     "numeric",
				Confidence:  0.7,
				Tags:        []string{"union", "fallback"},
			},
		}
	case "rce":
		payloads = []GeneratedPayload{
			{
				Payload:     "; echo 'RCE_TEST'",
				Type:        "RCE",
				Description: "Command separator injection",
				Context:     "command",
				Confidence:  0.8,
				Tags:        []string{"safe", "fallback"},
			},
		}
	default:
		payloads = []GeneratedPayload{
			{
				Payload:     "test",
				Type:        "generic",
				Description: "Basic test payload",
				Context:     "generic",
				Confidence:  0.5,
				Tags:        []string{"fallback"},
			},
		}
	}
	
	return &PayloadResponse{
		Payloads:   payloads,
		Success:    true,
		Message:    "Fallback payloads provided",
		Confidence: 0.6,
		Techniques: []string{"fallback"},
	}
}

// Helper methods
func (pg *PayloadGenerator) parseInt(s string, defaultVal int) int {
	// Simple integer parsing with default
	if s == "" {
		return defaultVal
	}
	// Add proper parsing logic here
	return defaultVal
}

func (pg *PayloadGenerator) applyEncoding(payload, encoding string) (string, error) {
	switch strings.ToLower(encoding) {
	case "url":
		return strings.ReplaceAll(strings.ReplaceAll(payload, " ", "%20"), "<", "%3C"), nil
	case "html":
		return strings.ReplaceAll(strings.ReplaceAll(payload, "<", "&lt;"), ">", "&gt;"), nil
	case "base64":
		// Add base64 encoding
		return payload, nil
	default:
		return payload, nil
	}
}

func (pg *PayloadGenerator) isDangerousPayload(payload string) bool {
	dangerousPatterns := []string{
		"rm -rf", "format c:", "del /f", "shutdown", "reboot",
		"wget", "curl http", "nc ", "bash -i",
	}
	
	payloadLower := strings.ToLower(payload)
	for _, pattern := range dangerousPatterns {
		if strings.Contains(payloadLower, pattern) {
			return true
		}
	}
	
	return false
}

func (pg *PayloadGenerator) buildPayloadMetadata(payload GeneratedPayload, request *PayloadRequest) map[string]string {
	metadata := make(map[string]string)
	
	metadata["generated_at"] = fmt.Sprintf("%d", getCurrentTimestamp())
	metadata["target_type"] = request.VulnerabilityType
	metadata["context"] = request.Context
	
	if request.Target != nil {
		metadata["target_url"] = request.Target.URL
	}
	
	if payload.Confidence > 0.8 {
		metadata["quality"] = "high"
	} else if payload.Confidence > 0.6 {
		metadata["quality"] = "medium"
	} else {
		metadata["quality"] = "low"
	}
	
	return metadata
}

func getCurrentTimestamp() int64 {
	return 1234567890 // Placeholder
}
