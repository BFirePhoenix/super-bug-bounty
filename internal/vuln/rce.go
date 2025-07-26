package vuln

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/bugbounty-tool/internal/config"
	"github.com/bugbounty-tool/internal/logger"
	"github.com/bugbounty-tool/pkg/models"
	"github.com/bugbounty-tool/pkg/utils"
)

// RCEScanner detects Remote Code Execution vulnerabilities
type RCEScanner struct {
	config   *config.Config
	log      logger.Logger
	client   *http.Client
	payloads []RCEPayload
}

type RCEPayload struct {
	Payload     string
	Type        string // command, eval, template, deserialization
	Platform    string // linux, windows, all
	Context     string // parameter, header, file
	Description string
	Dangerous   bool   // whether this payload is safe to test
	Verification string // what to look for in response
}

// NewRCEScanner creates a new RCE vulnerability scanner
func NewRCEScanner(cfg *config.Config, log logger.Logger) *RCEScanner {
	return &RCEScanner{
		config:   cfg,
		log:      log,
		client:   utils.NewHTTPClient(cfg),
		payloads: loadRCEPayloads(),
	}
}

// ScanForRCE performs comprehensive RCE vulnerability scanning
func (rs *RCEScanner) ScanForRCE(ctx context.Context, target *models.Target, config *models.ScanConfig) ([]*models.Vulnerability, error) {
	rs.log.Info("Starting RCE vulnerability scan", "target", target.URL)
	
	vulnerabilities := make([]*models.Vulnerability, 0)
	
	// Scan different RCE contexts
	contexts := []string{"command", "eval", "template", "deserialization"}
	
	for _, context := range contexts {
		switch context {
		case "command":
			vulns, err := rs.scanCommandInjection(ctx, target, config)
			if err != nil {
				rs.log.Error("Command injection scan failed", "error", err)
				continue
			}
			vulnerabilities = append(vulnerabilities, vulns...)
			
		case "eval":
			vulns, err := rs.scanCodeEvaluation(ctx, target, config)
			if err != nil {
				rs.log.Error("Code evaluation scan failed", "error", err)
				continue
			}
			vulnerabilities = append(vulnerabilities, vulns...)
			
		case "template":
			vulns, err := rs.scanTemplateInjection(ctx, target, config)
			if err != nil {
				rs.log.Error("Template injection scan failed", "error", err)
				continue
			}
			vulnerabilities = append(vulnerabilities, vulns...)
			
		case "deserialization":
			vulns, err := rs.scanDeserialization(ctx, target, config)
			if err != nil {
				rs.log.Error("Deserialization scan failed", "error", err)
				continue
			}
			vulnerabilities = append(vulnerabilities, vulns...)
		}
	}
	
	rs.log.Info("RCE scan completed",
		"target", target.URL,
		"vulnerabilities_found", len(vulnerabilities))
	
	return vulnerabilities, nil
}

func (rs *RCEScanner) scanCommandInjection(ctx context.Context, target *models.Target, config *models.ScanConfig) ([]*models.Vulnerability, error) {
	vulnerabilities := make([]*models.Vulnerability, 0)
	
	// Test parameters
	if len(target.Parameters) > 0 {
		vulns, err := rs.testCommandInjectionInParameters(ctx, target, config)
		if err != nil {
			return nil, err
		}
		vulnerabilities = append(vulnerabilities, vulns...)
	}
	
	// Test forms
	if len(target.Forms) > 0 {
		vulns, err := rs.testCommandInjectionInForms(ctx, target, config)
		if err != nil {
			return nil, err
		}
		vulnerabilities = append(vulnerabilities, vulns...)
	}
	
	// Test headers
	vulns, err := rs.testCommandInjectionInHeaders(ctx, target, config)
	if err != nil {
		return nil, err
	}
	vulnerabilities = append(vulnerabilities, vulns...)
	
	return vulnerabilities, nil
}

func (rs *RCEScanner) testCommandInjectionInParameters(ctx context.Context, target *models.Target, config *models.ScanConfig) ([]*models.Vulnerability, error) {
	vulnerabilities := make([]*models.Vulnerability, 0)
	
	parsedURL, err := url.Parse(target.URL)
	if err != nil {
		return nil, err
	}
	
	originalParams := parsedURL.Query()
	
	for paramName := range originalParams {
		for _, payload := range rs.payloads {
			if payload.Type != "command" || payload.Dangerous {
				continue // Skip dangerous payloads in automated testing
			}
			
			// Create test URL with payload
			testParams := make(url.Values)
			for k, v := range originalParams {
				testParams[k] = v
			}
			testParams.Set(paramName, payload.Payload)
			
			parsedURL.RawQuery = testParams.Encode()
			testURL := parsedURL.String()
			
			// Make request
			req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
			if err != nil {
				continue
			}
			
			req.Header.Set("User-Agent", config.UserAgent)
			if config.Headers != nil {
				for k, v := range config.Headers {
					req.Header.Set(k, v)
				}
			}
			
			resp, err := rs.client.Do(req)
			if err != nil {
				continue
			}
			
			// Read response
			body := make([]byte, rs.config.Scanning.MaxBodySize)
			n, _ := resp.Body.Read(body)
			resp.Body.Close()
			
			responseBody := string(body[:n])
			
			// Check for command execution indicators
			if rs.isRCEVulnerable(payload, responseBody, resp) {
				vuln := &models.Vulnerability{
					ID:          fmt.Sprintf("rce-cmd-%s-%d", paramName, time.Now().Unix()),
					Type:        "Remote Code Execution (Command Injection)",
					Severity:    "Critical",
					Title:       fmt.Sprintf("Command injection in parameter '%s'", paramName),
					Description: fmt.Sprintf("The parameter '%s' is vulnerable to command injection attacks. User input is executed as system commands.", paramName),
					URL:         testURL,
					Parameter:   paramName,
					Payload:     payload.Payload,
					Method:      "GET",
					Evidence:    rs.extractRCEEvidence(payload, responseBody),
					Impact:      "An attacker can execute arbitrary system commands on the server, potentially leading to complete system compromise.",
					Remediation: "Avoid executing user input as system commands. Use parameterized APIs and input validation. Implement proper sandboxing.",
					References: []string{
						"https://owasp.org/www-community/attacks/Command_Injection",
						"https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
					},
					Risk:        "Critical",
					Confidence:  rs.calculateRCEConfidence(payload, responseBody),
					Timestamp:   time.Now(),
				}
				
				vuln.ProofOfConcept = rs.generateRCEPoC(testURL, paramName, payload.Payload, "GET")
				vulnerabilities = append(vulnerabilities, vuln)
				
				rs.log.Info("Command injection vulnerability found",
					"url", testURL,
					"parameter", paramName,
					"payload", payload.Payload)
				
				break
			}
		}
	}
	
	return vulnerabilities, nil
}

func (rs *RCEScanner) testCommandInjectionInForms(ctx context.Context, target *models.Target, config *models.ScanConfig) ([]*models.Vulnerability, error) {
	vulnerabilities := make([]*models.Vulnerability, 0)
	
	for _, form := range target.Forms {
		// Skip authentication forms
		if rs.isAuthenticationForm(form) {
			continue
		}
		
		for _, input := range form.Inputs {
			if input.Type == "submit" || input.Type == "button" || input.Type == "hidden" {
				continue
			}
			
			for _, payload := range rs.payloads {
				if payload.Type != "command" || payload.Dangerous {
					continue
				}
				
				// Build form data
				formData := url.Values{}
				for _, formInput := range form.Inputs {
					if formInput.Name == input.Name {
						formData.Set(formInput.Name, payload.Payload)
					} else if formInput.Value != "" {
						formData.Set(formInput.Name, formInput.Value)
					} else {
						formData.Set(formInput.Name, "test")
					}
				}
				
				// Determine form action URL
				actionURL := form.Action
				if actionURL == "" {
					actionURL = target.URL
				}
				
				// Make request
				var req *http.Request
				var err error
				
				if strings.ToUpper(form.Method) == "POST" {
					req, err = http.NewRequestWithContext(ctx, "POST", actionURL, strings.NewReader(formData.Encode()))
					if err != nil {
						continue
					}
					req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				} else {
					parsedURL, err := url.Parse(actionURL)
					if err != nil {
						continue
					}
					parsedURL.RawQuery = formData.Encode()
					req, err = http.NewRequestWithContext(ctx, "GET", parsedURL.String(), nil)
					if err != nil {
						continue
					}
				}
				
				req.Header.Set("User-Agent", config.UserAgent)
				
				resp, err := rs.client.Do(req)
				if err != nil {
					continue
				}
				
				body := make([]byte, rs.config.Scanning.MaxBodySize)
				n, _ := resp.Body.Read(body)
				resp.Body.Close()
				
				responseBody := string(body[:n])
				
				if rs.isRCEVulnerable(payload, responseBody, resp) {
					vuln := &models.Vulnerability{
						ID:          fmt.Sprintf("rce-form-%s-%d", input.Name, time.Now().Unix()),
						Type:        "Remote Code Execution (Command Injection)",
						Severity:    "Critical",
						Title:       fmt.Sprintf("Command injection in form input '%s'", input.Name),
						Description: fmt.Sprintf("The form input '%s' is vulnerable to command injection.", input.Name),
						URL:         actionURL,
						Parameter:   input.Name,
						Payload:     payload.Payload,
						Method:      form.Method,
						Evidence:    rs.extractRCEEvidence(payload, responseBody),
						Impact:      "An attacker can execute arbitrary system commands through form input.",
						Remediation: "Validate and sanitize form inputs. Avoid executing user input as commands.",
						Risk:        "Critical",
						Confidence:  rs.calculateRCEConfidence(payload, responseBody),
						Timestamp:   time.Now(),
					}
					
					vulnerabilities = append(vulnerabilities, vuln)
					break
				}
			}
		}
	}
	
	return vulnerabilities, nil
}

func (rs *RCEScanner) testCommandInjectionInHeaders(ctx context.Context, target *models.Target, config *models.ScanConfig) ([]*models.Vulnerability, error) {
	vulnerabilities := make([]*models.Vulnerability, 0)
	
	// Test common headers that might be processed by the server
	testHeaders := []string{
		"User-Agent",
		"Referer",
		"X-Forwarded-For",
		"X-Real-IP",
		"X-Originating-IP",
		"CF-Connecting-IP",
		"X-Custom-Command",
	}
	
	for _, headerName := range testHeaders {
		for _, payload := range rs.payloads {
			if payload.Type != "command" || payload.Dangerous {
				continue
			}
			
			req, err := http.NewRequestWithContext(ctx, "GET", target.URL, nil)
			if err != nil {
				continue
			}
			
			req.Header.Set(headerName, payload.Payload)
			req.Header.Set("User-Agent", config.UserAgent)
			
			resp, err := rs.client.Do(req)
			if err != nil {
				continue
			}
			
			body := make([]byte, rs.config.Scanning.MaxBodySize)
			n, _ := resp.Body.Read(body)
			resp.Body.Close()
			
			responseBody := string(body[:n])
			
			if rs.isRCEVulnerable(payload, responseBody, resp) {
				vuln := &models.Vulnerability{
					ID:          fmt.Sprintf("rce-header-%s-%d", headerName, time.Now().Unix()),
					Type:        "Remote Code Execution (Command Injection)",
					Severity:    "Critical",
					Title:       fmt.Sprintf("Command injection in HTTP header '%s'", headerName),
					Description: fmt.Sprintf("The HTTP header '%s' is vulnerable to command injection.", headerName),
					URL:         target.URL,
					Parameter:   headerName,
					Payload:     payload.Payload,
					Method:      "GET",
					Evidence:    rs.extractRCEEvidence(payload, responseBody),
					Impact:      "An attacker can execute commands by manipulating HTTP headers.",
					Remediation: "Validate and sanitize HTTP header values before processing.",
					Risk:        "Critical",
					Confidence:  rs.calculateRCEConfidence(payload, responseBody),
					Timestamp:   time.Now(),
				}
				
				vulnerabilities = append(vulnerabilities, vuln)
				break
			}
		}
	}
	
	return vulnerabilities, nil
}

func (rs *RCEScanner) scanCodeEvaluation(ctx context.Context, target *models.Target, config *models.ScanConfig) ([]*models.Vulnerability, error) {
	vulnerabilities := make([]*models.Vulnerability, 0)
	
	// Test for code evaluation vulnerabilities (PHP eval, Python exec, etc.)
	parsedURL, err := url.Parse(target.URL)
	if err != nil {
		return nil, err
	}
	
	originalParams := parsedURL.Query()
	
	for paramName := range originalParams {
		for _, payload := range rs.payloads {
			if payload.Type != "eval" {
				continue
			}
			
			testParams := make(url.Values)
			for k, v := range originalParams {
				testParams[k] = v
			}
			testParams.Set(paramName, payload.Payload)
			
			parsedURL.RawQuery = testParams.Encode()
			testURL := parsedURL.String()
			
			resp, err := rs.makeRequest(ctx, testURL, "GET", "", config)
			if err != nil {
				continue
			}
			
			body := make([]byte, rs.config.Scanning.MaxBodySize)
			n, _ := resp.Body.Read(body)
			resp.Body.Close()
			
			responseBody := string(body[:n])
			
			if rs.isRCEVulnerable(payload, responseBody, resp) {
				vuln := &models.Vulnerability{
					ID:          fmt.Sprintf("rce-eval-%s-%d", paramName, time.Now().Unix()),
					Type:        "Remote Code Execution (Code Evaluation)",
					Severity:    "Critical",
					Title:       fmt.Sprintf("Code evaluation vulnerability in parameter '%s'", paramName),
					Description: fmt.Sprintf("The parameter '%s' is vulnerable to code evaluation attacks.", paramName),
					URL:         testURL,
					Parameter:   paramName,
					Payload:     payload.Payload,
					Method:      "GET",
					Evidence:    rs.extractRCEEvidence(payload, responseBody),
					Impact:      "An attacker can execute arbitrary code in the application context.",
					Remediation: "Avoid using eval() or similar functions with user input. Use safe alternatives.",
					Risk:        "Critical",
					Confidence:  rs.calculateRCEConfidence(payload, responseBody),
					Timestamp:   time.Now(),
				}
				
				vulnerabilities = append(vulnerabilities, vuln)
				break
			}
		}
	}
	
	return vulnerabilities, nil
}

func (rs *RCEScanner) scanTemplateInjection(ctx context.Context, target *models.Target, config *models.ScanConfig) ([]*models.Vulnerability, error) {
	vulnerabilities := make([]*models.Vulnerability, 0)
	
	parsedURL, err := url.Parse(target.URL)
	if err != nil {
		return nil, err
	}
	
	originalParams := parsedURL.Query()
	
	for paramName := range originalParams {
		for _, payload := range rs.payloads {
			if payload.Type != "template" {
				continue
			}
			
			testParams := make(url.Values)
			for k, v := range originalParams {
				testParams[k] = v
			}
			testParams.Set(paramName, payload.Payload)
			
			parsedURL.RawQuery = testParams.Encode()
			testURL := parsedURL.String()
			
			resp, err := rs.makeRequest(ctx, testURL, "GET", "", config)
			if err != nil {
				continue
			}
			
			body := make([]byte, rs.config.Scanning.MaxBodySize)
			n, _ := resp.Body.Read(body)
			resp.Body.Close()
			
			responseBody := string(body[:n])
			
			if rs.isRCEVulnerable(payload, responseBody, resp) {
				vuln := &models.Vulnerability{
					ID:          fmt.Sprintf("rce-template-%s-%d", paramName, time.Now().Unix()),
					Type:        "Remote Code Execution (Template Injection)",
					Severity:    "High",
					Title:       fmt.Sprintf("Template injection in parameter '%s'", paramName),
					Description: fmt.Sprintf("The parameter '%s' is vulnerable to server-side template injection.", paramName),
					URL:         testURL,
					Parameter:   paramName,
					Payload:     payload.Payload,
					Method:      "GET",
					Evidence:    rs.extractRCEEvidence(payload, responseBody),
					Impact:      "An attacker may be able to execute code through template injection.",
					Remediation: "Use safe template engines and avoid user input in templates.",
					Risk:        "High",
					Confidence:  rs.calculateRCEConfidence(payload, responseBody),
					Timestamp:   time.Now(),
				}
				
				vulnerabilities = append(vulnerabilities, vuln)
				break
			}
		}
	}
	
	return vulnerabilities, nil
}

func (rs *RCEScanner) scanDeserialization(ctx context.Context, target *models.Target, config *models.ScanConfig) ([]*models.Vulnerability, error) {
	vulnerabilities := make([]*models.Vulnerability, 0)
	
	// Test for insecure deserialization
	// This is more complex and typically requires specific payloads for different platforms
	
	for _, form := range target.Forms {
		for _, input := range form.Inputs {
			if input.Type == "hidden" && (strings.Contains(input.Value, "serialized") || 
				strings.Contains(input.Value, "pickle") || strings.Contains(input.Value, "json")) {
				
				// Potential serialized data found
				vuln := &models.Vulnerability{
					ID:          fmt.Sprintf("rce-deserial-%s-%d", input.Name, time.Now().Unix()),
					Type:        "Remote Code Execution (Insecure Deserialization)",
					Severity:    "High",
					Title:       fmt.Sprintf("Potential insecure deserialization in '%s'", input.Name),
					Description: "The application appears to deserialize user-controlled data, which may lead to remote code execution.",
					URL:         target.URL,
					Parameter:   input.Name,
					Evidence:    fmt.Sprintf("Serialized data found in input: %s", input.Value),
					Impact:      "An attacker may be able to execute code through deserialization attacks.",
					Remediation: "Avoid deserializing untrusted data. Use safe serialization formats like JSON with validation.",
					Risk:        "High",
					Confidence:  60, // Lower confidence as this requires manual verification
					Timestamp:   time.Now(),
				}
				
				vulnerabilities = append(vulnerabilities, vuln)
			}
		}
	}
	
	return vulnerabilities, nil
}

func (rs *RCEScanner) isRCEVulnerable(payload RCEPayload, responseBody string, resp *http.Response) bool {
	// Check for specific verification strings in the response
	if payload.Verification != "" {
		return strings.Contains(responseBody, payload.Verification)
	}
	
	// Check for common command execution indicators
	indicators := []string{
		"uid=", "gid=", // Unix id command output
		"root:", "/bin/", "/usr/", // Unix system paths
		"C:\\", "C:/", "Windows", // Windows paths
		"total ", // ls -l output
		"Directory of", // Windows dir output
		"Volume Serial Number", // Windows vol output
	}
	
	for _, indicator := range indicators {
		if strings.Contains(responseBody, indicator) {
			return true
		}
	}
	
	// Check for error messages that might indicate command execution
	errorIndicators := []string{
		"sh: command not found",
		"cmd: command not found",
		"cannot access",
		"permission denied",
		"no such file or directory",
	}
	
	for _, indicator := range errorIndicators {
		if strings.Contains(strings.ToLower(responseBody), strings.ToLower(indicator)) {
			return true
		}
	}
	
	return false
}

func (rs *RCEScanner) extractRCEEvidence(payload RCEPayload, responseBody string) string {
	// Extract relevant parts of the response as evidence
	lines := strings.Split(responseBody, "\n")
	evidence := make([]string, 0)
	
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		
		// Look for lines that might contain command output
		if strings.Contains(line, "uid=") || strings.Contains(line, "gid=") ||
		   strings.Contains(line, "root:") || strings.Contains(line, "/bin/") ||
		   strings.Contains(line, "C:\\") || strings.Contains(line, "total ") {
			evidence = append(evidence, fmt.Sprintf("Line %d: %s", i+1, line))
			if len(evidence) >= 3 {
				break
			}
		}
	}
	
	if len(evidence) > 0 {
		return strings.Join(evidence, "; ")
	}
	
	return fmt.Sprintf("Payload '%s' executed successfully", payload.Payload)
}

func (rs *RCEScanner) calculateRCEConfidence(payload RCEPayload, responseBody string) int {
	confidence := 30
	
	// Increase confidence based on specific indicators
	if strings.Contains(responseBody, "uid=") || strings.Contains(responseBody, "gid=") {
		confidence += 40
	}
	
	if strings.Contains(responseBody, "root:") || strings.Contains(responseBody, "/bin/") {
		confidence += 30
	}
	
	if strings.Contains(responseBody, "total ") || strings.Contains(responseBody, "Directory of") {
		confidence += 25
	}
	
	if payload.Verification != "" && strings.Contains(responseBody, payload.Verification) {
		confidence += 35
	}
	
	if confidence > 100 {
		confidence = 100
	}
	
	return confidence
}

func (rs *RCEScanner) generateRCEPoC(url, parameter, payload, method string) string {
	if method == "POST" {
		return fmt.Sprintf(`curl -X POST "%s" -d "%s=%s"`, url, parameter, url.QueryEscape(payload))
	}
	
	parsedURL, err := url.Parse(url)
	if err != nil {
		return fmt.Sprintf("%s %s", method, url)
	}
	
	params := parsedURL.Query()
	params.Set(parameter, payload)
	parsedURL.RawQuery = params.Encode()
	
	return fmt.Sprintf("GET %s", parsedURL.String())
}

func (rs *RCEScanner) makeRequest(ctx context.Context, url, method, body string, config *models.ScanConfig) (*http.Response, error) {
	if method == "" {
		method = "GET"
	}
	
	var req *http.Request
	var err error
	
	if body != "" {
		req, err = http.NewRequestWithContext(ctx, method, url, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req, err = http.NewRequestWithContext(ctx, method, url, nil)
	}
	
	if err != nil {
		return nil, err
	}
	
	req.Header.Set("User-Agent", config.UserAgent)
	if config.Headers != nil {
		for k, v := range config.Headers {
			req.Header.Set(k, v)
		}
	}
	
	return rs.client.Do(req)
}

func (rs *RCEScanner) isAuthenticationForm(form models.Form) bool {
	for _, input := range form.Inputs {
		name := strings.ToLower(input.Name)
		if strings.Contains(name, "password") || strings.Contains(name, "login") {
			return true
		}
	}
	return false
}

func loadRCEPayloads() []RCEPayload {
	return []RCEPayload{
		// Safe command injection test payloads
		{
			Payload:      "; echo 'RCE_TEST_12345'",
			Type:         "command",
			Platform:     "linux",
			Context:      "parameter",
			Description:  "Safe echo command for Linux",
			Dangerous:    false,
			Verification: "RCE_TEST_12345",
		},
		{
			Payload:      "| echo 'RCE_TEST_12345'",
			Type:         "command",
			Platform:     "linux",
			Context:      "parameter",
			Description:  "Pipe echo command for Linux",
			Dangerous:    false,
			Verification: "RCE_TEST_12345",
		},
		{
			Payload:      "& echo 'RCE_TEST_12345'",
			Type:         "command",
			Platform:     "windows",
			Context:      "parameter",
			Description:  "Safe echo command for Windows",
			Dangerous:    false,
			Verification: "RCE_TEST_12345",
		},
		{
			Payload:      "`echo 'RCE_TEST_12345'`",
			Type:         "command",
			Platform:     "linux",
			Context:      "parameter",
			Description:  "Backtick execution for Linux",
			Dangerous:    false,
			Verification: "RCE_TEST_12345",
		},
		{
			Payload:      "$(echo 'RCE_TEST_12345')",
			Type:         "command",
			Platform:     "linux",
			Context:      "parameter",
			Description:  "Command substitution for Linux",
			Dangerous:    false,
			Verification: "RCE_TEST_12345",
		},
		
		// Code evaluation payloads
		{
			Payload:      "print('RCE_TEST_12345')",
			Type:         "eval",
			Platform:     "all",
			Context:      "parameter",
			Description:  "Python code evaluation",
			Dangerous:    false,
			Verification: "RCE_TEST_12345",
		},
		{
			Payload:      "echo 'RCE_TEST_12345';",
			Type:         "eval",
			Platform:     "all",
			Context:      "parameter",
			Description:  "PHP code evaluation",
			Dangerous:    false,
			Verification: "RCE_TEST_12345",
		},
		{
			Payload:      "console.log('RCE_TEST_12345')",
			Type:         "eval",
			Platform:     "all",
			Context:      "parameter",
			Description:  "JavaScript code evaluation",
			Dangerous:    false,
			Verification: "RCE_TEST_12345",
		},
		
		// Template injection payloads
		{
			Payload:      "{{7*7}}",
			Type:         "template",
			Platform:     "all",
			Context:      "parameter",
			Description:  "Basic template injection test",
			Dangerous:    false,
			Verification: "49",
		},
		{
			Payload:      "${7*7}",
			Type:         "template",
			Platform:     "all",
			Context:      "parameter",
			Description:  "JSP/EL template injection",
			Dangerous:    false,
			Verification: "49",
		},
		{
			Payload:      "#{7*7}",
			Type:         "template",
			Platform:     "all",
			Context:      "parameter",
			Description:  "Ruby template injection",
			Dangerous:    false,
			Verification: "49",
		},
		{
			Payload:      "{{config}}",
			Type:         "template",
			Platform:     "all",
			Context:      "parameter",
			Description:  "Flask/Jinja2 config exposure",
			Dangerous:    false,
			Verification: "Config",
		},
	}
}
