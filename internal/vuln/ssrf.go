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

// SSRFScanner detects Server-Side Request Forgery vulnerabilities
type SSRFScanner struct {
	config   *config.Config
	log      logger.Logger
	client   *http.Client
	payloads []SSRFPayload
}

type SSRFPayload struct {
	URL         string
	Type        string // internal, cloud, redirect, blind
	Description string
	Indicators  []string
	Risk        string
}

// NewSSRFScanner creates a new SSRF vulnerability scanner
func NewSSRFScanner(cfg *config.Config, log logger.Logger) *SSRFScanner {
	return &SSRFScanner{
		config:   cfg,
		log:      log,
		client:   utils.NewHTTPClient(cfg),
		payloads: loadSSRFPayloads(),
	}
}

// ScanForSSRF performs comprehensive SSRF vulnerability scanning
func (ss *SSRFScanner) ScanForSSRF(ctx context.Context, target *models.Target, config *models.ScanConfig) ([]*models.Vulnerability, error) {
	ss.log.Info("Starting SSRF vulnerability scan", "target", target.URL)
	
	vulnerabilities := make([]*models.Vulnerability, 0)
	
	// Test different SSRF contexts
	contexts := []string{"url_parameter", "form_input", "file_upload", "api_endpoint"}
	
	for _, context := range contexts {
		switch context {
		case "url_parameter":
			vulns, err := ss.scanURLParameters(ctx, target, config)
			if err != nil {
				ss.log.Error("SSRF URL parameter scan failed", "error", err)
				continue
			}
			vulnerabilities = append(vulnerabilities, vulns...)
			
		case "form_input":
			vulns, err := ss.scanFormInputs(ctx, target, config)
			if err != nil {
				ss.log.Error("SSRF form input scan failed", "error", err)
				continue
			}
			vulnerabilities = append(vulnerabilities, vulns...)
			
		case "api_endpoint":
			vulns, err := ss.scanAPIEndpoints(ctx, target, config)
			if err != nil {
				ss.log.Error("SSRF API endpoint scan failed", "error", err)
				continue
			}
			vulnerabilities = append(vulnerabilities, vulns...)
		}
	}
	
	ss.log.Info("SSRF scan completed",
		"target", target.URL,
		"vulnerabilities_found", len(vulnerabilities))
	
	return vulnerabilities, nil
}

func (ss *SSRFScanner) scanURLParameters(ctx context.Context, target *models.Target, config *models.ScanConfig) ([]*models.Vulnerability, error) {
	vulnerabilities := make([]*models.Vulnerability, 0)
	
	parsedURL, err := url.Parse(target.URL)
	if err != nil {
		return nil, err
	}
	
	originalParams := parsedURL.Query()
	
	// Test each parameter with SSRF payloads
	for paramName := range originalParams {
		// Skip non-URL looking parameters
		originalValue := originalParams.Get(paramName)
		if !ss.looksLikeURLParameter(originalValue) {
			continue
		}
		
		for _, payload := range ss.payloads {
			// Create test URL with payload
			testParams := make(url.Values)
			for k, v := range originalParams {
				testParams[k] = v
			}
			testParams.Set(paramName, payload.URL)
			
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
			
			startTime := time.Now()
			resp, err := ss.client.Do(req)
			responseTime := time.Since(startTime)
			
			if err != nil {
				// Check if this is a timeout or connection error that might indicate SSRF
				if ss.isSSRFIndicativeError(err, payload) {
					vuln := ss.createSSRFVulnerability(target.URL, paramName, payload, "timeout/error", err.Error(), responseTime)
					vulnerabilities = append(vulnerabilities, vuln)
				}
				continue
			}
			
			// Read response
			body := make([]byte, ss.config.Scanning.MaxBodySize)
			n, _ := resp.Body.Read(body)
			resp.Body.Close()
			
			responseBody := string(body[:n])
			
			// Check for SSRF indicators
			if ss.isSSRFVulnerable(payload, responseBody, resp, responseTime) {
				evidence := ss.extractSSRFEvidence(payload, responseBody, resp)
				vuln := ss.createSSRFVulnerability(testURL, paramName, payload, evidence, responseBody, responseTime)
				vulnerabilities = append(vulnerabilities, vuln)
				
				ss.log.Info("SSRF vulnerability found",
					"url", testURL,
					"parameter", paramName,
					"payload", payload.URL)
				
				break // Found vulnerability, move to next parameter
			}
		}
	}
	
	return vulnerabilities, nil
}

func (ss *SSRFScanner) scanFormInputs(ctx context.Context, target *models.Target, config *models.ScanConfig) ([]*models.Vulnerability, error) {
	vulnerabilities := make([]*models.Vulnerability, 0)
	
	for _, form := range target.Forms {
		for _, input := range form.Inputs {
			// Skip non-relevant input types
			if input.Type == "submit" || input.Type == "button" || input.Type == "hidden" {
				continue
			}
			
			// Look for URL-like input names or existing URL values
			if !ss.isURLRelatedInput(input) {
				continue
			}
			
			for _, payload := range ss.payloads {
				// Build form data
				formData := url.Values{}
				for _, formInput := range form.Inputs {
					if formInput.Name == input.Name {
						formData.Set(formInput.Name, payload.URL)
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
				
				startTime := time.Now()
				resp, err := ss.client.Do(req)
				responseTime := time.Since(startTime)
				
				if err != nil {
					if ss.isSSRFIndicativeError(err, payload) {
						vuln := ss.createSSRFVulnerability(actionURL, input.Name, payload, "form timeout/error", err.Error(), responseTime)
						vulnerabilities = append(vulnerabilities, vuln)
					}
					continue
				}
				
				body := make([]byte, ss.config.Scanning.MaxBodySize)
				n, _ := resp.Body.Read(body)
				resp.Body.Close()
				
				responseBody := string(body[:n])
				
				if ss.isSSRFVulnerable(payload, responseBody, resp, responseTime) {
					evidence := ss.extractSSRFEvidence(payload, responseBody, resp)
					vuln := ss.createSSRFVulnerability(actionURL, input.Name, payload, evidence, responseBody, responseTime)
					vulnerabilities = append(vulnerabilities, vuln)
					break
				}
			}
		}
	}
	
	return vulnerabilities, nil
}

func (ss *SSRFScanner) scanAPIEndpoints(ctx context.Context, target *models.Target, config *models.ScanConfig) ([]*models.Vulnerability, error) {
	vulnerabilities := make([]*models.Vulnerability, 0)
	
	// Common API endpoints that might be vulnerable to SSRF
	apiEndpoints := []string{
		"/api/fetch",
		"/api/url",
		"/api/proxy",
		"/api/webhook",
		"/api/callback",
		"/api/import",
		"/api/export",
		"/api/download",
		"/api/upload",
		"/webhook",
		"/proxy",
		"/fetch",
	}
	
	baseURL := ss.getBaseURL(target.URL)
	
	for _, endpoint := range apiEndpoints {
		testURL := baseURL + endpoint
		
		// Test common parameter names for SSRF
		paramNames := []string{"url", "uri", "link", "src", "source", "target", "dest", "destination", "callback", "webhook"}
		
		for _, paramName := range paramNames {
			for _, payload := range ss.payloads {
				// Test both GET and POST methods
				methods := []string{"GET", "POST"}
				
				for _, method := range methods {
					var req *http.Request
					var err error
					
					if method == "POST" {
						formData := url.Values{}
						formData.Set(paramName, payload.URL)
						req, err = http.NewRequestWithContext(ctx, "POST", testURL, strings.NewReader(formData.Encode()))
						if err != nil {
							continue
						}
						req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					} else {
						u, err := url.Parse(testURL)
						if err != nil {
							continue
						}
						params := u.Query()
						params.Set(paramName, payload.URL)
						u.RawQuery = params.Encode()
						
						req, err = http.NewRequestWithContext(ctx, "GET", u.String(), nil)
						if err != nil {
							continue
						}
					}
					
					req.Header.Set("User-Agent", config.UserAgent)
					
					startTime := time.Now()
					resp, err := ss.client.Do(req)
					responseTime := time.Since(startTime)
					
					if err != nil {
						if ss.isSSRFIndicativeError(err, payload) {
							vuln := ss.createSSRFVulnerability(testURL, paramName, payload, "API timeout/error", err.Error(), responseTime)
							vulnerabilities = append(vulnerabilities, vuln)
						}
						continue
					}
					
					body := make([]byte, ss.config.Scanning.MaxBodySize)
					n, _ := resp.Body.Read(body)
					resp.Body.Close()
					
					responseBody := string(body[:n])
					
					if ss.isSSRFVulnerable(payload, responseBody, resp, responseTime) {
						evidence := ss.extractSSRFEvidence(payload, responseBody, resp)
						vuln := ss.createSSRFVulnerability(testURL, paramName, payload, evidence, responseBody, responseTime)
						vulnerabilities = append(vulnerabilities, vuln)
						break
					}
				}
			}
		}
	}
	
	return vulnerabilities, nil
}

func (ss *SSRFScanner) looksLikeURLParameter(value string) bool {
	// Check if parameter value looks like a URL
	urlPatterns := []string{
		"http://", "https://", "ftp://", "file://",
		"://", ".com", ".org", ".net", ".edu",
	}
	
	valueLower := strings.ToLower(value)
	for _, pattern := range urlPatterns {
		if strings.Contains(valueLower, pattern) {
			return true
		}
	}
	
	return false
}

func (ss *SSRFScanner) isURLRelatedInput(input models.FormInput) bool {
	name := strings.ToLower(input.Name)
	value := strings.ToLower(input.Value)
	
	// Check input name
	urlNames := []string{"url", "uri", "link", "src", "source", "href", "callback", "webhook", "endpoint"}
	for _, urlName := range urlNames {
		if strings.Contains(name, urlName) {
			return true
		}
	}
	
	// Check input value
	if ss.looksLikeURLParameter(value) {
		return true
	}
	
	return false
}

func (ss *SSRFScanner) isSSRFIndicativeError(err error, payload SSRFPayload) bool {
	errorStr := strings.ToLower(err.Error())
	
	// Check for errors that might indicate SSRF attempts
	ssrfErrors := []string{
		"connection refused",
		"connection timeout",
		"no route to host",
		"network unreachable",
		"timeout",
		"dial tcp",
		"i/o timeout",
	}
	
	for _, ssrfError := range ssrfErrors {
		if strings.Contains(errorStr, ssrfError) {
			return true
		}
	}
	
	return false
}

func (ss *SSRFScanner) isSSRFVulnerable(payload SSRFPayload, responseBody string, resp *http.Response, responseTime time.Duration) bool {
	// Check for payload-specific indicators
	for _, indicator := range payload.Indicators {
		if strings.Contains(responseBody, indicator) {
			return true
		}
	}
	
	// Check for common SSRF response indicators
	commonIndicators := []string{
		"AWS", "EC2", "metadata", "169.254.169.254",
		"localhost", "127.0.0.1", "internal", "private",
		"connection established", "connection successful",
		"curl", "wget", "fetch", "HttpClient",
	}
	
	responseBodyLower := strings.ToLower(responseBody)
	for _, indicator := range commonIndicators {
		if strings.Contains(responseBodyLower, strings.ToLower(indicator)) {
			return true
		}
	}
	
	// Check response time for internal network access
	if payload.Type == "internal" && responseTime < 100*time.Millisecond {
		return true
	}
	
	// Check for specific status codes
	if payload.Type == "cloud" && resp.StatusCode == 200 {
		return true
	}
	
	return false
}

func (ss *SSRFScanner) extractSSRFEvidence(payload SSRFPayload, responseBody string, resp *http.Response) string {
	evidence := fmt.Sprintf("Status: %d", resp.StatusCode)
	
	// Look for specific indicators in response
	for _, indicator := range payload.Indicators {
		if strings.Contains(responseBody, indicator) {
			evidence += fmt.Sprintf(", Found indicator: %s", indicator)
		}
	}
	
	// Extract relevant response headers
	relevantHeaders := []string{"Server", "X-Powered-By", "Content-Type"}
	for _, header := range relevantHeaders {
		if value := resp.Header.Get(header); value != "" {
			evidence += fmt.Sprintf(", %s: %s", header, value)
		}
	}
	
	// Extract first few lines of response if they contain interesting data
	lines := strings.Split(responseBody, "\n")
	for i, line := range lines {
		if i >= 3 {
			break
		}
		line = strings.TrimSpace(line)
		if len(line) > 0 && len(line) < 100 {
			evidence += fmt.Sprintf(", Response line %d: %s", i+1, line)
		}
	}
	
	return evidence
}

func (ss *SSRFScanner) createSSRFVulnerability(url, parameter string, payload SSRFPayload, evidence, responseBody string, responseTime time.Duration) *models.Vulnerability {
	vuln := &models.Vulnerability{
		ID:          fmt.Sprintf("ssrf-%s-%s-%d", payload.Type, parameter, time.Now().Unix()),
		Type:        "Server-Side Request Forgery (SSRF)",
		Severity:    payload.Risk,
		Title:       fmt.Sprintf("SSRF vulnerability in parameter '%s'", parameter),
		Description: fmt.Sprintf("The parameter '%s' is vulnerable to Server-Side Request Forgery. %s", parameter, payload.Description),
		URL:         url,
		Parameter:   parameter,
		Payload:     payload.URL,
		Method:      "GET",
		Evidence:    evidence,
		Impact:      ss.getSSRFImpact(payload.Type),
		Remediation: ss.getSSRFRemediation(),
		References: []string{
			"https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
			"https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
			"https://portswigger.net/web-security/ssrf",
		},
		Risk:        payload.Risk,
		Confidence:  ss.calculateSSRFConfidence(payload, evidence),
		Timestamp:   time.Now(),
	}
	
	vuln.ProofOfConcept = ss.generateSSRFPoC(url, parameter, payload.URL)
	return vuln
}

func (ss *SSRFScanner) getSSRFImpact(ssrfType string) string {
	switch ssrfType {
	case "internal":
		return "Attackers can access internal services and resources not accessible from the internet, potentially leading to information disclosure or further attacks on internal infrastructure."
	case "cloud":
		return "Attackers can access cloud metadata services to retrieve sensitive information such as API keys, credentials, and instance information."
	case "redirect":
		return "Attackers can cause the server to make requests to arbitrary external URLs, potentially leading to data exfiltration or abuse of server resources."
	case "blind":
		return "Attackers can cause the server to make requests to external servers, which can be used for data exfiltration or as part of more complex attack chains."
	default:
		return "Attackers can cause the server to make requests to arbitrary URLs, potentially accessing internal resources or external services."
	}
}

func (ss *SSRFScanner) getSSRFRemediation() string {
	return "Implement proper input validation and URL filtering. Use allow-lists for permitted domains/IPs. Disable or restrict access to internal network ranges. Implement network segmentation and use a dedicated service for external requests."
}

func (ss *SSRFScanner) calculateSSRFConfidence(payload SSRFPayload, evidence string) int {
	confidence := 50
	
	// Increase confidence based on specific indicators
	if strings.Contains(evidence, "Found indicator:") {
		confidence += 30
	}
	
	if strings.Contains(evidence, "Status: 200") {
		confidence += 20
	}
	
	if payload.Type == "cloud" && strings.Contains(evidence, "metadata") {
		confidence += 25
	}
	
	if payload.Type == "internal" && strings.Contains(evidence, "127.0.0.1") {
		confidence += 20
	}
	
	if confidence > 100 {
		confidence = 100
	}
	
	return confidence
}

func (ss *SSRFScanner) generateSSRFPoC(targetURL, parameter, payload string) string {
	return fmt.Sprintf(`curl -X GET "%s?%s=%s"`, targetURL, parameter, url.QueryEscape(payload))
}

func (ss *SSRFScanner) getBaseURL(fullURL string) string {
	if u, err := url.Parse(fullURL); err == nil {
		return fmt.Sprintf("%s://%s", u.Scheme, u.Host)
	}
	return fullURL
}

func loadSSRFPayloads() []SSRFPayload {
	return []SSRFPayload{
		// Internal network access
		{
			URL:         "http://127.0.0.1:80",
			Type:        "internal",
			Description: "Localhost access attempt",
			Indicators:  []string{"localhost", "127.0.0.1"},
			Risk:        "High",
		},
		{
			URL:         "http://127.0.0.1:22",
			Type:        "internal",
			Description: "SSH port access attempt",
			Indicators:  []string{"SSH", "OpenSSH"},
			Risk:        "High",
		},
		{
			URL:         "http://127.0.0.1:3306",
			Type:        "internal",
			Description: "MySQL port access attempt",
			Indicators:  []string{"mysql", "database"},
			Risk:        "High",
		},
		{
			URL:         "http://192.168.1.1",
			Type:        "internal",
			Description: "Private network access",
			Indicators:  []string{"192.168", "private"},
			Risk:        "High",
		},
		{
			URL:         "http://10.0.0.1",
			Type:        "internal",
			Description: "Private network access",
			Indicators:  []string{"10.0", "private"},
			Risk:        "High",
		},
		
		// Cloud metadata access
		{
			URL:         "http://169.254.169.254/latest/meta-data/",
			Type:        "cloud",
			Description: "AWS metadata service access",
			Indicators:  []string{"ami-", "instance-", "security-credentials"},
			Risk:        "Critical",
		},
		{
			URL:         "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
			Type:        "cloud",
			Description: "AWS IAM credentials access",
			Indicators:  []string{"AccessKeyId", "SecretAccessKey", "Token"},
			Risk:        "Critical",
		},
		{
			URL:         "http://metadata.google.internal/computeMetadata/v1/",
			Type:        "cloud",
			Description: "GCP metadata service access",
			Indicators:  []string{"access_token", "service-accounts"},
			Risk:        "Critical",
		},
		{
			URL:         "http://169.254.169.254/metadata/instance",
			Type:        "cloud",
			Description: "Azure metadata service access",
			Indicators:  []string{"subscriptionId", "resourceGroupName"},
			Risk:        "Critical",
		},
		
		// External redirect tests
		{
			URL:         "http://httpbin.org/get",
			Type:        "redirect",
			Description: "External service request test",
			Indicators:  []string{"httpbin", "origin"},
			Risk:        "Medium",
		},
		{
			URL:         "https://example.com",
			Type:        "redirect",
			Description: "External domain access test",
			Indicators:  []string{"Example Domain", "example.com"},
			Risk:        "Medium",
		},
		
		// Protocol tests
		{
			URL:         "file:///etc/passwd",
			Type:        "internal",
			Description: "File protocol access attempt",
			Indicators:  []string{"root:", "bin:", "daemon:"},
			Risk:        "High",
		},
		{
			URL:         "file:///etc/hosts",
			Type:        "internal",
			Description: "Hosts file access attempt",
			Indicators:  []string{"localhost", "127.0.0.1"},
			Risk:        "Medium",
		},
		{
			URL:         "ftp://127.0.0.1",
			Type:        "internal",
			Description: "FTP protocol access attempt",
			Indicators:  []string{"FTP", "220"},
			Risk:        "Medium",
		},
		
		// Bypass attempts
		{
			URL:         "http://0177.0.0.1",
			Type:        "internal",
			Description: "Octal encoding bypass attempt",
			Indicators:  []string{"localhost", "127.0.0.1"},
			Risk:        "High",
		},
		{
			URL:         "http://127.1",
			Type:        "internal",
			Description: "Short form localhost bypass",
			Indicators:  []string{"localhost", "127.0.0.1"},
			Risk:        "High",
		},
		{
			URL:         "http://[::1]",
			Type:        "internal",
			Description: "IPv6 localhost access",
			Indicators:  []string{"localhost", "::1"},
			Risk:        "High",
		},
	}
}
