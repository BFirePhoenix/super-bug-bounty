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

// XSSScanner detects Cross-Site Scripting vulnerabilities
type XSSScanner struct {
	config   *config.Config
	log      logger.Logger
	client   *http.Client
	payloads []XSSPayload
}

type XSSPayload struct {
	Payload     string
	Type        string // reflected, stored, dom
	Context     string // html, attribute, script, etc.
	Description string
	Dangerous   bool
}

// NewXSSScanner creates a new XSS vulnerability scanner
func NewXSSScanner(cfg *config.Config, log logger.Logger) *XSSScanner {
	return &XSSScanner{
		config:   cfg,
		log:      log,
		client:   utils.NewHTTPClient(cfg),
		payloads: loadXSSPayloads(),
	}
}

// ScanForXSS performs comprehensive XSS vulnerability scanning
func (xs *XSSScanner) ScanForXSS(ctx context.Context, target *models.Target, config *models.ScanConfig) ([]*models.Vulnerability, error) {
	xs.log.Info("Starting XSS vulnerability scan", "target", target.URL)
	
	vulnerabilities := make([]*models.Vulnerability, 0)
	
	// Scan different contexts
	contexts := []string{"reflected", "stored", "dom"}
	
	for _, context := range contexts {
		switch context {
		case "reflected":
			vulns, err := xs.scanReflectedXSS(ctx, target, config)
			if err != nil {
				xs.log.Error("Reflected XSS scan failed", "error", err)
				continue
			}
			vulnerabilities = append(vulnerabilities, vulns...)
			
		case "stored":
			vulns, err := xs.scanStoredXSS(ctx, target, config)
			if err != nil {
				xs.log.Error("Stored XSS scan failed", "error", err)
				continue
			}
			vulnerabilities = append(vulnerabilities, vulns...)
			
		case "dom":
			vulns, err := xs.scanDOMXSS(ctx, target, config)
			if err != nil {
				xs.log.Error("DOM XSS scan failed", "error", err)
				continue
			}
			vulnerabilities = append(vulnerabilities, vulns...)
		}
	}
	
	xs.log.Info("XSS scan completed", 
		"target", target.URL,
		"vulnerabilities_found", len(vulnerabilities))
	
	return vulnerabilities, nil
}

func (xs *XSSScanner) scanReflectedXSS(ctx context.Context, target *models.Target, config *models.ScanConfig) ([]*models.Vulnerability, error) {
	vulnerabilities := make([]*models.Vulnerability, 0)
	
	// Test GET parameters
	if len(target.Parameters) > 0 {
		vulns, err := xs.testReflectedXSSInParameters(ctx, target, config)
		if err != nil {
			return nil, err
		}
		vulnerabilities = append(vulnerabilities, vulns...)
	}
	
	// Test forms
	if len(target.Forms) > 0 {
		vulns, err := xs.testReflectedXSSInForms(ctx, target, config)
		if err != nil {
			return nil, err
		}
		vulnerabilities = append(vulnerabilities, vulns...)
	}
	
	// Test headers
	vulns, err := xs.testReflectedXSSInHeaders(ctx, target, config)
	if err != nil {
		return nil, err
	}
	vulnerabilities = append(vulnerabilities, vulns...)
	
	return vulnerabilities, nil
}

func (xs *XSSScanner) testReflectedXSSInParameters(ctx context.Context, target *models.Target, config *models.ScanConfig) ([]*models.Vulnerability, error) {
	vulnerabilities := make([]*models.Vulnerability, 0)
	
	// Parse URL to get query parameters
	parsedURL, err := url.Parse(target.URL)
	if err != nil {
		return nil, err
	}
	
	originalParams := parsedURL.Query()
	
	// Test each parameter with various payloads
	for paramName := range originalParams {
		for _, payload := range xs.payloads {
			if payload.Type != "reflected" && payload.Type != "all" {
				continue
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
			
			// Set headers
			req.Header.Set("User-Agent", config.UserAgent)
			if config.Headers != nil {
				for k, v := range config.Headers {
					req.Header.Set(k, v)
				}
			}
			
			resp, err := xs.client.Do(req)
			if err != nil {
				continue
			}
			
			// Read response
			body := make([]byte, xs.config.Scanning.MaxBodySize)
			n, _ := resp.Body.Read(body)
			resp.Body.Close()
			
			responseBody := string(body[:n])
			
			// Check if payload is reflected and executable
			if xs.isXSSVulnerable(payload.Payload, responseBody, resp.Header) {
				vuln := &models.Vulnerability{
					ID:          fmt.Sprintf("xss-reflected-%s-%d", paramName, time.Now().Unix()),
					Type:        "Cross-Site Scripting (Reflected)",
					Severity:    xs.calculateXSSSeverity(payload, resp),
					Title:       fmt.Sprintf("Reflected XSS in parameter '%s'", paramName),
					Description: fmt.Sprintf("The parameter '%s' is vulnerable to reflected XSS attacks. User input is reflected in the response without proper sanitization.", paramName),
					URL:         testURL,
					Parameter:   paramName,
					Payload:     payload.Payload,
					Method:      "GET",
					Evidence:    xs.extractEvidence(payload.Payload, responseBody),
					Impact:      "An attacker can execute arbitrary JavaScript in the victim's browser, potentially stealing cookies, session tokens, or performing actions on behalf of the user.",
					Remediation: "Implement proper input validation and output encoding. Use Content Security Policy (CSP) headers to mitigate XSS attacks.",
					References: []string{
						"https://owasp.org/www-community/attacks/xss/",
						"https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
					},
					Risk:        xs.calculateRisk(payload, resp),
					Confidence:  xs.calculateConfidence(payload, responseBody),
					Timestamp:   time.Now(),
				}
				
				// Add proof of concept
				vuln.ProofOfConcept = xs.generateXSSPoC(testURL, paramName, payload.Payload, "GET")
				
				vulnerabilities = append(vulnerabilities, vuln)
				
				xs.log.Info("Reflected XSS vulnerability found",
					"url", testURL,
					"parameter", paramName,
					"payload", payload.Payload)
				
				// Break after finding vulnerability to avoid too many duplicates
				break
			}
		}
	}
	
	return vulnerabilities, nil
}

func (xs *XSSScanner) testReflectedXSSInForms(ctx context.Context, target *models.Target, config *models.ScanConfig) ([]*models.Vulnerability, error) {
	vulnerabilities := make([]*models.Vulnerability, 0)
	
	for _, form := range target.Forms {
		// Test each form input
		for _, input := range form.Inputs {
			if input.Type == "submit" || input.Type == "button" || input.Type == "hidden" {
				continue
			}
			
			for _, payload := range xs.payloads {
				if payload.Type != "reflected" && payload.Type != "all" {
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
				} else if !strings.HasPrefix(actionURL, "http") {
					baseURL, _ := url.Parse(target.URL)
					actionURL = baseURL.ResolveReference(&url.URL{Path: actionURL}).String()
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
					// GET method
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
				if config.Headers != nil {
					for k, v := range config.Headers {
						req.Header.Set(k, v)
					}
				}
				
				resp, err := xs.client.Do(req)
				if err != nil {
					continue
				}
				
				// Read response
				body := make([]byte, xs.config.Scanning.MaxBodySize)
				n, _ := resp.Body.Read(body)
				resp.Body.Close()
				
				responseBody := string(body[:n])
				
				// Check for XSS vulnerability
				if xs.isXSSVulnerable(payload.Payload, responseBody, resp.Header) {
					vuln := &models.Vulnerability{
						ID:          fmt.Sprintf("xss-form-%s-%d", input.Name, time.Now().Unix()),
						Type:        "Cross-Site Scripting (Reflected)",
						Severity:    xs.calculateXSSSeverity(payload, resp),
						Title:       fmt.Sprintf("Reflected XSS in form input '%s'", input.Name),
						Description: fmt.Sprintf("The form input '%s' is vulnerable to reflected XSS attacks.", input.Name),
						URL:         actionURL,
						Parameter:   input.Name,
						Payload:     payload.Payload,
						Method:      form.Method,
						Evidence:    xs.extractEvidence(payload.Payload, responseBody),
						Impact:      "An attacker can execute arbitrary JavaScript in the victim's browser.",
						Remediation: "Implement proper input validation and output encoding for form inputs.",
						Risk:        xs.calculateRisk(payload, resp),
						Confidence:  xs.calculateConfidence(payload, responseBody),
						Timestamp:   time.Now(),
					}
					
					vuln.ProofOfConcept = xs.generateXSSPoC(actionURL, input.Name, payload.Payload, form.Method)
					vulnerabilities = append(vulnerabilities, vuln)
					
					break
				}
			}
		}
	}
	
	return vulnerabilities, nil
}

func (xs *XSSScanner) testReflectedXSSInHeaders(ctx context.Context, target *models.Target, config *models.ScanConfig) ([]*models.Vulnerability, error) {
	vulnerabilities := make([]*models.Vulnerability, 0)
	
	// Test common headers that might be reflected
	testHeaders := []string{
		"User-Agent",
		"Referer",
		"X-Forwarded-For",
		"X-Real-IP",
		"X-Originating-IP",
		"CF-Connecting-IP",
		"X-Custom-Header",
	}
	
	for _, headerName := range testHeaders {
		for _, payload := range xs.payloads {
			if payload.Type != "reflected" && payload.Type != "all" {
				continue
			}
			
			req, err := http.NewRequestWithContext(ctx, "GET", target.URL, nil)
			if err != nil {
				continue
			}
			
			// Set test header with payload
			req.Header.Set(headerName, payload.Payload)
			req.Header.Set("User-Agent", config.UserAgent)
			
			resp, err := xs.client.Do(req)
			if err != nil {
				continue
			}
			
			// Read response
			body := make([]byte, xs.config.Scanning.MaxBodySize)
			n, _ := resp.Body.Read(body)
			resp.Body.Close()
			
			responseBody := string(body[:n])
			
			// Check for XSS vulnerability
			if xs.isXSSVulnerable(payload.Payload, responseBody, resp.Header) {
				vuln := &models.Vulnerability{
					ID:          fmt.Sprintf("xss-header-%s-%d", headerName, time.Now().Unix()),
					Type:        "Cross-Site Scripting (Reflected)",
					Severity:    xs.calculateXSSSeverity(payload, resp),
					Title:       fmt.Sprintf("Reflected XSS in HTTP header '%s'", headerName),
					Description: fmt.Sprintf("The HTTP header '%s' is vulnerable to reflected XSS attacks.", headerName),
					URL:         target.URL,
					Parameter:   headerName,
					Payload:     payload.Payload,
					Method:      "GET",
					Evidence:    xs.extractEvidence(payload.Payload, responseBody),
					Impact:      "An attacker can execute arbitrary JavaScript by manipulating HTTP headers.",
					Remediation: "Validate and sanitize HTTP header values before reflecting them in responses.",
					Risk:        xs.calculateRisk(payload, resp),
					Confidence:  xs.calculateConfidence(payload, responseBody),
					Timestamp:   time.Now(),
				}
				
				vulnerabilities = append(vulnerabilities, vuln)
				break
			}
		}
	}
	
	return vulnerabilities, nil
}

func (xs *XSSScanner) scanStoredXSS(ctx context.Context, target *models.Target, config *models.ScanConfig) ([]*models.Vulnerability, error) {
	vulnerabilities := make([]*models.Vulnerability, 0)
	
	// Test forms that might store data
	for _, form := range target.Forms {
		// Skip login/authentication forms
		if xs.isAuthenticationForm(form) {
			continue
		}
		
		vulns, err := xs.testStoredXSSInForm(ctx, target, form, config)
		if err != nil {
			xs.log.Error("Stored XSS test failed", "form", form.Action, "error", err)
			continue
		}
		vulnerabilities = append(vulnerabilities, vulns...)
	}
	
	return vulnerabilities, nil
}

func (xs *XSSScanner) testStoredXSSInForm(ctx context.Context, target *models.Target, form models.Form, config *models.ScanConfig) ([]*models.Vulnerability, error) {
	vulnerabilities := make([]*models.Vulnerability, 0)
	
	// Generate unique payload for tracking
	uniqueID := fmt.Sprintf("xss-%d", time.Now().Unix())
	trackingPayloads := []string{
		fmt.Sprintf("<script>console.log('%s')</script>", uniqueID),
		fmt.Sprintf("'><script>alert('%s')</script>", uniqueID),
		fmt.Sprintf("\"><img src=x onerror=alert('%s')>", uniqueID),
	}
	
	for _, payload := range trackingPayloads {
		// Submit form with payload
		if err := xs.submitFormWithPayload(ctx, target, form, payload, config); err != nil {
			continue
		}
		
		// Wait a moment for potential processing
		time.Sleep(2 * time.Second)
		
		// Check if payload is stored by visiting the same page or related pages
		stored := xs.checkForStoredPayload(ctx, target.URL, uniqueID, config)
		if stored {
			vuln := &models.Vulnerability{
				ID:          fmt.Sprintf("xss-stored-%s-%d", form.Action, time.Now().Unix()),
				Type:        "Cross-Site Scripting (Stored)",
				Severity:    "High",
				Title:       "Stored XSS vulnerability",
				Description: "User input is stored and executed when the page is viewed by other users.",
				URL:         form.Action,
				Payload:     payload,
				Method:      form.Method,
				Evidence:    fmt.Sprintf("Payload '%s' was successfully stored and executed", payload),
				Impact:      "An attacker can execute arbitrary JavaScript that affects all users who view the stored content.",
				Remediation: "Implement proper input validation, output encoding, and Content Security Policy.",
				Risk:        "High",
				Confidence:  90,
				Timestamp:   time.Now(),
			}
			
			vulnerabilities = append(vulnerabilities, vuln)
			break
		}
	}
	
	return vulnerabilities, nil
}

func (xs *XSSScanner) scanDOMXSS(ctx context.Context, target *models.Target, config *models.ScanConfig) ([]*models.Vulnerability, error) {
	vulnerabilities := make([]*models.Vulnerability, 0)
	
	// DOM XSS typically involves client-side JavaScript analysis
	// This is a simplified implementation that checks for common DOM XSS patterns
	
	req, err := http.NewRequestWithContext(ctx, "GET", target.URL, nil)
	if err != nil {
		return nil, err
	}
	
	req.Header.Set("User-Agent", config.UserAgent)
	
	resp, err := xs.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	// Read response
	body := make([]byte, xs.config.Scanning.MaxBodySize)
	n, _ := resp.Body.Read(body)
	responseBody := string(body[:n])
	
	// Check for DOM XSS patterns
	domPatterns := []struct {
		pattern     *regexp.Regexp
		description string
		risk        string
	}{
		{
			pattern:     regexp.MustCompile(`document\.location\.hash`),
			description: "Potential DOM XSS via location.hash",
			risk:        "Medium",
		},
		{
			pattern:     regexp.MustCompile(`document\.URL`),
			description: "Potential DOM XSS via document.URL",
			risk:        "Medium",
		},
		{
			pattern:     regexp.MustCompile(`window\.location\.search`),
			description: "Potential DOM XSS via location.search",
			risk:        "Medium",
		},
		{
			pattern:     regexp.MustCompile(`innerHTML\s*=.*document\.(location|URL)`),
			description: "Dangerous innerHTML assignment with user-controlled data",
			risk:        "High",
		},
		{
			pattern:     regexp.MustCompile(`eval\s*\(.*document\.(location|URL)`),
			description: "Dangerous eval() with user-controlled data",
			risk:        "Critical",
		},
	}
	
	for _, domPattern := range domPatterns {
		if domPattern.pattern.MatchString(responseBody) {
			matches := domPattern.pattern.FindAllString(responseBody, -1)
			for _, match := range matches {
				vuln := &models.Vulnerability{
					ID:          fmt.Sprintf("xss-dom-%d", time.Now().Unix()),
					Type:        "Cross-Site Scripting (DOM)",
					Severity:    domPattern.risk,
					Title:       "Potential DOM-based XSS vulnerability",
					Description: domPattern.description,
					URL:         target.URL,
					Evidence:    match,
					Impact:      "Client-side JavaScript code may be vulnerable to DOM-based XSS attacks.",
					Remediation: "Review JavaScript code for unsafe DOM manipulation and implement proper sanitization.",
					Risk:        domPattern.risk,
					Confidence:  60, // Lower confidence as this requires manual verification
					Timestamp:   time.Now(),
				}
				
				vulnerabilities = append(vulnerabilities, vuln)
			}
		}
	}
	
	return vulnerabilities, nil
}

func (xs *XSSScanner) isXSSVulnerable(payload, responseBody string, headers http.Header) bool {
	// Check if payload is reflected without proper encoding
	if !strings.Contains(responseBody, payload) {
		return false
	}
	
	// Check for various contexts where XSS can occur
	contexts := []struct {
		pattern     *regexp.Regexp
		description string
	}{
		{regexp.MustCompile(fmt.Sprintf(`>%s<`, regexp.QuoteMeta(payload))), "HTML content"},
		{regexp.MustCompile(fmt.Sprintf(`=['"]%s['"]`, regexp.QuoteMeta(payload))), "Attribute value"},
		{regexp.MustCompile(fmt.Sprintf(`<script[^>]*>.*%s.*</script>`, regexp.QuoteMeta(payload))), "Script context"},
		{regexp.MustCompile(fmt.Sprintf(`javascript:.*%s`, regexp.QuoteMeta(payload))), "JavaScript URI"},
	}
	
	for _, context := range contexts {
		if context.pattern.MatchString(responseBody) {
			// Additional checks for actual XSS potential
			if xs.isExecutableContext(payload, responseBody) {
				return true
			}
		}
	}
	
	return false
}

func (xs *XSSScanner) isExecutableContext(payload, responseBody string) bool {
	// Check if the payload appears in an executable context
	executable := []string{
		"<script", "onerror=", "onload=", "onclick=", "javascript:",
		"<img", "<iframe", "<object", "<embed",
	}
	
	for _, exec := range executable {
		if strings.Contains(strings.ToLower(payload), strings.ToLower(exec)) {
			return true
		}
	}
	
	return false
}

func (xs *XSSScanner) calculateXSSSeverity(payload XSSPayload, resp *http.Response) string {
	if payload.Dangerous {
		return "High"
	}
	
	// Check for security headers that might mitigate XSS
	if csp := resp.Header.Get("Content-Security-Policy"); csp != "" {
		if strings.Contains(csp, "'unsafe-inline'") || strings.Contains(csp, "'unsafe-eval'") {
			return "Medium"
		}
		return "Low"
	}
	
	return "Medium"
}

func (xs *XSSScanner) calculateRisk(payload XSSPayload, resp *http.Response) string {
	return xs.calculateXSSSeverity(payload, resp)
}

func (xs *XSSScanner) calculateConfidence(payload XSSPayload, responseBody string) int {
	confidence := 50
	
	// Increase confidence if payload is clearly reflected
	if strings.Contains(responseBody, payload.Payload) {
		confidence += 30
	}
	
	// Increase confidence if payload appears in executable context
	if xs.isExecutableContext(payload.Payload, responseBody) {
		confidence += 20
	}
	
	if confidence > 100 {
		confidence = 100
	}
	
	return confidence
}

func (xs *XSSScanner) extractEvidence(payload, responseBody string) string {
	// Find and return the context where payload appears
	lines := strings.Split(responseBody, "\n")
	for i, line := range lines {
		if strings.Contains(line, payload) {
			evidence := fmt.Sprintf("Line %d: %s", i+1, strings.TrimSpace(line))
			if len(evidence) > 200 {
				evidence = evidence[:200] + "..."
			}
			return evidence
		}
	}
	return fmt.Sprintf("Payload '%s' found in response", payload)
}

func (xs *XSSScanner) generateXSSPoC(url, parameter, payload, method string) string {
	if method == "POST" {
		return fmt.Sprintf(`curl -X POST "%s" -d "%s=%s"`, url, parameter, url.QueryEscape(payload))
	}
	
	parsedURL, err := url.Parse(url)
	if err != nil {
		return fmt.Sprintf("GET %s?%s=%s", url, parameter, url.QueryEscape(payload))
	}
	
	params := parsedURL.Query()
	params.Set(parameter, payload)
	parsedURL.RawQuery = params.Encode()
	
	return fmt.Sprintf("GET %s", parsedURL.String())
}

func (xs *XSSScanner) submitFormWithPayload(ctx context.Context, target *models.Target, form models.Form, payload string, config *models.ScanConfig) error {
	// Build form data with payload in all text inputs
	formData := url.Values{}
	for _, input := range form.Inputs {
		if input.Type == "text" || input.Type == "textarea" || input.Type == "" {
			formData.Set(input.Name, payload)
		} else if input.Value != "" {
			formData.Set(input.Name, input.Value)
		}
	}
	
	// Determine form action URL
	actionURL := form.Action
	if actionURL == "" {
		actionURL = target.URL
	}
	
	// Submit form
	req, err := http.NewRequestWithContext(ctx, strings.ToUpper(form.Method), actionURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return err
	}
	
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", config.UserAgent)
	
	resp, err := xs.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	return nil
}

func (xs *XSSScanner) checkForStoredPayload(ctx context.Context, url, uniqueID string, config *models.ScanConfig) bool {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false
	}
	
	req.Header.Set("User-Agent", config.UserAgent)
	
	resp, err := xs.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	
	body := make([]byte, xs.config.Scanning.MaxBodySize)
	n, _ := resp.Body.Read(body)
	responseBody := string(body[:n])
	
	return strings.Contains(responseBody, uniqueID)
}

func (xs *XSSScanner) isAuthenticationForm(form models.Form) bool {
	// Check if form looks like a login/authentication form
	for _, input := range form.Inputs {
		name := strings.ToLower(input.Name)
		if strings.Contains(name, "password") || strings.Contains(name, "login") {
			return true
		}
	}
	return false
}

func loadXSSPayloads() []XSSPayload {
	return []XSSPayload{
		{
			Payload:     "<script>alert('XSS')</script>",
			Type:        "all",
			Context:     "html",
			Description: "Basic script tag",
			Dangerous:   true,
		},
		{
			Payload:     "'><script>alert('XSS')</script>",
			Type:        "all",
			Context:     "attribute",
			Description: "Attribute escape",
			Dangerous:   true,
		},
		{
			Payload:     "\"><script>alert('XSS')</script>",
			Type:        "all",
			Context:     "attribute",
			Description: "Double quote escape",
			Dangerous:   true,
		},
		{
			Payload:     "<img src=x onerror=alert('XSS')>",
			Type:        "all",
			Context:     "html",
			Description: "Image onerror event",
			Dangerous:   true,
		},
		{
			Payload:     "<svg onload=alert('XSS')>",
			Type:        "all",
			Context:     "html",
			Description: "SVG onload event",
			Dangerous:   true,
		},
		{
			Payload:     "javascript:alert('XSS')",
			Type:        "all",
			Context:     "href",
			Description: "JavaScript URI",
			Dangerous:   true,
		},
		{
			Payload:     "<iframe src=javascript:alert('XSS')>",
			Type:        "all",
			Context:     "html",
			Description: "Iframe JavaScript URI",
			Dangerous:   true,
		},
		{
			Payload:     "<body onload=alert('XSS')>",
			Type:        "all",
			Context:     "html",
			Description: "Body onload event",
			Dangerous:   true,
		},
		{
			Payload:     "<input onfocus=alert('XSS') autofocus>",
			Type:        "all",
			Context:     "html",
			Description: "Input onfocus with autofocus",
			Dangerous:   true,
		},
		{
			Payload:     "<select onfocus=alert('XSS') autofocus>",
			Type:        "all",
			Context:     "html",
			Description: "Select onfocus with autofocus",
			Dangerous:   true,
		},
	}
}
