package vuln

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/bugbounty-tool/internal/config"
	"github.com/bugbounty-tool/internal/logger"
	"github.com/bugbounty-tool/pkg/models"
	"github.com/bugbounty-tool/pkg/utils"
)

// CORSScanner detects CORS misconfiguration vulnerabilities
type CORSScanner struct {
	config *config.Config
	log    logger.Logger
	client *http.Client
}

type CORSTest struct {
	Origin          string
	Description     string
	ExpectedAllowed bool
	Severity        string
}

// NewCORSScanner creates a new CORS vulnerability scanner
func NewCORSScanner(cfg *config.Config, log logger.Logger) *CORSScanner {
	return &CORSScanner{
		config: cfg,
		log:    log,
		client: utils.NewHTTPClient(cfg),
	}
}

// ScanForCORS performs comprehensive CORS misconfiguration scanning
func (cs *CORSScanner) ScanForCORS(ctx context.Context, target *models.Target, config *models.ScanConfig) ([]*models.Vulnerability, error) {
	cs.log.Info("Starting CORS vulnerability scan", "target", target.URL)
	
	vulnerabilities := make([]*models.Vulnerability, 0)
	
	// Define test origins for CORS bypass attempts
	testOrigins := cs.generateTestOrigins(target.URL)
	
	for _, testOrigin := range testOrigins {
		vuln, err := cs.testCORSOrigin(ctx, target, testOrigin, config)
		if err != nil {
			cs.log.Error("CORS test failed", "origin", testOrigin.Origin, "error", err)
			continue
		}
		
		if vuln != nil {
			vulnerabilities = append(vulnerabilities, vuln)
		}
	}
	
	// Test for null origin bypass
	if nullVuln := cs.testNullOrigin(ctx, target, config); nullVuln != nil {
		vulnerabilities = append(vulnerabilities, nullVuln)
	}
	
	// Test for wildcard misconfigurations
	if wildcardVuln := cs.testWildcardMisconfiguration(ctx, target, config); wildcardVuln != nil {
		vulnerabilities = append(vulnerabilities, wildcardVuln)
	}
	
	// Test for credential exposure
	if credVuln := cs.testCredentialExposure(ctx, target, config); credVuln != nil {
		vulnerabilities = append(vulnerabilities, credVuln)
	}
	
	cs.log.Info("CORS scan completed",
		"target", target.URL,
		"vulnerabilities_found", len(vulnerabilities))
	
	return vulnerabilities, nil
}

func (cs *CORSScanner) generateTestOrigins(targetURL string) []CORSTest {
	// Extract domain from target URL
	domain := cs.extractDomain(targetURL)
	
	return []CORSTest{
		{
			Origin:          "https://evil.com",
			Description:     "External malicious domain",
			ExpectedAllowed: false,
			Severity:        "High",
		},
		{
			Origin:          "https://attacker.evil.com",
			Description:     "Subdomain of malicious domain",
			ExpectedAllowed: false,
			Severity:        "High",
		},
		{
			Origin:          fmt.Sprintf("https://%s.evil.com", domain),
			Description:     "Domain as subdomain of malicious domain",
			ExpectedAllowed: false,
			Severity:        "High",
		},
		{
			Origin:          fmt.Sprintf("https://evil%s", domain),
			Description:     "Domain with malicious prefix",
			ExpectedAllowed: false,
			Severity:        "Medium",
		},
		{
			Origin:          fmt.Sprintf("https://%sevil.com", domain),
			Description:     "Domain with malicious suffix",
			ExpectedAllowed: false,
			Severity:        "Medium",
		},
		{
			Origin:          fmt.Sprintf("https://%s.evil.com", strings.Replace(domain, ".", "", -1)),
			Description:     "Domain without dots as subdomain",
			ExpectedAllowed: false,
			Severity:        "Medium",
		},
		{
			Origin:          "https://127.0.0.1",
			Description:     "Localhost IP",
			ExpectedAllowed: false,
			Severity:        "Medium",
		},
		{
			Origin:          "https://localhost",
			Description:     "Localhost domain",
			ExpectedAllowed: false,
			Severity:        "Medium",
		},
		{
			Origin:          "file://",
			Description:     "File protocol",
			ExpectedAllowed: false,
			Severity:        "Low",
		},
		{
			Origin:          "data://text/html,<script>alert(1)</script>",
			Description:     "Data URI",
			ExpectedAllowed: false,
			Severity:        "Medium",
		},
	}
}

func (cs *CORSScanner) testCORSOrigin(ctx context.Context, target *models.Target, test CORSTest, config *models.ScanConfig) (*models.Vulnerability, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", target.URL, nil)
	if err != nil {
		return nil, err
	}
	
	// Set Origin header
	req.Header.Set("Origin", test.Origin)
	req.Header.Set("User-Agent", config.UserAgent)
	
	// Add custom headers if provided
	if config.Headers != nil {
		for k, v := range config.Headers {
			req.Header.Set(k, v)
		}
	}
	
	resp, err := cs.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	// Check CORS headers in response
	accessControlAllowOrigin := resp.Header.Get("Access-Control-Allow-Origin")
	accessControlAllowCredentials := resp.Header.Get("Access-Control-Allow-Credentials")
	
	// Analyze CORS configuration
	isVulnerable := false
	vulnType := ""
	severity := "Low"
	
	if accessControlAllowOrigin == test.Origin {
		isVulnerable = true
		vulnType = "Origin Reflection"
		severity = test.Severity
	} else if accessControlAllowOrigin == "*" && accessControlAllowCredentials == "true" {
		isVulnerable = true
		vulnType = "Wildcard with Credentials"
		severity = "High"
	} else if accessControlAllowOrigin == "*" {
		isVulnerable = true
		vulnType = "Wildcard Origin"
		severity = "Medium"
	}
	
	if isVulnerable {
		vuln := &models.Vulnerability{
			ID:          fmt.Sprintf("cors-%s-%d", strings.ToLower(vulnType), time.Now().Unix()),
			Type:        "CORS Misconfiguration",
			Severity:    severity,
			Title:       fmt.Sprintf("CORS misconfiguration: %s", vulnType),
			Description: cs.buildCORSDescription(vulnType, test, accessControlAllowOrigin, accessControlAllowCredentials),
			URL:         target.URL,
			Method:      "GET",
			Evidence:    cs.buildCORSEvidence(test.Origin, accessControlAllowOrigin, accessControlAllowCredentials),
			Impact:      cs.buildCORSImpact(vulnType),
			Remediation: cs.buildCORSRemediation(vulnType),
			References: []string{
				"https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny",
				"https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
				"https://portswigger.net/web-security/cors",
			},
			Risk:        severity,
			Confidence:  cs.calculateCORSConfidence(vulnType),
			Timestamp:   time.Now(),
		}
		
		vuln.ProofOfConcept = cs.generateCORSPoC(target.URL, test.Origin)
		return vuln, nil
	}
	
	return nil, nil
}

func (cs *CORSScanner) testNullOrigin(ctx context.Context, target *models.Target, config *models.ScanConfig) *models.Vulnerability {
	req, err := http.NewRequestWithContext(ctx, "GET", target.URL, nil)
	if err != nil {
		return nil
	}
	
	req.Header.Set("Origin", "null")
	req.Header.Set("User-Agent", config.UserAgent)
	
	resp, err := cs.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	
	accessControlAllowOrigin := resp.Header.Get("Access-Control-Allow-Origin")
	accessControlAllowCredentials := resp.Header.Get("Access-Control-Allow-Credentials")
	
	if accessControlAllowOrigin == "null" {
		vuln := &models.Vulnerability{
			ID:          fmt.Sprintf("cors-null-%d", time.Now().Unix()),
			Type:        "CORS Misconfiguration",
			Severity:    "Medium",
			Title:       "CORS allows null origin",
			Description: "The application allows requests from null origin, which can be exploited by attackers using data URIs or sandboxed iframes.",
			URL:         target.URL,
			Method:      "GET",
			Evidence:    fmt.Sprintf("Origin: null → Access-Control-Allow-Origin: %s", accessControlAllowOrigin),
			Impact:      "Attackers can bypass CORS restrictions using null origin from data URIs, sandboxed iframes, or file:// protocol.",
			Remediation: "Remove 'null' from allowed origins. Implement proper origin validation.",
			Risk:        "Medium",
			Confidence:  90,
			Timestamp:   time.Now(),
		}
		
		if accessControlAllowCredentials == "true" {
			vuln.Severity = "High"
			vuln.Risk = "High"
			vuln.Description += " Credentials are also allowed, making this a high-risk vulnerability."
		}
		
		return vuln
	}
	
	return nil
}

func (cs *CORSScanner) testWildcardMisconfiguration(ctx context.Context, target *models.Target, config *models.ScanConfig) *models.Vulnerability {
	req, err := http.NewRequestWithContext(ctx, "GET", target.URL, nil)
	if err != nil {
		return nil
	}
	
	req.Header.Set("Origin", "https://evil.com")
	req.Header.Set("User-Agent", config.UserAgent)
	
	resp, err := cs.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	
	accessControlAllowOrigin := resp.Header.Get("Access-Control-Allow-Origin")
	accessControlAllowCredentials := resp.Header.Get("Access-Control-Allow-Credentials")
	
	if accessControlAllowOrigin == "*" && accessControlAllowCredentials == "true" {
		return &models.Vulnerability{
			ID:          fmt.Sprintf("cors-wildcard-creds-%d", time.Now().Unix()),
			Type:        "CORS Misconfiguration",
			Severity:    "High",
			Title:       "CORS wildcard with credentials enabled",
			Description: "The application uses wildcard (*) in Access-Control-Allow-Origin with credentials enabled, which is a dangerous misconfiguration.",
			URL:         target.URL,
			Method:      "GET",
			Evidence:    fmt.Sprintf("Access-Control-Allow-Origin: %s, Access-Control-Allow-Credentials: %s", accessControlAllowOrigin, accessControlAllowCredentials),
			Impact:      "Any website can make credentialed requests to the application, potentially accessing sensitive user data.",
			Remediation: "Either remove wildcard and specify exact origins, or disable credentials (set Access-Control-Allow-Credentials to false).",
			Risk:        "High",
			Confidence:  95,
			Timestamp:   time.Now(),
		}
	}
	
	return nil
}

func (cs *CORSScanner) testCredentialExposure(ctx context.Context, target *models.Target, config *models.ScanConfig) *models.Vulnerability {
	// Test if credentials are exposed through CORS
	req, err := http.NewRequestWithContext(ctx, "GET", target.URL, nil)
	if err != nil {
		return nil
	}
	
	req.Header.Set("Origin", "https://evil.com")
	req.Header.Set("User-Agent", config.UserAgent)
	req.Header.Set("Cookie", "test=value") // Simulate having cookies
	
	resp, err := cs.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	
	accessControlAllowCredentials := resp.Header.Get("Access-Control-Allow-Credentials")
	accessControlExposeHeaders := resp.Header.Get("Access-Control-Expose-Headers")
	
	// Check if sensitive headers are exposed
	sensitiveHeaders := []string{"authorization", "cookie", "set-cookie", "x-auth-token", "x-api-key"}
	exposedSensitive := false
	
	if accessControlExposeHeaders != "" {
		exposedHeadersLower := strings.ToLower(accessControlExposeHeaders)
		for _, sensitive := range sensitiveHeaders {
			if strings.Contains(exposedHeadersLower, sensitive) {
				exposedSensitive = true
				break
			}
		}
	}
	
	if accessControlAllowCredentials == "true" && exposedSensitive {
		return &models.Vulnerability{
			ID:          fmt.Sprintf("cors-credential-exposure-%d", time.Now().Unix()),
			Type:        "CORS Misconfiguration",
			Severity:    "Medium",
			Title:       "CORS exposes sensitive headers with credentials",
			Description: "The application allows credentials and exposes sensitive headers through CORS.",
			URL:         target.URL,
			Method:      "GET",
			Evidence:    fmt.Sprintf("Access-Control-Allow-Credentials: %s, Access-Control-Expose-Headers: %s", accessControlAllowCredentials, accessControlExposeHeaders),
			Impact:      "Sensitive authentication information may be accessible to cross-origin requests.",
			Remediation: "Review exposed headers and remove sensitive ones from Access-Control-Expose-Headers.",
			Risk:        "Medium",
			Confidence:  80,
			Timestamp:   time.Now(),
		}
	}
	
	return nil
}

func (cs *CORSScanner) extractDomain(url string) string {
	// Simple domain extraction
	if strings.HasPrefix(url, "http://") {
		url = url[7:]
	} else if strings.HasPrefix(url, "https://") {
		url = url[8:]
	}
	
	if idx := strings.Index(url, "/"); idx != -1 {
		url = url[:idx]
	}
	
	if idx := strings.Index(url, ":"); idx != -1 {
		url = url[:idx]
	}
	
	return url
}

func (cs *CORSScanner) buildCORSDescription(vulnType string, test CORSTest, allowOrigin, allowCredentials string) string {
	base := fmt.Sprintf("The application has a CORS misconfiguration of type '%s'. ", vulnType)
	
	switch vulnType {
	case "Origin Reflection":
		base += fmt.Sprintf("The application reflects the Origin header value (%s) in the Access-Control-Allow-Origin response header without proper validation.", test.Origin)
	case "Wildcard with Credentials":
		base += "The application uses wildcard (*) in Access-Control-Allow-Origin while also allowing credentials, which is prohibited by CORS specification."
	case "Wildcard Origin":
		base += "The application uses wildcard (*) in Access-Control-Allow-Origin, allowing any website to make requests."
	}
	
	if allowCredentials == "true" {
		base += " Credentials are also allowed, increasing the risk."
	}
	
	return base
}

func (cs *CORSScanner) buildCORSEvidence(origin, allowOrigin, allowCredentials string) string {
	evidence := fmt.Sprintf("Request Origin: %s → Response Access-Control-Allow-Origin: %s", origin, allowOrigin)
	if allowCredentials != "" {
		evidence += fmt.Sprintf(", Access-Control-Allow-Credentials: %s", allowCredentials)
	}
	return evidence
}

func (cs *CORSScanner) buildCORSImpact(vulnType string) string {
	switch vulnType {
	case "Origin Reflection":
		return "An attacker can make cross-origin requests from any domain and access the response data, potentially stealing sensitive information."
	case "Wildcard with Credentials":
		return "Any website can make credentialed requests to the application, potentially accessing sensitive user data and performing actions on behalf of users."
	case "Wildcard Origin":
		return "Any website can make cross-origin requests to the application, though without credentials, the impact is limited to public data."
	default:
		return "Cross-origin access controls are misconfigured, potentially allowing unauthorized access to resources."
	}
}

func (cs *CORSScanner) buildCORSRemediation(vulnType string) string {
	switch vulnType {
	case "Origin Reflection":
		return "Implement proper origin validation. Maintain a whitelist of allowed origins and validate against it before setting Access-Control-Allow-Origin."
	case "Wildcard with Credentials":
		return "Either specify exact allowed origins instead of wildcard, or disable credentials by removing Access-Control-Allow-Credentials header."
	case "Wildcard Origin":
		return "Replace wildcard with specific allowed origins. Implement origin validation and maintain a whitelist of trusted domains."
	default:
		return "Review and properly configure CORS headers. Implement strict origin validation and follow CORS best practices."
	}
}

func (cs *CORSScanner) calculateCORSConfidence(vulnType string) int {
	switch vulnType {
	case "Origin Reflection":
		return 95
	case "Wildcard with Credentials":
		return 100
	case "Wildcard Origin":
		return 90
	default:
		return 80
	}
}

func (cs *CORSScanner) generateCORSPoC(targetURL, origin string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>CORS PoC</title>
</head>
<body>
    <script>
        fetch('%s', {
            method: 'GET',
            credentials: 'include'
        })
        .then(response => response.text())
        .then(data => {
            console.log('CORS bypass successful!');
            console.log('Response:', data);
            document.body.innerHTML = '<h1>CORS Vulnerability Confirmed</h1><pre>' + data + '</pre>';
        })
        .catch(error => {
            console.error('CORS request failed:', error);
        });
    </script>
    <h1>CORS Proof of Concept</h1>
    <p>Origin: %s</p>
    <p>Target: %s</p>
    <p>Check console for results.</p>
</body>
</html>`, targetURL, origin, targetURL)
}
