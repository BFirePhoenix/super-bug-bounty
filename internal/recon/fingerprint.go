package recon

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/bugbounty-tool/internal/config"
	"github.com/bugbounty-tool/internal/logger"
	"github.com/bugbounty-tool/pkg/models"
)

// TechnologyFingerprinter identifies web technologies and frameworks
type TechnologyFingerprinter struct {
	config      *config.Config
	log         logger.Logger
	client      *http.Client
	
	// Technology detection rules
	rules       []FingerprintRule
	headerRules []HeaderRule
	bodyRules   []BodyRule
}

type FingerprintRule struct {
	Technology string            `json:"technology"`
	Confidence int               `json:"confidence"`
	Headers    map[string]string `json:"headers"`
	Body       []string          `json:"body"`
	Meta       []string          `json:"meta"`
	Scripts    []string          `json:"scripts"`
	Cookies    []string          `json:"cookies"`
	URL        []string          `json:"url"`
}

type HeaderRule struct {
	Header     string
	Pattern    *regexp.Regexp
	Technology string
	Confidence int
}

type BodyRule struct {
	Pattern    *regexp.Regexp
	Technology string
	Confidence int
}

// NewTechnologyFingerprinter creates a new technology fingerprinting engine
func NewTechnologyFingerprinter(cfg *config.Config, log logger.Logger) *TechnologyFingerprinter {
	tf := &TechnologyFingerprinter{
		config: cfg,
		log:    log,
		client: &http.Client{
			Timeout: time.Duration(cfg.Scanning.DefaultTimeout) * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: !cfg.Scanning.VerifySSL,
				},
			},
		},
	}
	
	// Load detection rules
	tf.loadDetectionRules()
	
	return tf
}

// FingerprintTechnologies identifies technologies used by a target
func (tf *TechnologyFingerprinter) FingerprintTechnologies(ctx context.Context, target string) (*models.TechnologyProfile, error) {
	tf.log.Info("Starting technology fingerprinting", "target", target)
	
	profile := &models.TechnologyProfile{
		Target:       target,
		Technologies: make([]models.Technology, 0),
		StartTime:    time.Now(),
	}
	
	// Ensure target has scheme
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}
	
	// Perform HTTP request to gather information
	resp, err := tf.makeRequest(ctx, target)
	if err != nil {
		// Try HTTP if HTTPS fails
		if strings.HasPrefix(target, "https://") {
			target = strings.Replace(target, "https://", "http://", 1)
			resp, err = tf.makeRequest(ctx, target)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to connect to target: %w", err)
		}
	}
	defer resp.Body.Close()
	
	// Read response body
	body := make([]byte, tf.config.Scanning.MaxBodySize)
	n, _ := resp.Body.Read(body)
	bodyContent := string(body[:n])
	
	// Analyze headers
	tf.analyzeHeaders(resp.Header, profile)
	
	// Analyze body content
	tf.analyzeBody(bodyContent, profile)
	
	// Analyze cookies
	tf.analyzeCookies(resp.Cookies(), profile)
	
	// Analyze SSL/TLS if HTTPS
	if strings.HasPrefix(target, "https://") {
		tf.analyzeSSL(resp.TLS, profile)
	}
	
	// Perform additional specialized scans
	tf.scanForFrameworks(ctx, target, profile)
	tf.scanForCMS(ctx, target, profile)
	tf.scanForWAF(ctx, target, profile)
	
	profile.EndTime = time.Now()
	profile.Duration = profile.EndTime.Sub(profile.StartTime)
	
	tf.log.Info("Technology fingerprinting completed",
		"target", target,
		"technologies_found", len(profile.Technologies),
		"duration", profile.Duration)
	
	return profile, nil
}

func (tf *TechnologyFingerprinter) makeRequest(ctx context.Context, target string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return nil, err
	}
	
	// Set headers to mimic a real browser
	req.Header.Set("User-Agent", tf.config.Scanning.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Connection", "keep-alive")
	
	return tf.client.Do(req)
}

func (tf *TechnologyFingerprinter) analyzeHeaders(headers http.Header, profile *models.TechnologyProfile) {
	for _, rule := range tf.headerRules {
		if headerValue := headers.Get(rule.Header); headerValue != "" {
			if rule.Pattern.MatchString(headerValue) {
				tf.addTechnology(profile, rule.Technology, rule.Confidence, "header", 
					fmt.Sprintf("%s: %s", rule.Header, headerValue))
			}
		}
	}
	
	// Common header-based detections
	if server := headers.Get("Server"); server != "" {
		tf.detectServerTechnology(server, profile)
	}
	
	if powered := headers.Get("X-Powered-By"); powered != "" {
		tf.detectPoweredByTechnology(powered, profile)
	}
	
	// Security headers analysis
	tf.analyzeSecurityHeaders(headers, profile)
}

func (tf *TechnologyFingerprinter) analyzeBody(body string, profile *models.TechnologyProfile) {
	for _, rule := range tf.bodyRules {
		if rule.Pattern.MatchString(body) {
			tf.addTechnology(profile, rule.Technology, rule.Confidence, "body", 
				rule.Pattern.FindString(body))
		}
	}
	
	// Meta tag analysis
	tf.analyzeMetaTags(body, profile)
	
	// Script analysis
	tf.analyzeScripts(body, profile)
	
	// CSS analysis
	tf.analyzeCSS(body, profile)
	
	// Form analysis
	tf.analyzeForms(body, profile)
}

func (tf *TechnologyFingerprinter) analyzeCookies(cookies []*http.Cookie, profile *models.TechnologyProfile) {
	for _, cookie := range cookies {
		// Common cookie-based detections
		switch {
		case strings.Contains(cookie.Name, "PHPSESSID"):
			tf.addTechnology(profile, "PHP", 90, "cookie", cookie.Name)
		case strings.Contains(cookie.Name, "JSESSIONID"):
			tf.addTechnology(profile, "Java", 90, "cookie", cookie.Name)
		case strings.Contains(cookie.Name, "ASP.NET_SessionId"):
			tf.addTechnology(profile, "ASP.NET", 90, "cookie", cookie.Name)
		case strings.Contains(cookie.Name, "CFID") || strings.Contains(cookie.Name, "CFTOKEN"):
			tf.addTechnology(profile, "ColdFusion", 90, "cookie", cookie.Name)
		case strings.Contains(cookie.Name, "laravel_session"):
			tf.addTechnology(profile, "Laravel", 90, "cookie", cookie.Name)
		case strings.Contains(cookie.Name, "django"):
			tf.addTechnology(profile, "Django", 90, "cookie", cookie.Name)
		}
	}
}

func (tf *TechnologyFingerprinter) analyzeSSL(tlsState *tls.ConnectionState, profile *models.TechnologyProfile) {
	if tlsState == nil {
		return
	}
	
	// TLS version detection
	switch tlsState.Version {
	case tls.VersionTLS10:
		tf.addTechnology(profile, "TLS 1.0", 100, "ssl", "TLS Version")
	case tls.VersionTLS11:
		tf.addTechnology(profile, "TLS 1.1", 100, "ssl", "TLS Version")
	case tls.VersionTLS12:
		tf.addTechnology(profile, "TLS 1.2", 100, "ssl", "TLS Version")
	case tls.VersionTLS13:
		tf.addTechnology(profile, "TLS 1.3", 100, "ssl", "TLS Version")
	}
	
	// Certificate analysis
	if len(tlsState.PeerCertificates) > 0 {
		cert := tlsState.PeerCertificates[0]
		
		// Certificate authority detection
		if strings.Contains(cert.Issuer.String(), "Let's Encrypt") {
			tf.addTechnology(profile, "Let's Encrypt", 100, "ssl", "Certificate Issuer")
		} else if strings.Contains(cert.Issuer.String(), "Cloudflare") {
			tf.addTechnology(profile, "Cloudflare", 100, "ssl", "Certificate Issuer")
		}
	}
}

func (tf *TechnologyFingerprinter) scanForFrameworks(ctx context.Context, target string, profile *models.TechnologyProfile) {
	// Common framework detection endpoints
	frameworkPaths := map[string]string{
		"WordPress":   "/wp-admin/",
		"Drupal":      "/user/login",
		"Joomla":      "/administrator/",
		"Magento":     "/admin/",
		"PrestaShop":  "/admin123/",
		"Django":      "/admin/",
		"Laravel":     "/login",
		"Symfony":     "/app_dev.php/",
		"CodeIgniter": "/system/",
		"Zend":        "/public/",
	}
	
	for framework, path := range frameworkPaths {
		testURL := strings.TrimSuffix(target, "/") + path
		if tf.testEndpoint(ctx, testURL) {
			tf.addTechnology(profile, framework, 80, "endpoint", path)
		}
	}
}

func (tf *TechnologyFingerprinter) scanForCMS(ctx context.Context, target string, profile *models.TechnologyProfile) {
	// CMS-specific file detection
	cmsFiles := map[string][]string{
		"WordPress": {
			"/wp-config.php",
			"/wp-content/",
			"/wp-includes/",
			"/readme.html",
		},
		"Drupal": {
			"/CHANGELOG.txt",
			"/COPYRIGHT.txt",
			"/sites/default/",
		},
		"Joomla": {
			"/administrator/",
			"/language/en-GB/",
			"/templates/",
		},
	}
	
	for cms, files := range cmsFiles {
		detected := 0
		for _, file := range files {
			testURL := strings.TrimSuffix(target, "/") + file
			if tf.testEndpoint(ctx, testURL) {
				detected++
			}
		}
		
		if detected > 0 {
			confidence := min(90, detected*30)
			tf.addTechnology(profile, cms, confidence, "cms", fmt.Sprintf("%d files detected", detected))
		}
	}
}

func (tf *TechnologyFingerprinter) scanForWAF(ctx context.Context, target string, profile *models.TechnologyProfile) {
	// WAF detection using specific payloads
	wafPayloads := []string{
		"?test=<script>alert(1)</script>",
		"?test=' OR 1=1--",
		"?test=../../../../etc/passwd",
	}
	
	for _, payload := range wafPayloads {
		testURL := target + payload
		resp, err := tf.makeRequest(ctx, testURL)
		if err != nil {
			continue
		}
		resp.Body.Close()
		
		// Check for WAF indicators in response
		tf.detectWAFFromResponse(resp, profile)
	}
}

func (tf *TechnologyFingerprinter) detectServerTechnology(server string, profile *models.TechnologyProfile) {
	server = strings.ToLower(server)
	
	serverMappings := map[string]string{
		"apache":     "Apache",
		"nginx":      "Nginx",
		"iis":        "IIS",
		"cloudflare": "Cloudflare",
		"aws":        "AWS",
		"gws":        "Google Web Server",
	}
	
	for key, tech := range serverMappings {
		if strings.Contains(server, key) {
			tf.addTechnology(profile, tech, 90, "server", server)
		}
	}
}

func (tf *TechnologyFingerprinter) detectPoweredByTechnology(powered string, profile *models.TechnologyProfile) {
	powered = strings.ToLower(powered)
	
	poweredMappings := map[string]string{
		"php":        "PHP",
		"asp.net":    "ASP.NET",
		"express":    "Express.js",
		"django":     "Django",
		"rails":      "Ruby on Rails",
		"laravel":    "Laravel",
		"wordpress":  "WordPress",
	}
	
	for key, tech := range poweredMappings {
		if strings.Contains(powered, key) {
			tf.addTechnology(profile, tech, 95, "powered-by", powered)
		}
	}
}

func (tf *TechnologyFingerprinter) analyzeSecurityHeaders(headers http.Header, profile *models.TechnologyProfile) {
	securityHeaders := []string{
		"Content-Security-Policy",
		"X-Frame-Options",
		"X-XSS-Protection",
		"X-Content-Type-Options",
		"Strict-Transport-Security",
		"Referrer-Policy",
		"Feature-Policy",
		"Permissions-Policy",
	}
	
	for _, header := range securityHeaders {
		if value := headers.Get(header); value != "" {
			tf.addTechnology(profile, "Security Headers", 70, "security", 
				fmt.Sprintf("%s: %s", header, value))
		}
	}
}

func (tf *TechnologyFingerprinter) analyzeMetaTags(body string, profile *models.TechnologyProfile) {
	// Meta generator detection
	generatorRegex := regexp.MustCompile(`<meta[^>]*name=['"]generator['"][^>]*content=['"]([^'"]+)['"]`)
	matches := generatorRegex.FindAllStringSubmatch(body, -1)
	
	for _, match := range matches {
		if len(match) > 1 {
			generator := match[1]
			tf.detectGeneratorTechnology(generator, profile)
		}
	}
}

func (tf *TechnologyFingerprinter) analyzeScripts(body string, profile *models.TechnologyProfile) {
	// JavaScript library detection
	scriptRegex := regexp.MustCompile(`<script[^>]*src=['"]([^'"]+)['"]`)
	matches := scriptRegex.FindAllStringSubmatch(body, -1)
	
	jsLibraries := map[string]string{
		"jquery":     "jQuery",
		"bootstrap":  "Bootstrap",
		"angular":    "AngularJS",
		"react":      "React",
		"vue":        "Vue.js",
		"backbone":   "Backbone.js",
		"ember":      "Ember.js",
		"lodash":     "Lodash",
		"underscore": "Underscore.js",
	}
	
	for _, match := range matches {
		if len(match) > 1 {
			src := strings.ToLower(match[1])
			for lib, tech := range jsLibraries {
				if strings.Contains(src, lib) {
					tf.addTechnology(profile, tech, 80, "script", src)
				}
			}
		}
	}
}

func (tf *TechnologyFingerprinter) analyzeCSS(body string, profile *models.TechnologyProfile) {
	// CSS framework detection
	linkRegex := regexp.MustCompile(`<link[^>]*href=['"]([^'"]+)['"]`)
	matches := linkRegex.FindAllStringSubmatch(body, -1)
	
	cssFrameworks := map[string]string{
		"bootstrap":   "Bootstrap",
		"foundation":  "Foundation",
		"bulma":       "Bulma",
		"materialize": "Materialize",
		"semantic":    "Semantic UI",
	}
	
	for _, match := range matches {
		if len(match) > 1 {
			href := strings.ToLower(match[1])
			for framework, tech := range cssFrameworks {
				if strings.Contains(href, framework) {
					tf.addTechnology(profile, tech, 75, "css", href)
				}
			}
		}
	}
}

func (tf *TechnologyFingerprinter) analyzeForms(body string, profile *models.TechnologyProfile) {
	// CSRF token detection
	csrfRegex := regexp.MustCompile(`<input[^>]*name=['"](_token|csrf_token|authenticity_token)['"]`)
	if csrfRegex.MatchString(body) {
		tf.addTechnology(profile, "CSRF Protection", 60, "form", "CSRF token detected")
	}
}

func (tf *TechnologyFingerprinter) detectGeneratorTechnology(generator string, profile *models.TechnologyProfile) {
	generator = strings.ToLower(generator)
	
	generatorMappings := map[string]string{
		"wordpress":  "WordPress",
		"drupal":     "Drupal",
		"joomla":     "Joomla",
		"wix":        "Wix",
		"squarespace": "Squarespace",
		"shopify":    "Shopify",
	}
	
	for key, tech := range generatorMappings {
		if strings.Contains(generator, key) {
			tf.addTechnology(profile, tech, 95, "meta", generator)
		}
	}
}

func (tf *TechnologyFingerprinter) detectWAFFromResponse(resp *http.Response, profile *models.TechnologyProfile) {
	// WAF detection based on headers and status codes
	wafHeaders := map[string]string{
		"cf-ray":         "Cloudflare",
		"x-sucuri-id":    "Sucuri",
		"x-fw-hash":      "Fortinet",
		"x-protected-by": "Unknown WAF",
	}
	
	for header, waf := range wafHeaders {
		if resp.Header.Get(header) != "" {
			tf.addTechnology(profile, waf+" WAF", 90, "waf", header)
		}
	}
	
	// Status code based detection
	if resp.StatusCode == 406 || resp.StatusCode == 429 {
		tf.addTechnology(profile, "WAF/Rate Limiting", 70, "waf", 
			fmt.Sprintf("Status Code: %d", resp.StatusCode))
	}
}

func (tf *TechnologyFingerprinter) testEndpoint(ctx context.Context, url string) bool {
	resp, err := tf.makeRequest(ctx, url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	
	// Consider 200, 301, 302, 403 as positive indicators
	return resp.StatusCode == 200 || resp.StatusCode == 301 || 
		   resp.StatusCode == 302 || resp.StatusCode == 403
}

func (tf *TechnologyFingerprinter) addTechnology(profile *models.TechnologyProfile, name string, confidence int, source, evidence string) {
	// Check if technology already exists
	for i, tech := range profile.Technologies {
		if tech.Name == name {
			// Update confidence if higher
			if confidence > tech.Confidence {
				profile.Technologies[i].Confidence = confidence
				profile.Technologies[i].Evidence = append(tech.Evidence, evidence)
			}
			return
		}
	}
	
	// Add new technology
	tech := models.Technology{
		Name:       name,
		Confidence: confidence,
		Source:     source,
		Evidence:   []string{evidence},
		Timestamp:  time.Now(),
	}
	
	profile.Technologies = append(profile.Technologies, tech)
}

func (tf *TechnologyFingerprinter) loadDetectionRules() {
	// Load Wappalyzer-style rules from embedded data or files
	tf.rules = []FingerprintRule{
		// Example rules - in production, load from comprehensive rule files
		{
			Technology: "WordPress",
			Confidence: 100,
			Headers:    map[string]string{"link": "wp-content"},
			Body:       []string{"wp-content", "wp-includes"},
		},
		{
			Technology: "jQuery",
			Confidence: 100,
			Scripts:    []string{"jquery"},
		},
	}
	
	// Compile regex patterns for header rules
	tf.headerRules = []HeaderRule{
		{
			Header:     "Server",
			Pattern:    regexp.MustCompile(`(?i)apache`),
			Technology: "Apache",
			Confidence: 90,
		},
		{
			Header:     "Server",
			Pattern:    regexp.MustCompile(`(?i)nginx`),
			Technology: "Nginx",
			Confidence: 90,
		},
	}
	
	// Compile regex patterns for body rules
	tf.bodyRules = []BodyRule{
		{
			Pattern:    regexp.MustCompile(`(?i)wp-content`),
			Technology: "WordPress",
			Confidence: 95,
		},
		{
			Pattern:    regexp.MustCompile(`(?i)powered by drupal`),
			Technology: "Drupal",
			Confidence: 100,
		},
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
