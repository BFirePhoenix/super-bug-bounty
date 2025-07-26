package utils

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bugbounty-tool/internal/config"
)

// NewHTTPClient creates a new HTTP client with optimal settings for security testing
func NewHTTPClient(cfg *config.Config) *http.Client {
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: !cfg.Scanning.VerifySSL,
			MinVersion:         tls.VersionTLS10,
		},
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DisableKeepAlives:     false,
		DisableCompression:    false,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(cfg.Scanning.DefaultTimeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !cfg.Scanning.FollowRedirects {
				return http.ErrUseLastResponse
			}
			if len(via) >= cfg.Scanning.MaxRedirects {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	return client
}

// SafeRequest performs a safe HTTP request with proper error handling
func SafeRequest(client *http.Client, method, url string, headers map[string]string) (*http.Response, error) {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set default headers
	req.Header.Set("User-Agent", "BugBountyTool/1.0")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Connection", "close")

	// Add custom headers
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	return resp, nil
}

// GetRedirectChain follows redirects and returns the chain
func GetRedirectChain(client *http.Client, url string) ([]string, error) {
	var redirects []string
	
	// Create client that doesn't follow redirects
	noRedirectClient := &http.Client{
		Transport: client.Transport,
		Timeout:   client.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	currentURL := url
	for i := 0; i < 10; i++ { // Max 10 redirects
		resp, err := SafeRequest(noRedirectClient, "GET", currentURL, nil)
		if err != nil {
			break
		}
		defer resp.Body.Close()

		redirects = append(redirects, currentURL)

		if resp.StatusCode < 300 || resp.StatusCode >= 400 {
			break
		}

		location := resp.Header.Get("Location")
		if location == "" {
			break
		}

		// Handle relative URLs
		if !strings.HasPrefix(location, "http") {
			baseURL, err := url.Parse(currentURL)
			if err != nil {
				break
			}
			locationURL, err := url.Parse(location)
			if err != nil {
				break
			}
			location = baseURL.ResolveReference(locationURL).String()
		}

		currentURL = location
	}

	return redirects, nil
}

// IsValidURL checks if a URL is valid and reachable
func IsValidURL(urlStr string) bool {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return false
	}

	if parsedURL.Scheme == "" || parsedURL.Host == "" {
		return false
	}

	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return false
	}

	return true
}

// ExtractDomain extracts the domain from a URL
func ExtractDomain(urlStr string) string {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return ""
	}
	return parsedURL.Host
}

// NormalizeURL normalizes a URL by removing fragments and sorting query parameters
func NormalizeURL(urlStr string) string {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return urlStr
	}

	// Remove fragment
	parsedURL.Fragment = ""

	// Sort query parameters
	query := parsedURL.Query()
	parsedURL.RawQuery = query.Encode()

	return parsedURL.String()
}

// GetResponseFingerprint creates a fingerprint of an HTTP response
func GetResponseFingerprint(resp *http.Response, body []byte) string {
	fingerprint := fmt.Sprintf("status:%d", resp.StatusCode)
	
	if server := resp.Header.Get("Server"); server != "" {
		fingerprint += fmt.Sprintf(",server:%s", server)
	}
	
	if contentType := resp.Header.Get("Content-Type"); contentType != "" {
		fingerprint += fmt.Sprintf(",content-type:%s", contentType)
	}
	
	fingerprint += fmt.Sprintf(",content-length:%d", len(body))
	
	return fingerprint
}

// DetectWAF attempts to detect Web Application Firewall from response
func DetectWAF(resp *http.Response, body []byte) string {
	headers := resp.Header
	bodyStr := strings.ToLower(string(body))

	// Cloudflare
	if headers.Get("CF-RAY") != "" || headers.Get("CF-Cache-Status") != "" {
		return "Cloudflare"
	}

	// AWS WAF
	if headers.Get("X-Amzn-RequestId") != "" || strings.Contains(bodyStr, "request blocked") {
		return "AWS WAF"
	}

	// Akamai
	if headers.Get("X-Akamai-Request-ID") != "" {
		return "Akamai"
	}

	// Imperva/Incapsula
	if headers.Get("X-Iinfo") != "" || strings.Contains(bodyStr, "incapsula") {
		return "Imperva"
	}

	// ModSecurity
	if strings.Contains(bodyStr, "mod_security") || strings.Contains(bodyStr, "modsecurity") {
		return "ModSecurity"
	}

	// Sucuri
	if headers.Get("X-Sucuri-ID") != "" || strings.Contains(bodyStr, "sucuri") {
		return "Sucuri"
	}

	// Barracuda
	if strings.Contains(bodyStr, "barracuda") {
		return "Barracuda"
	}

	// F5 BIG-IP
	if headers.Get("X-WA-Info") != "" || strings.Contains(bodyStr, "f5") {
		return "F5 BIG-IP"
	}

	return ""
}

// TestConnectivity tests basic connectivity to a target
func TestConnectivity(target string, timeout time.Duration) error {
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	resp, err := client.Head(target)
	if err != nil {
		return fmt.Errorf("connectivity test failed: %w", err)
	}
	defer resp.Body.Close()

	return nil
}

// BuildURL builds a URL with query parameters
func BuildURL(baseURL string, params map[string]string) (string, error) {
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	query := parsedURL.Query()
	for key, value := range params {
		query.Set(key, value)
	}
	parsedURL.RawQuery = query.Encode()

	return parsedURL.String(), nil
}

// ParseUserAgent extracts information from User-Agent header
func ParseUserAgent(userAgent string) map[string]string {
	info := make(map[string]string)
	
	ua := strings.ToLower(userAgent)
	
	// Browser detection
	if strings.Contains(ua, "chrome") {
		info["browser"] = "Chrome"
	} else if strings.Contains(ua, "firefox") {
		info["browser"] = "Firefox"
	} else if strings.Contains(ua, "safari") {
		info["browser"] = "Safari"
	} else if strings.Contains(ua, "edge") {
		info["browser"] = "Edge"
	}
	
	// OS detection
	if strings.Contains(ua, "windows") {
		info["os"] = "Windows"
	} else if strings.Contains(ua, "macintosh") || strings.Contains(ua, "mac os") {
		info["os"] = "macOS"
	} else if strings.Contains(ua, "linux") {
		info["os"] = "Linux"
	} else if strings.Contains(ua, "android") {
		info["os"] = "Android"
	} else if strings.Contains(ua, "iphone") || strings.Contains(ua, "ipad") {
		info["os"] = "iOS"
	}
	
	return info
}

// GetSecurityHeaders analyzes security headers in HTTP response
func GetSecurityHeaders(headers http.Header) map[string]string {
	securityHeaders := map[string]string{
		"Content-Security-Policy":   "",
		"Strict-Transport-Security": "",
		"X-Frame-Options":          "",
		"X-Content-Type-Options":   "",
		"X-XSS-Protection":         "",
		"Referrer-Policy":          "",
		"Feature-Policy":           "",
		"Permissions-Policy":       "",
	}

	for header := range securityHeaders {
		if value := headers.Get(header); value != "" {
			securityHeaders[header] = value
		}
	}

	return securityHeaders
}

// RandomUserAgent returns a random realistic User-Agent string
func RandomUserAgent() string {
	userAgents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
	}
	
	return userAgents[time.Now().UnixNano()%int64(len(userAgents))]
}

// RetryRequest performs a request with exponential backoff retry
func RetryRequest(client *http.Client, req *http.Request, maxRetries int) (*http.Response, error) {
	var lastErr error
	
	for i := 0; i <= maxRetries; i++ {
		resp, err := client.Do(req)
		if err == nil {
			return resp, nil
		}
		
		lastErr = err
		
		if i < maxRetries {
			// Exponential backoff: 1s, 2s, 4s, 8s...
			backoff := time.Duration(1<<uint(i)) * time.Second
			time.Sleep(backoff)
		}
	}
	
	return nil, fmt.Errorf("request failed after %d retries: %w", maxRetries, lastErr)
}
