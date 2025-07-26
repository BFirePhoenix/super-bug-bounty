package recon

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gocolly/colly/v2"
	"github.com/gocolly/colly/v2/debug"
	"github.com/gocolly/colly/v2/extensions"
	"github.com/bugbounty-tool/internal/config"
	"github.com/bugbounty-tool/internal/logger"
	"github.com/bugbounty-tool/pkg/models"
)

// WebCrawler performs comprehensive web crawling and content discovery
type WebCrawler struct {
	config     *config.Config
	log        logger.Logger
	collector  *colly.Collector
	
	// Crawl state
	visitedURLs  map[string]bool
	foundURLs    []string
	forms        []models.Form
	endpoints    []models.Endpoint
	jsFiles      []string
	cssFiles     []string
	images       []string
	
	mutex        sync.RWMutex
}

// NewWebCrawler creates a new web crawler instance
func NewWebCrawler(cfg *config.Config, log logger.Logger) *WebCrawler {
	c := colly.NewCollector(
		colly.Debugger(&debug.LogDebugger{}),
		colly.AllowedDomains(), // Will be set dynamically
	)
	
	// Configure collector
	c.Limit(&colly.LimitRule{
		DomainGlob:  "*",
		Parallelism: cfg.Scanning.DefaultThreads,
		Delay:       time.Duration(1000/cfg.Scanning.RateLimit) * time.Millisecond,
	})
	
	c.SetRequestTimeout(time.Duration(cfg.Scanning.DefaultTimeout) * time.Second)
	
	// Add user agent rotation
	extensions.RandomUserAgent(c)
	extensions.Referer(c)
	
	wc := &WebCrawler{
		config:      cfg,
		log:         log,
		collector:   c,
		visitedURLs: make(map[string]bool),
		foundURLs:   make([]string, 0),
		forms:       make([]models.Form, 0),
		endpoints:   make([]models.Endpoint, 0),
		jsFiles:     make([]string, 0),
		cssFiles:    make([]string, 0),
		images:      make([]string, 0),
	}
	
	wc.setupCallbacks()
	return wc
}

// Crawl performs comprehensive web crawling
func (wc *WebCrawler) Crawl(ctx context.Context, targetURL string, config *models.ScanConfig) (*models.CrawlResults, error) {
	wc.log.Info("Starting web crawling", "target", targetURL)
	
	// Parse target URL to get domain
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}
	
	// Set allowed domains
	wc.collector.AllowedDomains = []string{parsedURL.Host}
	if strings.HasPrefix(parsedURL.Host, "www.") {
		wc.collector.AllowedDomains = append(wc.collector.AllowedDomains, parsedURL.Host[4:])
	}
	
	results := &models.CrawlResults{
		Target:    targetURL,
		StartTime: time.Now(),
	}
	
	// Check robots.txt first
	if err := wc.analyzeRobotsTxt(parsedURL); err != nil {
		wc.log.Warn("Failed to analyze robots.txt", "error", err)
	}
	
	// Start crawling
	if err := wc.collector.Visit(targetURL); err != nil {
		return nil, fmt.Errorf("failed to start crawling: %w", err)
	}
	
	// Wait for crawling to complete
	wc.collector.Wait()
	
	// Compile results
	wc.mutex.RLock()
	results.URLs = make([]string, len(wc.foundURLs))
	copy(results.URLs, wc.foundURLs)
	results.Forms = make([]models.Form, len(wc.forms))
	copy(results.Forms, wc.forms)
	results.Endpoints = make([]models.Endpoint, len(wc.endpoints))
	copy(results.Endpoints, wc.endpoints)
	results.JSFiles = make([]string, len(wc.jsFiles))
	copy(results.JSFiles, wc.jsFiles)
	results.CSSFiles = make([]string, len(wc.cssFiles))
	copy(results.CSSFiles, wc.cssFiles)
	results.Images = make([]string, len(wc.images))
	copy(results.Images, wc.images)
	wc.mutex.RUnlock()
	
	results.EndTime = time.Now()
	results.Duration = results.EndTime.Sub(results.StartTime)
	
	wc.log.Info("Web crawling completed",
		"target", targetURL,
		"urls_found", len(results.URLs),
		"forms_found", len(results.Forms),
		"endpoints_found", len(results.Endpoints),
		"duration", results.Duration)
	
	return results, nil
}

func (wc *WebCrawler) setupCallbacks() {
	// Handle HTML pages
	wc.collector.OnHTML("html", func(e *colly.HTMLElement) {
		wc.extractLinksFromHTML(e)
		wc.extractFormsFromHTML(e)
		wc.extractResourcesFromHTML(e)
		wc.extractEndpointsFromHTML(e)
	})
	
	// Handle JavaScript files
	wc.collector.OnHTML("script[src]", func(e *colly.HTMLElement) {
		src := e.Attr("src")
		if src != "" {
			absoluteURL := e.Request.AbsoluteURL(src)
			wc.mutex.Lock()
			wc.jsFiles = append(wc.jsFiles, absoluteURL)
			wc.mutex.Unlock()
			
			// Analyze JavaScript for endpoints
			wc.analyzeJavaScript(absoluteURL)
		}
	})
	
	// Handle inline JavaScript
	wc.collector.OnHTML("script", func(e *colly.HTMLElement) {
		if e.Attr("src") == "" {
			// Inline JavaScript
			jsContent := e.Text
			wc.extractEndpointsFromJS(jsContent)
		}
	})
	
	// Handle CSS files
	wc.collector.OnHTML("link[rel=stylesheet]", func(e *colly.HTMLElement) {
		href := e.Attr("href")
		if href != "" {
			absoluteURL := e.Request.AbsoluteURL(href)
			wc.mutex.Lock()
			wc.cssFiles = append(wc.cssFiles, absoluteURL)
			wc.mutex.Unlock()
		}
	})
	
	// Handle images
	wc.collector.OnHTML("img[src]", func(e *colly.HTMLElement) {
		src := e.Attr("src")
		if src != "" {
			absoluteURL := e.Request.AbsoluteURL(src)
			wc.mutex.Lock()
			wc.images = append(wc.images, absoluteURL)
			wc.mutex.Unlock()
		}
	})
	
	// Track visited URLs
	wc.collector.OnRequest(func(r *colly.Request) {
		wc.mutex.Lock()
		wc.visitedURLs[r.URL.String()] = true
		wc.foundURLs = append(wc.foundURLs, r.URL.String())
		wc.mutex.Unlock()
		
		wc.log.Debug("Visiting URL", "url", r.URL.String())
	})
	
	// Handle errors
	wc.collector.OnError(func(r *colly.Response, err error) {
		wc.log.Error("Crawl error", "url", r.Request.URL.String(), "error", err)
	})
	
	// Handle responses
	wc.collector.OnResponse(func(r *colly.Response) {
		wc.log.Debug("Response received", 
			"url", r.Request.URL.String(),
			"status", r.StatusCode,
			"content_type", strings.Split(r.Headers.Get("Content-Type"), ";")[0])
	})
}

func (wc *WebCrawler) extractLinksFromHTML(e *colly.HTMLElement) {
	// Extract links from various HTML elements
	e.ForEach("a[href]", func(_ int, el *colly.HTMLElement) {
		href := el.Attr("href")
		if href != "" {
			absoluteURL := el.Request.AbsoluteURL(href)
			el.Request.Visit(absoluteURL)
		}
	})
	
	// Extract from other elements that might contain URLs
	e.ForEach("[src], [href], [action], [data-url], [data-href]", func(_ int, el *colly.HTMLElement) {
		attributes := []string{"src", "href", "action", "data-url", "data-href"}
		for _, attr := range attributes {
			if value := el.Attr(attr); value != "" {
				absoluteURL := el.Request.AbsoluteURL(value)
				if wc.isValidURL(absoluteURL) {
					el.Request.Visit(absoluteURL)
				}
			}
		}
	})
}

func (wc *WebCrawler) extractFormsFromHTML(e *colly.HTMLElement) {
	e.ForEach("form", func(_ int, form *colly.HTMLElement) {
		formData := models.Form{
			Action:   form.Attr("action"),
			Method:   strings.ToUpper(form.Attr("method")),
			Inputs:   make([]models.FormInput, 0),
			URL:      e.Request.URL.String(),
			Detected: time.Now(),
		}
		
		if formData.Method == "" {
			formData.Method = "GET"
		}
		
		// Extract form inputs
		form.ForEach("input, select, textarea", func(_ int, input *colly.HTMLElement) {
			inputData := models.FormInput{
				Name:     input.Attr("name"),
				Type:     input.Attr("type"),
				Value:    input.Attr("value"),
				Required: input.Attr("required") != "",
			}
			
			if inputData.Type == "" {
				switch input.Name {
				case "input":
					inputData.Type = "text"
				case "select":
					inputData.Type = "select"
				case "textarea":
					inputData.Type = "textarea"
				}
			}
			
			formData.Inputs = append(formData.Inputs, inputData)
		})
		
		wc.mutex.Lock()
		wc.forms = append(wc.forms, formData)
		wc.mutex.Unlock()
	})
}

func (wc *WebCrawler) extractResourcesFromHTML(e *colly.HTMLElement) {
	// Extract various resource URLs
	resourceSelectors := map[string]string{
		"link[href]":      "href",
		"script[src]":     "src",
		"img[src]":        "src",
		"iframe[src]":     "src",
		"embed[src]":      "src",
		"object[data]":    "data",
		"source[src]":     "src",
		"track[src]":      "src",
	}
	
	for selector, attr := range resourceSelectors {
		e.ForEach(selector, func(_ int, el *colly.HTMLElement) {
			src := el.Attr(attr)
			if src != "" {
				absoluteURL := el.Request.AbsoluteURL(src)
				wc.addEndpoint(absoluteURL, "resource", el.Request.URL.String())
			}
		})
	}
}

func (wc *WebCrawler) extractEndpointsFromHTML(e *colly.HTMLElement) {
	// Extract API endpoints from HTML comments
	html := e.Text
	wc.extractEndpointsFromText(html, e.Request.URL.String())
	
	// Extract from data attributes
	e.ForEach("[data-api], [data-endpoint], [data-url]", func(_ int, el *colly.HTMLElement) {
		attributes := []string{"data-api", "data-endpoint", "data-url"}
		for _, attr := range attributes {
			if value := el.Attr(attr); value != "" {
				wc.addEndpoint(value, "data-attribute", e.Request.URL.String())
			}
		}
	})
}

func (wc *WebCrawler) extractEndpointsFromJS(jsContent string) {
	// Regular expressions to find API endpoints in JavaScript
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`['"\`](/[a-zA-Z0-9/_\-\.]+)['"\`]`),
		regexp.MustCompile(`['"\`](https?://[^'"\`\s]+)['"\`]`),
		regexp.MustCompile(`fetch\s*\(\s*['"\`]([^'"\`]+)['"\`]`),
		regexp.MustCompile(`xhr\.open\s*\(\s*['"][^'"]*['"],\s*['"\`]([^'"\`]+)['"\`]`),
		regexp.MustCompile(`axios\.[a-z]+\s*\(\s*['"\`]([^'"\`]+)['"\`]`),
		regexp.MustCompile(`\$\.ajax\s*\(\s*['"\`]([^'"\`]+)['"\`]`),
		regexp.MustCompile(`api[/_]([a-zA-Z0-9/_\-\.]+)`),
		regexp.MustCompile(`endpoint['":\s]+['"]([^'"]+)['"]`),
	}
	
	for _, pattern := range patterns {
		matches := pattern.FindAllStringSubmatch(jsContent, -1)
		for _, match := range matches {
			if len(match) > 1 {
				endpoint := match[1]
				wc.addEndpoint(endpoint, "javascript", "")
			}
		}
	}
}

func (wc *WebCrawler) extractEndpointsFromText(text, source string) {
	// Extract potential endpoints from any text content
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`/api/[a-zA-Z0-9/_\-\.]+`),
		regexp.MustCompile(`/v\d+/[a-zA-Z0-9/_\-\.]+`),
		regexp.MustCompile(`/rest/[a-zA-Z0-9/_\-\.]+`),
		regexp.MustCompile(`/graphql[a-zA-Z0-9/_\-\.]*`),
		regexp.MustCompile(`/admin/[a-zA-Z0-9/_\-\.]+`),
		regexp.MustCompile(`/dashboard/[a-zA-Z0-9/_\-\.]+`),
	}
	
	for _, pattern := range patterns {
		matches := pattern.FindAllString(text, -1)
		for _, match := range matches {
			wc.addEndpoint(match, "text-extraction", source)
		}
	}
}

func (wc *WebCrawler) analyzeJavaScript(jsURL string) {
	// Download and analyze JavaScript file
	req, err := http.NewRequest("GET", jsURL, nil)
	if err != nil {
		return
	}
	
	client := &http.Client{
		Timeout: time.Duration(wc.config.Scanning.DefaultTimeout) * time.Second,
	}
	
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	
	// Read JavaScript content
	buf := make([]byte, wc.config.Scanning.MaxBodySize)
	n, _ := resp.Body.Read(buf)
	jsContent := string(buf[:n])
	
	// Extract endpoints from JavaScript
	wc.extractEndpointsFromJS(jsContent)
}

func (wc *WebCrawler) analyzeRobotsTxt(targetURL *url.URL) error {
	robotsURL := fmt.Sprintf("%s://%s/robots.txt", targetURL.Scheme, targetURL.Host)
	
	req, err := http.NewRequest("GET", robotsURL, nil)
	if err != nil {
		return err
	}
	
	client := &http.Client{
		Timeout: time.Duration(wc.config.Scanning.DefaultTimeout) * time.Second,
	}
	
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 200 {
		return fmt.Errorf("robots.txt not found: %d", resp.StatusCode)
	}
	
	// Read robots.txt content
	buf := make([]byte, wc.config.Scanning.MaxBodySize)
	n, _ := resp.Body.Read(buf)
	robotsContent := string(buf[:n])
	
	// Extract disallowed paths as potential endpoints
	lines := strings.Split(robotsContent, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(line), "disallow:") {
			path := strings.TrimSpace(line[9:])
			if path != "" && path != "/" {
				wc.addEndpoint(path, "robots.txt", robotsURL)
			}
		} else if strings.HasPrefix(strings.ToLower(line), "sitemap:") {
			sitemapURL := strings.TrimSpace(line[8:])
			if sitemapURL != "" {
				wc.analyzeSitemap(sitemapURL)
			}
		}
	}
	
	return nil
}

func (wc *WebCrawler) analyzeSitemap(sitemapURL string) {
	req, err := http.NewRequest("GET", sitemapURL, nil)
	if err != nil {
		return
	}
	
	client := &http.Client{
		Timeout: time.Duration(wc.config.Scanning.DefaultTimeout) * time.Second,
	}
	
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 200 {
		return
	}
	
	// Read sitemap content
	buf := make([]byte, wc.config.Scanning.MaxBodySize)
	n, _ := resp.Body.Read(buf)
	sitemapContent := string(buf[:n])
	
	// Extract URLs from sitemap (basic XML parsing)
	urlPattern := regexp.MustCompile(`<loc>(.*?)</loc>`)
	matches := urlPattern.FindAllStringSubmatch(sitemapContent, -1)
	
	for _, match := range matches {
		if len(match) > 1 {
			url := match[1]
			wc.addEndpoint(url, "sitemap", sitemapURL)
		}
	}
}

func (wc *WebCrawler) addEndpoint(endpoint, source, referrer string) {
	// Clean and validate endpoint
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" || endpoint == "/" {
		return
	}
	
	// Skip common non-endpoint patterns
	skipPatterns := []string{
		".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg",
		".pdf", ".doc", ".docx", ".xls", ".xlsx", ".zip", ".tar", ".gz",
		"mailto:", "tel:", "javascript:", "#",
	}
	
	for _, pattern := range skipPatterns {
		if strings.Contains(strings.ToLower(endpoint), pattern) {
			return
		}
	}
	
	wc.mutex.Lock()
	defer wc.mutex.Unlock()
	
	// Check for duplicates
	for _, existing := range wc.endpoints {
		if existing.URL == endpoint {
			return
		}
	}
	
	// Add new endpoint
	newEndpoint := models.Endpoint{
		URL:       endpoint,
		Method:    "GET",
		Source:    source,
		Referrer:  referrer,
		Detected:  time.Now(),
		Parameters: wc.extractParameters(endpoint),
	}
	
	wc.endpoints = append(wc.endpoints, newEndpoint)
}

func (wc *WebCrawler) extractParameters(endpoint string) []models.Parameter {
	params := make([]models.Parameter, 0)
	
	// Parse URL to extract query parameters
	if parsedURL, err := url.Parse(endpoint); err == nil {
		for key, values := range parsedURL.Query() {
			for _, value := range values {
				param := models.Parameter{
					Name:     key,
					Value:    value,
					Type:     wc.guessParameterType(value),
					Source:   "query",
					Location: "url",
				}
				params = append(params, param)
			}
		}
	}
	
	return params
}

func (wc *WebCrawler) guessParameterType(value string) string {
	// Simple type guessing based on value patterns
	if value == "" {
		return "string"
	}
	
	// Check for numeric values
	if regexp.MustCompile(`^\d+$`).MatchString(value) {
		return "integer"
	}
	
	if regexp.MustCompile(`^\d+\.\d+$`).MatchString(value) {
		return "float"
	}
	
	// Check for boolean values
	if value == "true" || value == "false" {
		return "boolean"
	}
	
	// Check for email
	if regexp.MustCompile(`^[^@]+@[^@]+\.[^@]+$`).MatchString(value) {
		return "email"
	}
	
	// Check for URL
	if regexp.MustCompile(`^https?://`).MatchString(value) {
		return "url"
	}
	
	// Check for date patterns
	if regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`).MatchString(value) {
		return "date"
	}
	
	return "string"
}

func (wc *WebCrawler) isValidURL(urlStr string) bool {
	if urlStr == "" {
		return false
	}
	
	// Skip common non-URL patterns
	skipPatterns := []string{
		"javascript:", "mailto:", "tel:", "ftp:", "#", "data:",
	}
	
	for _, pattern := range skipPatterns {
		if strings.HasPrefix(strings.ToLower(urlStr), pattern) {
			return false
		}
	}
	
	// Check if it's a valid URL
	if _, err := url.Parse(urlStr); err != nil {
		return false
	}
	
	return true
}
