package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/bugbounty-tool/internal/config"
	"github.com/bugbounty-tool/internal/logger"
	"golang.org/x/net/proxy"
)

// Manager handles proxy configurations and connections
type Manager struct {
	config       *config.Config
	log          logger.Logger
	proxies      []ProxyConfig
	currentProxy int
	mutex        sync.RWMutex
	torClient    *http.Client
}

// ProxyConfig represents a proxy configuration
type ProxyConfig struct {
	Type     string // http, https, socks5, tor
	Host     string
	Port     int
	Username string
	Password string
	Enabled  bool
}

// NewManager creates a new proxy manager
func NewManager(cfg *config.Config, log logger.Logger) *Manager {
	m := &Manager{
		config:  cfg,
		log:     log,
		proxies: make([]ProxyConfig, 0),
	}
	
	// Load proxy configurations
	m.loadProxyConfigs()
	
	// Initialize Tor client if available
	m.initTorClient()
	
	return m
}

// GetHTTPClient returns an HTTP client configured with proxy settings
func (m *Manager) GetHTTPClient(timeout time.Duration) *http.Client {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: !m.config.Scanning.VerifySSL,
		},
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	
	// Configure proxy if available
	if len(m.proxies) > 0 && m.currentProxy < len(m.proxies) {
		proxyConfig := m.proxies[m.currentProxy]
		if proxyConfig.Enabled {
			proxyURL := m.buildProxyURL(proxyConfig)
			if proxyURL != nil {
				transport.Proxy = http.ProxyURL(proxyURL)
				m.log.Debug("Using proxy", 
					"type", proxyConfig.Type,
					"host", proxyConfig.Host,
					"port", proxyConfig.Port)
			}
		}
	}
	
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= m.config.Scanning.MaxRedirects {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

// GetTorClient returns a Tor-enabled HTTP client
func (m *Manager) GetTorClient(timeout time.Duration) *http.Client {
	if m.torClient != nil {
		// Clone the client with new timeout
		transport := m.torClient.Transport.(*http.Transport).Clone()
		return &http.Client{
			Transport: transport,
			Timeout:   timeout,
		}
	}
	
	// Fallback to regular client
	return m.GetHTTPClient(timeout)
}

// RotateProxy switches to the next available proxy
func (m *Manager) RotateProxy() {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	if len(m.proxies) > 1 {
		m.currentProxy = (m.currentProxy + 1) % len(m.proxies)
		m.log.Debug("Rotated to proxy", "index", m.currentProxy)
	}
}

// AddProxy adds a new proxy configuration
func (m *Manager) AddProxy(proxyConfig ProxyConfig) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	m.proxies = append(m.proxies, proxyConfig)
	m.log.Info("Added proxy", 
		"type", proxyConfig.Type,
		"host", proxyConfig.Host,
		"port", proxyConfig.Port)
}

// TestProxy tests if a proxy is working
func (m *Manager) TestProxy(proxyConfig ProxyConfig) error {
	proxyURL := m.buildProxyURL(proxyConfig)
	if proxyURL == nil {
		return fmt.Errorf("invalid proxy configuration")
	}
	
	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	
	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}
	
	// Test with a simple HTTP request
	testURL := "http://httpbin.org/ip"
	resp, err := client.Get(testURL)
	if err != nil {
		return fmt.Errorf("proxy test failed: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 200 {
		return fmt.Errorf("proxy test failed with status: %d", resp.StatusCode)
	}
	
	m.log.Info("Proxy test successful", 
		"type", proxyConfig.Type,
		"host", proxyConfig.Host,
		"port", proxyConfig.Port)
	
	return nil
}

// GetProxyList returns the list of configured proxies
func (m *Manager) GetProxyList() []ProxyConfig {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	
	proxies := make([]ProxyConfig, len(m.proxies))
	copy(proxies, m.proxies)
	return proxies
}

// DisableProxy disables a specific proxy
func (m *Manager) DisableProxy(index int) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	if index < 0 || index >= len(m.proxies) {
		return fmt.Errorf("invalid proxy index: %d", index)
	}
	
	m.proxies[index].Enabled = false
	m.log.Info("Disabled proxy", "index", index)
	
	return nil
}

// EnableProxy enables a specific proxy
func (m *Manager) EnableProxy(index int) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	if index < 0 || index >= len(m.proxies) {
		return fmt.Errorf("invalid proxy index: %d", index)
	}
	
	m.proxies[index].Enabled = true
	m.log.Info("Enabled proxy", "index", index)
	
	return nil
}

// Helper methods
func (m *Manager) loadProxyConfigs() {
	// Load proxy configurations from environment or config file
	// For now, just check for common proxy environment variables
	
	if httpProxy := getEnvProxy("HTTP_PROXY"); httpProxy != nil {
		m.proxies = append(m.proxies, *httpProxy)
	}
	
	if httpsProxy := getEnvProxy("HTTPS_PROXY"); httpsProxy != nil {
		m.proxies = append(m.proxies, *httpsProxy)
	}
	
	// Check for SOCKS5 proxy
	if socksProxy := getEnvProxy("SOCKS_PROXY"); socksProxy != nil {
		socksProxy.Type = "socks5"
		m.proxies = append(m.proxies, *socksProxy)
	}
}

func (m *Manager) initTorClient() {
	// Try to connect to Tor SOCKS proxy
	torDialer, err := proxy.SOCKS5("tcp", "127.0.0.1:9050", nil, proxy.Direct)
	if err != nil {
		m.log.Debug("Tor not available", "error", err)
		return
	}
	
	// Test Tor connection
	conn, err := torDialer.Dial("tcp", "check.torproject.org:80")
	if err != nil {
		m.log.Debug("Tor connection test failed", "error", err)
		return
	}
	conn.Close()
	
	// Create Tor-enabled HTTP client
	transport := &http.Transport{
		Dial: torDialer.Dial,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: !m.config.Scanning.VerifySSL,
		},
	}
	
	m.torClient = &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}
	
	m.log.Info("Tor client initialized successfully")
}

func (m *Manager) buildProxyURL(proxyConfig ProxyConfig) *url.URL {
	var scheme string
	switch proxyConfig.Type {
	case "http":
		scheme = "http"
	case "https":
		scheme = "https"
	case "socks5":
		scheme = "socks5"
	default:
		return nil
	}
	
	proxyURL := &url.URL{
		Scheme: scheme,
		Host:   fmt.Sprintf("%s:%d", proxyConfig.Host, proxyConfig.Port),
	}
	
	if proxyConfig.Username != "" {
		if proxyConfig.Password != "" {
			proxyURL.User = url.UserPassword(proxyConfig.Username, proxyConfig.Password)
		} else {
			proxyURL.User = url.User(proxyConfig.Username)
		}
	}
	
	return proxyURL
}

func getEnvProxy(envVar string) *ProxyConfig {
	proxyURL := os.Getenv(envVar)
	if proxyURL == "" {
		return nil
	}
	
	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil
	}
	
	port := 80
	if u.Port() != "" {
		if p, err := strconv.Atoi(u.Port()); err == nil {
			port = p
		}
	}
	
	config := &ProxyConfig{
		Type:    u.Scheme,
		Host:    u.Hostname(),
		Port:    port,
		Enabled: true,
	}
	
	if u.User != nil {
		config.Username = u.User.Username()
		if password, ok := u.User.Password(); ok {
			config.Password = password
		}
	}
	
	return config
}

// ProxyChain manages a chain of proxies for advanced routing
type ProxyChain struct {
	proxies []ProxyConfig
	current int
	mutex   sync.RWMutex
}

// NewProxyChain creates a new proxy chain
func NewProxyChain(proxies []ProxyConfig) *ProxyChain {
	return &ProxyChain{
		proxies: proxies,
		current: 0,
	}
}

// GetNext returns the next proxy in the chain
func (pc *ProxyChain) GetNext() *ProxyConfig {
	pc.mutex.Lock()
	defer pc.mutex.Unlock()
	
	if len(pc.proxies) == 0 {
		return nil
	}
	
	proxy := &pc.proxies[pc.current]
	pc.current = (pc.current + 1) % len(pc.proxies)
	
	return proxy
}

// ProxyRotator automatically rotates proxies on failures
type ProxyRotator struct {
	manager     *Manager
	maxFailures int
	failures    map[int]int
	mutex       sync.RWMutex
}

// NewProxyRotator creates a new proxy rotator
func NewProxyRotator(manager *Manager, maxFailures int) *ProxyRotator {
	return &ProxyRotator{
		manager:     manager,
		maxFailures: maxFailures,
		failures:    make(map[int]int),
	}
}

// RecordFailure records a failure for the current proxy
func (pr *ProxyRotator) RecordFailure() {
	pr.mutex.Lock()
	defer pr.mutex.Unlock()
	
	currentIndex := pr.manager.currentProxy
	pr.failures[currentIndex]++
	
	if pr.failures[currentIndex] >= pr.maxFailures {
		// Disable the proxy and rotate
		pr.manager.DisableProxy(currentIndex)
		pr.manager.RotateProxy()
		delete(pr.failures, currentIndex)
	}
}

// RecordSuccess records a success for the current proxy
func (pr *ProxyRotator) RecordSuccess() {
	pr.mutex.Lock()
	defer pr.mutex.Unlock()
	
	currentIndex := pr.manager.currentProxy
	if pr.failures[currentIndex] > 0 {
		pr.failures[currentIndex]--
	}
}
