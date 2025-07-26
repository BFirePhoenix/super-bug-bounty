package models

import (
	"net/url"
	"time"
)

// Target represents a scan target
type Target struct {
	ID          string      `json:"id" yaml:"id"`
	URL         string      `json:"url" yaml:"url"`
	Domain      string      `json:"domain" yaml:"domain"`
	Scheme      string      `json:"scheme" yaml:"scheme"`
	Port        int         `json:"port" yaml:"port"`
	Path        string      `json:"path" yaml:"path"`
	Parameters  []Parameter `json:"parameters,omitempty" yaml:"parameters,omitempty"`
	Forms       []Form      `json:"forms,omitempty" yaml:"forms,omitempty"`
	Headers     Headers     `json:"headers,omitempty" yaml:"headers,omitempty"`
	Cookies     []Cookie    `json:"cookies,omitempty" yaml:"cookies,omitempty"`
	Technologies []Technology `json:"technologies,omitempty" yaml:"technologies,omitempty"`
	StatusCode  int         `json:"status_code" yaml:"status_code"`
	Title       string      `json:"title,omitempty" yaml:"title,omitempty"`
	ContentType string      `json:"content_type,omitempty" yaml:"content_type,omitempty"`
	ContentLength int64     `json:"content_length" yaml:"content_length"`
	ResponseTime time.Duration `json:"response_time" yaml:"response_time"`
	Screenshot  string      `json:"screenshot,omitempty" yaml:"screenshot,omitempty"`
	Tags        []string    `json:"tags,omitempty" yaml:"tags,omitempty"`
	Notes       string      `json:"notes,omitempty" yaml:"notes,omitempty"`
	LastScanned time.Time   `json:"last_scanned" yaml:"last_scanned"`
	CreatedAt   time.Time   `json:"created_at" yaml:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at" yaml:"updated_at"`
}

// Parameter represents a URL parameter
type Parameter struct {
	Name     string    `json:"name" yaml:"name"`
	Value    string    `json:"value" yaml:"value"`
	Type     string    `json:"type" yaml:"type"` // query, path, header, body
	Location string    `json:"location" yaml:"location"` // url, form, header
	Required bool      `json:"required" yaml:"required"`
	Source   string    `json:"source,omitempty" yaml:"source,omitempty"`
	Examples []string  `json:"examples,omitempty" yaml:"examples,omitempty"`
	Pattern  string    `json:"pattern,omitempty" yaml:"pattern,omitempty"`
	Detected time.Time `json:"detected" yaml:"detected"`
}

// Form represents an HTML form
type Form struct {
	ID       string      `json:"id" yaml:"id"`
	Action   string      `json:"action" yaml:"action"`
	Method   string      `json:"method" yaml:"method"`
	Encoding string      `json:"encoding,omitempty" yaml:"encoding,omitempty"`
	Inputs   []FormInput `json:"inputs" yaml:"inputs"`
	URL      string      `json:"url" yaml:"url"`
	Name     string      `json:"name,omitempty" yaml:"name,omitempty"`
	Target   string      `json:"target,omitempty" yaml:"target,omitempty"`
	CSRF     *CSRFToken  `json:"csrf,omitempty" yaml:"csrf,omitempty"`
	Detected time.Time   `json:"detected" yaml:"detected"`
}

// FormInput represents a form input field
type FormInput struct {
	Name         string   `json:"name" yaml:"name"`
	Type         string   `json:"type" yaml:"type"`
	Value        string   `json:"value,omitempty" yaml:"value,omitempty"`
	Placeholder  string   `json:"placeholder,omitempty" yaml:"placeholder,omitempty"`
	Required     bool     `json:"required" yaml:"required"`
	Disabled     bool     `json:"disabled" yaml:"disabled"`
	Readonly     bool     `json:"readonly" yaml:"readonly"`
	Multiple     bool     `json:"multiple" yaml:"multiple"`
	Options      []string `json:"options,omitempty" yaml:"options,omitempty"`
	MinLength    int      `json:"min_length,omitempty" yaml:"min_length,omitempty"`
	MaxLength    int      `json:"max_length,omitempty" yaml:"max_length,omitempty"`
	Pattern      string   `json:"pattern,omitempty" yaml:"pattern,omitempty"`
	Accept       string   `json:"accept,omitempty" yaml:"accept,omitempty"`
	Autocomplete string   `json:"autocomplete,omitempty" yaml:"autocomplete,omitempty"`
}

// CSRFToken represents CSRF protection information
type CSRFToken struct {
	Name  string `json:"name" yaml:"name"`
	Value string `json:"value" yaml:"value"`
	Type  string `json:"type" yaml:"type"` // hidden, meta, header
}

// Headers represents HTTP headers
type Headers map[string][]string

// Cookie represents an HTTP cookie
type Cookie struct {
	Name     string    `json:"name" yaml:"name"`
	Value    string    `json:"value" yaml:"value"`
	Domain   string    `json:"domain,omitempty" yaml:"domain,omitempty"`
	Path     string    `json:"path,omitempty" yaml:"path,omitempty"`
	Expires  time.Time `json:"expires,omitempty" yaml:"expires,omitempty"`
	MaxAge   int       `json:"max_age,omitempty" yaml:"max_age,omitempty"`
	Secure   bool      `json:"secure" yaml:"secure"`
	HttpOnly bool      `json:"http_only" yaml:"http_only"`
	SameSite string    `json:"same_site,omitempty" yaml:"same_site,omitempty"`
}

// Technology represents detected technology
type Technology struct {
	Name       string    `json:"name" yaml:"name"`
	Version    string    `json:"version,omitempty" yaml:"version,omitempty"`
	Category   string    `json:"category" yaml:"category"`
	Confidence int       `json:"confidence" yaml:"confidence"`
	Source     string    `json:"source" yaml:"source"` // header, html, script, css, etc.
	Evidence   []string  `json:"evidence,omitempty" yaml:"evidence,omitempty"`
	Icon       string    `json:"icon,omitempty" yaml:"icon,omitempty"`
	Website    string    `json:"website,omitempty" yaml:"website,omitempty"`
	CPE        string    `json:"cpe,omitempty" yaml:"cpe,omitempty"`
	Timestamp  time.Time `json:"timestamp" yaml:"timestamp"`
}

// Endpoint represents a discovered endpoint
type Endpoint struct {
	ID         string      `json:"id" yaml:"id"`
	URL        string      `json:"url" yaml:"url"`
	Method     string      `json:"method" yaml:"method"`
	Parameters []Parameter `json:"parameters,omitempty" yaml:"parameters,omitempty"`
	Headers    Headers     `json:"headers,omitempty" yaml:"headers,omitempty"`
	Body       string      `json:"body,omitempty" yaml:"body,omitempty"`
	Source     string      `json:"source" yaml:"source"` // crawl, robots, sitemap, js, etc.
	Referrer   string      `json:"referrer,omitempty" yaml:"referrer,omitempty"`
	StatusCode int         `json:"status_code,omitempty" yaml:"status_code,omitempty"`
	ContentType string     `json:"content_type,omitempty" yaml:"content_type,omitempty"`
	Size       int64       `json:"size,omitempty" yaml:"size,omitempty"`
	ResponseTime time.Duration `json:"response_time,omitempty" yaml:"response_time,omitempty"`
	Tags       []string    `json:"tags,omitempty" yaml:"tags,omitempty"`
	Tested     bool        `json:"tested" yaml:"tested"`
	Detected   time.Time   `json:"detected" yaml:"detected"`
}

// Subdomain represents a discovered subdomain
type Subdomain struct {
	Name       string    `json:"name" yaml:"name"`
	IPs        []string  `json:"ips" yaml:"ips"`
	CNAME      string    `json:"cname,omitempty" yaml:"cname,omitempty"`
	MXRecords  []string  `json:"mx_records,omitempty" yaml:"mx_records,omitempty"`
	TXTRecords []string  `json:"txt_records,omitempty" yaml:"txt_records,omitempty"`
	Source     string    `json:"source" yaml:"source"` // bruteforce, dns, api, ct, etc.
	StatusCode int       `json:"status_code,omitempty" yaml:"status_code,omitempty"`
	Title      string    `json:"title,omitempty" yaml:"title,omitempty"`
	Technology []string  `json:"technology,omitempty" yaml:"technology,omitempty"`
	Screenshot string    `json:"screenshot,omitempty" yaml:"screenshot,omitempty"`
	Ports      []Port    `json:"ports,omitempty" yaml:"ports,omitempty"`
	Active     bool      `json:"active" yaml:"active"`
	Timestamp  time.Time `json:"timestamp" yaml:"timestamp"`
}

// Port represents an open port
type Port struct {
	Number   int    `json:"number" yaml:"number"`
	Protocol string `json:"protocol" yaml:"protocol"` // tcp, udp
	State    string `json:"state" yaml:"state"`       // open, closed, filtered
	Service  string `json:"service,omitempty" yaml:"service,omitempty"`
	Version  string `json:"version,omitempty" yaml:"version,omitempty"`
	Banner   string `json:"banner,omitempty" yaml:"banner,omitempty"`
}

// Certificate represents SSL/TLS certificate information
type Certificate struct {
	Subject            string    `json:"subject" yaml:"subject"`
	Issuer             string    `json:"issuer" yaml:"issuer"`
	SerialNumber       string    `json:"serial_number" yaml:"serial_number"`
	NotBefore          time.Time `json:"not_before" yaml:"not_before"`
	NotAfter           time.Time `json:"not_after" yaml:"not_after"`
	Fingerprint        string    `json:"fingerprint" yaml:"fingerprint"`
	KeyAlgorithm       string    `json:"key_algorithm" yaml:"key_algorithm"`
	KeySize            int       `json:"key_size" yaml:"key_size"`
	SignatureAlgorithm string    `json:"signature_algorithm" yaml:"signature_algorithm"`
	DNSNames           []string  `json:"dns_names,omitempty" yaml:"dns_names,omitempty"`
	IPAddresses        []string  `json:"ip_addresses,omitempty" yaml:"ip_addresses,omitempty"`
	SelfSigned         bool      `json:"self_signed" yaml:"self_signed"`
	Expired            bool      `json:"expired" yaml:"expired"`
	ValidChain         bool      `json:"valid_chain" yaml:"valid_chain"`
}

// Methods for Target

// ParseURL parses the target URL and extracts components
func (t *Target) ParseURL() error {
	parsedURL, err := url.Parse(t.URL)
	if err != nil {
		return err
	}
	
	t.Scheme = parsedURL.Scheme
	t.Domain = parsedURL.Hostname()
	t.Path = parsedURL.Path
	
	if parsedURL.Port() != "" {
		port := 80
		if parsedURL.Scheme == "https" {
			port = 443
		}
		if parsedURL.Port() != "" {
			// Parse port number
			t.Port = port // Simplified - would parse actual port
		}
		t.Port = port
	}
	
	// Extract query parameters
	for key, values := range parsedURL.Query() {
		for _, value := range values {
			param := Parameter{
				Name:     key,
				Value:    value,
				Type:     "query",
				Location: "url",
				Detected: time.Now(),
			}
			t.Parameters = append(t.Parameters, param)
		}
	}
	
	return nil
}

// AddParameter adds a parameter to the target
func (t *Target) AddParameter(param Parameter) {
	if t.Parameters == nil {
		t.Parameters = make([]Parameter, 0)
	}
	
	// Check if parameter already exists
	for i, existing := range t.Parameters {
		if existing.Name == param.Name && existing.Location == param.Location {
			// Update existing parameter
			t.Parameters[i] = param
			return
		}
	}
	
	t.Parameters = append(t.Parameters, param)
}

// AddForm adds a form to the target
func (t *Target) AddForm(form Form) {
	if t.Forms == nil {
		t.Forms = make([]Form, 0)
	}
	
	// Check if form already exists
	for i, existing := range t.Forms {
		if existing.Action == form.Action {
			// Update existing form
			t.Forms[i] = form
			return
		}
	}
	
	t.Forms = append(t.Forms, form)
}

// AddTechnology adds detected technology to the target
func (t *Target) AddTechnology(tech Technology) {
	if t.Technologies == nil {
		t.Technologies = make([]Technology, 0)
	}
	
	// Check if technology already exists
	for i, existing := range t.Technologies {
		if existing.Name == tech.Name {
			// Update with higher confidence
			if tech.Confidence > existing.Confidence {
				t.Technologies[i] = tech
			}
			return
		}
	}
	
	t.Technologies = append(t.Technologies, tech)
}

// AddTag adds a tag to the target
func (t *Target) AddTag(tag string) {
	if t.Tags == nil {
		t.Tags = make([]string, 0)
	}
	
	// Check if tag already exists
	for _, existing := range t.Tags {
		if existing == tag {
			return
		}
	}
	
	t.Tags = append(t.Tags, tag)
}

// HasTag checks if the target has a specific tag
func (t *Target) HasTag(tag string) bool {
	for _, existing := range t.Tags {
		if existing == tag {
			return true
		}
	}
	return false
}

// GetParameterByName returns a parameter by name
func (t *Target) GetParameterByName(name string) *Parameter {
	for i, param := range t.Parameters {
		if param.Name == name {
			return &t.Parameters[i]
		}
	}
	return nil
}

// GetFormByAction returns a form by action URL
func (t *Target) GetFormByAction(action string) *Form {
	for i, form := range t.Forms {
		if form.Action == action {
			return &t.Forms[i]
		}
	}
	return nil
}

// IsHTTPS returns true if the target uses HTTPS
func (t *Target) IsHTTPS() bool {
	return t.Scheme == "https"
}

// GetBaseURL returns the base URL without path and parameters
func (t *Target) GetBaseURL() string {
	return fmt.Sprintf("%s://%s", t.Scheme, t.Domain)
}

// UpdateLastScanned updates the last scanned timestamp
func (t *Target) UpdateLastScanned() {
	t.LastScanned = time.Now()
	t.UpdatedAt = time.Now()
}

// Methods for Form

// GetInputByName returns a form input by name
func (f *Form) GetInputByName(name string) *FormInput {
	for i, input := range f.Inputs {
		if input.Name == name {
			return &f.Inputs[i]
		}
	}
	return nil
}

// HasCSRFProtection returns true if the form has CSRF protection
func (f *Form) HasCSRFProtection() bool {
	return f.CSRF != nil
}

// IsPasswordForm returns true if the form contains password fields
func (f *Form) IsPasswordForm() bool {
	for _, input := range f.Inputs {
		if input.Type == "password" {
			return true
		}
	}
	return false
}

// IsFileUploadForm returns true if the form accepts file uploads
func (f *Form) IsFileUploadForm() bool {
	if f.Encoding == "multipart/form-data" {
		return true
	}
	
	for _, input := range f.Inputs {
		if input.Type == "file" {
			return true
		}
	}
	return false
}

// Methods for Endpoint

// GenerateID generates a unique ID for the endpoint
func (e *Endpoint) GenerateID() {
	e.ID = fmt.Sprintf("endpoint-%s-%s-%d", e.Method, e.URL, time.Now().UnixNano())
}

// AddParameter adds a parameter to the endpoint
func (e *Endpoint) AddParameter(param Parameter) {
	if e.Parameters == nil {
		e.Parameters = make([]Parameter, 0)
	}
	e.Parameters = append(e.Parameters, param)
}

// GetParameterNames returns all parameter names
func (e *Endpoint) GetParameterNames() []string {
	names := make([]string, len(e.Parameters))
	for i, param := range e.Parameters {
		names[i] = param.Name
	}
	return names
}

// Methods for Subdomain

// IsWildcard checks if the subdomain is a wildcard
func (s *Subdomain) IsWildcard() bool {
	return strings.HasPrefix(s.Name, "*.")
}

// GetDomain returns the root domain
func (s *Subdomain) GetDomain() string {
	parts := strings.Split(s.Name, ".")
	if len(parts) >= 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return s.Name
}

// HasOpenPorts returns true if the subdomain has open ports
func (s *Subdomain) HasOpenPorts() bool {
	for _, port := range s.Ports {
		if port.State == "open" {
			return true
		}
	}
	return false
}

// GetOpenPorts returns all open ports
func (s *Subdomain) GetOpenPorts() []Port {
	openPorts := make([]Port, 0)
	for _, port := range s.Ports {
		if port.State == "open" {
			openPorts = append(openPorts, port)
		}
	}
	return openPorts
}
