package report

import (
	"bytes"
	"html/template"
	"strings"
	"time"
)

// TemplateManager handles report template operations
type TemplateManager struct {
	templates map[string]*template.Template
	funcMap   template.FuncMap
}

// NewTemplateManager creates a new template manager
func NewTemplateManager() *TemplateManager {
	tm := &TemplateManager{
		templates: make(map[string]*template.Template),
	}
	
	// Initialize template functions
	tm.funcMap = template.FuncMap{
		"lower":        strings.ToLower,
		"upper":        strings.ToUpper,
		"title":        strings.Title,
		"formatTime":   tm.formatTime,
		"severityIcon": tm.severityIcon,
		"severityColor": tm.severityColor,
		"truncate":     tm.truncate,
		"join":         strings.Join,
		"replace":      strings.ReplaceAll,
		"contains":     strings.Contains,
		"hasPrefix":    strings.HasPrefix,
		"hasSuffix":    strings.HasSuffix,
		"split":        strings.Split,
		"add":          tm.add,
		"multiply":     tm.multiply,
		"percentage":   tm.percentage,
		"riskLevel":    tm.riskLevel,
		"isHighRisk":   tm.isHighRisk,
		"vulnClass":    tm.vulnClass,
	}
	
	return tm
}

// LoadTemplate loads a template with custom functions
func (tm *TemplateManager) LoadTemplate(name, content string) error {
	tmpl, err := template.New(name).Funcs(tm.funcMap).Parse(content)
	if err != nil {
		return err
	}
	
	tm.templates[name] = tmpl
	return nil
}

// RenderTemplate renders a template with data
func (tm *TemplateManager) RenderTemplate(name string, data interface{}) (string, error) {
	tmpl, exists := tm.templates[name]
	if !exists {
		return "", ErrTemplateNotFound
	}
	
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}
	
	return buf.String(), nil
}

// Template helper functions
func (tm *TemplateManager) formatTime(t time.Time) string {
	return t.Format("2006-01-02 15:04:05")
}

func (tm *TemplateManager) severityIcon(severity string) string {
	icons := map[string]string{
		"critical": "🔴",
		"high":     "🟠",
		"medium":   "🟡",
		"low":      "🔵",
		"info":     "⚪",
	}
	
	if icon, exists := icons[strings.ToLower(severity)]; exists {
		return icon
	}
	return "⚫"
}

func (tm *TemplateManager) severityColor(severity string) string {
	colors := map[string]string{
		"critical": "#d73027",
		"high":     "#fc8d59",
		"medium":   "#fee08b",
		"low":      "#91bfdb",
		"info":     "#ffffcc",
	}
	
	if color, exists := colors[strings.ToLower(severity)]; exists {
		return color
	}
	return "#666666"
}

func (tm *TemplateManager) truncate(s string, length int) string {
	if len(s) <= length {
		return s
	}
	return s[:length] + "..."
}

func (tm *TemplateManager) add(a, b int) int {
	return a + b
}

func (tm *TemplateManager) multiply(a, b int) int {
	return a * b
}

func (tm *TemplateManager) percentage(part, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(part) / float64(total) * 100
}

func (tm *TemplateManager) riskLevel(severity string) int {
	levels := map[string]int{
		"critical": 5,
		"high":     4,
		"medium":   3,
		"low":      2,
		"info":     1,
	}
	
	if level, exists := levels[strings.ToLower(severity)]; exists {
		return level
	}
	return 1
}

func (tm *TemplateManager) isHighRisk(severity string) bool {
	return strings.ToLower(severity) == "critical" || strings.ToLower(severity) == "high"
}

func (tm *TemplateManager) vulnClass(vulnType string) string {
	// Convert vulnerability type to CSS class
	class := strings.ToLower(vulnType)
	class = strings.ReplaceAll(class, " ", "-")
	class = strings.ReplaceAll(class, "(", "")
	class = strings.ReplaceAll(class, ")", "")
	return "vuln-" + class
}

// Error definitions
var (
	ErrTemplateNotFound = fmt.Errorf("template not found")
)

// Built-in templates
const (
	DefaultHTMLTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
            color: #333;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }
        .header h1 {
            margin: 0;
            font-size: 2.5em;
            font-weight: 300;
        }
        .header .subtitle {
            margin-top: 10px;
            opacity: 0.9;
            font-size: 1.1em;
        }
        .content {
            padding: 40px;
        }
        .section {
            margin-bottom: 40px;
        }
        .section h2 {
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .summary-card {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            border-left: 4px solid #3498db;
        }
        .summary-card.critical { border-left-color: #e74c3c; }
        .summary-card.high { border-left-color: #f39c12; }
        .summary-card.medium { border-left-color: #f1c40f; }
        .summary-card.low { border-left-color: #3498db; }
        .summary-card h3 {
            margin: 0 0 10px 0;
            font-size: 2em;
            color: #2c3e50;
        }
        .vulnerability {
            background: white;
            border: 1px solid #ddd;
            border-radius: 8px;
            margin-bottom: 20px;
            overflow: hidden;
        }
        .vuln-header {
            padding: 20px;
            background: #f8f9fa;
            border-bottom: 1px solid #ddd;
        }
        .vuln-title {
            margin: 0;
            color: #2c3e50;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .severity-badge {
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: bold;
            text-transform: uppercase;
        }
        .severity-critical { background: #e74c3c; color: white; }
        .severity-high { background: #f39c12; color: white; }
        .severity-medium { background: #f1c40f; color: #333; }
        .severity-low { background: #3498db; color: white; }
        .severity-info { background: #95a5a6; color: white; }
        .vuln-content {
            padding: 20px;
        }
        .vuln-meta {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
            background: #f8f9fa;
            padding: 15px;
            border-radius: 6px;
        }
        .meta-item {
            display: flex;
            flex-direction: column;
        }
        .meta-label {
            font-weight: bold;
            color: #7f8c8d;
            font-size: 0.9em;
            margin-bottom: 5px;
        }
        .meta-value {
            color: #2c3e50;
            word-break: break-all;
        }
        .description {
            margin-bottom: 20px;
            line-height: 1.6;
        }
        .evidence {
            background: #2c3e50;
            color: #ecf0f1;
            padding: 15px;
            border-radius: 6px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            overflow-x: auto;
            margin-bottom: 15px;
        }
        .poc {
            background: #34495e;
            color: #ecf0f1;
            padding: 15px;
            border-radius: 6px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            overflow-x: auto;
        }
        .footer {
            background: #2c3e50;
            color: white;
            padding: 20px;
            text-align: center;
        }
        @media (max-width: 768px) {
            .summary-grid {
                grid-template-columns: 1fr;
            }
            .vuln-meta {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Security Assessment Report</h1>
            <div class="subtitle">
                Target: {{.Metadata.Target}}<br>
                Generated: {{formatTime .Metadata.GeneratedAt}}<br>
                Scan ID: {{.Metadata.ScanID}}
            </div>
        </div>
        
        <div class="content">
            <div class="section">
                <h2>Executive Summary</h2>
                <div class="summary-grid">
                    <div class="summary-card critical">
                        <h3>{{.ExecutiveSummary.CriticalIssues}}</h3>
                        <p>Critical Issues</p>
                    </div>
                    <div class="summary-card high">
                        <h3>{{.ExecutiveSummary.HighIssues}}</h3>
                        <p>High Issues</p>
                    </div>
                    <div class="summary-card medium">
                        <h3>{{.ExecutiveSummary.MediumIssues}}</h3>
                        <p>Medium Issues</p>
                    </div>
                    <div class="summary-card low">
                        <h3>{{.ExecutiveSummary.LowIssues}}</h3>
                        <p>Low Issues</p>
                    </div>
                </div>
                
                <p><strong>Overall Risk Level:</strong> {{.ExecutiveSummary.OverallRisk}}</p>
                <p><strong>Total Vulnerabilities:</strong> {{.ExecutiveSummary.TotalIssues}}</p>
                
                {{if .ExecutiveSummary.KeyFindings}}
                <h3>Key Findings</h3>
                <ul>
                    {{range .ExecutiveSummary.KeyFindings}}
                    <li>{{.}}</li>
                    {{end}}
                </ul>
                {{end}}
                
                {{if .ExecutiveSummary.Recommendations}}
                <h3>Recommendations</h3>
                <ul>
                    {{range .ExecutiveSummary.Recommendations}}
                    <li>{{.}}</li>
                    {{end}}
                </ul>
                {{end}}
            </div>
            
            <div class="section">
                <h2>Detailed Findings</h2>
                {{range .ScanResults.Vulnerabilities}}
                <div class="vulnerability">
                    <div class="vuln-header">
                        <h3 class="vuln-title">
                            {{severityIcon .Severity}}
                            {{.Title}}
                            <span class="severity-badge severity-{{lower .Severity}}">{{.Severity}}</span>
                        </h3>
                    </div>
                    
                    <div class="vuln-content">
                        <div class="vuln-meta">
                            <div class="meta-item">
                                <div class="meta-label">Vulnerability Type</div>
                                <div class="meta-value">{{.Type}}</div>
                            </div>
                            <div class="meta-item">
                                <div class="meta-label">URL</div>
                                <div class="meta-value">{{.URL}}</div>
                            </div>
                            {{if .Parameter}}
                            <div class="meta-item">
                                <div class="meta-label">Parameter</div>
                                <div class="meta-value">{{.Parameter}}</div>
                            </div>
                            {{end}}
                            <div class="meta-item">
                                <div class="meta-label">Method</div>
                                <div class="meta-value">{{.Method}}</div>
                            </div>
                            <div class="meta-item">
                                <div class="meta-label">Confidence</div>
                                <div class="meta-value">{{.Confidence}}%</div>
                            </div>
                            <div class="meta-item">
                                <div class="meta-label">Risk Level</div>
                                <div class="meta-value">{{.Risk}}</div>
                            </div>
                        </div>
                        
                        <div class="description">
                            <strong>Description:</strong> {{.Description}}
                        </div>
                        
                        {{if .Evidence}}
                        <div class="evidence">
                            <strong>Evidence:</strong><br>
                            {{.Evidence}}
                        </div>
                        {{end}}
                        
                        <div class="description">
                            <strong>Impact:</strong> {{.Impact}}
                        </div>
                        
                        <div class="description">
                            <strong>Remediation:</strong> {{.Remediation}}
                        </div>
                        
                        {{if .ProofOfConcept}}
                        <div class="poc">
                            <strong>Proof of Concept:</strong><br>
                            {{.ProofOfConcept}}
                        </div>
                        {{end}}
                    </div>
                </div>
                {{end}}
            </div>
        </div>
        
        <div class="footer">
            <p>Generated by BugBounty CLI Tool v{{.Metadata.Version}} on {{formatTime .Metadata.GeneratedAt}}</p>
        </div>
    </div>
</body>
</html>`

	ExecutiveTemplate = `<!DOCTYPE html>
<html>
<head>
    <title>Executive Summary</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { text-align: center; margin-bottom: 40px; }
        .summary { background: #f8f9fa; padding: 20px; border-radius: 8px; }
        .risk-high { color: #dc3545; font-weight: bold; }
        .risk-medium { color: #ffc107; font-weight: bold; }
        .risk-low { color: #28a745; font-weight: bold; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Executive Summary</h1>
        <p>Security Assessment for {{.Metadata.Target}}</p>
    </div>
    
    <div class="summary">
        <h2>Risk Overview</h2>
        <p class="risk-{{lower .ExecutiveSummary.OverallRisk}}">
            Overall Risk Level: {{.ExecutiveSummary.OverallRisk}}
        </p>
        
        <h3>Issue Breakdown</h3>
        <ul>
            <li>Critical Issues: {{.ExecutiveSummary.CriticalIssues}}</li>
            <li>High Issues: {{.ExecutiveSummary.HighIssues}}</li>
            <li>Medium Issues: {{.ExecutiveSummary.MediumIssues}}</li>
            <li>Low Issues: {{.ExecutiveSummary.LowIssues}}</li>
        </ul>
        
        {{if .ExecutiveSummary.Recommendations}}
        <h3>Immediate Actions Required</h3>
        <ol>
            {{range .ExecutiveSummary.Recommendations}}
            <li>{{.}}</li>
            {{end}}
        </ol>
        {{end}}
    </div>
</body>
</html>`
)
