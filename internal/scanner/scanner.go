package scanner

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/bugbounty-tool/internal/config"
	"github.com/bugbounty-tool/internal/logger"
	"github.com/bugbounty-tool/internal/recon"
	"github.com/bugbounty-tool/internal/vuln"
	"github.com/bugbounty-tool/internal/ai"
	"github.com/bugbounty-tool/pkg/models"
)

// Scanner orchestrates the entire scanning process
type Scanner struct {
	config *config.Config
	log    logger.Logger
	
	// Module instances
	reconEngine *recon.Engine
	vulnEngine  *vuln.Engine
	aiEngine    *ai.Engine
	
	// State management
	activeScans map[string]*models.ScanSession
	mutex       sync.RWMutex
}

// New creates a new scanner instance
func New(cfg *config.Config, log logger.Logger) (*Scanner, error) {
	s := &Scanner{
		config:      cfg,
		log:         log,
		activeScans: make(map[string]*models.ScanSession),
	}
	
	// Initialize reconnaissance engine
	reconEngine, err := recon.NewEngine(cfg, log)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize recon engine: %w", err)
	}
	s.reconEngine = reconEngine
	
	// Initialize vulnerability engine
	vulnEngine, err := vuln.NewEngine(cfg, log)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize vulnerability engine: %w", err)
	}
	s.vulnEngine = vulnEngine
	
	// Initialize AI engine
	aiEngine, err := ai.NewEngine(cfg, log)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize AI engine: %w", err)
	}
	s.aiEngine = aiEngine
	
	return s, nil
}

// Scan performs a comprehensive security scan
func (s *Scanner) Scan(ctx context.Context, config *models.ScanConfig) (*models.ScanResults, error) {
	// Create scan session
	session := &models.ScanSession{
		ID:        generateScanID(),
		Target:    config.Target,
		Config:    config,
		StartTime: time.Now(),
		Status:    "running",
	}
	
	// Register active scan
	s.mutex.Lock()
	s.activeScans[session.ID] = session
	s.mutex.Unlock()
	
	defer func() {
		s.mutex.Lock()
		delete(s.activeScans, session.ID)
		s.mutex.Unlock()
	}()
	
	s.log.Info("Starting scan session",
		"scan_id", session.ID,
		"target", config.Target,
		"profile", config.Profile)
	
	results := &models.ScanResults{
		ScanID:    session.ID,
		Target:    config.Target,
		StartTime: session.StartTime,
		Status:    "running",
	}
	
	// Phase 1: Reconnaissance
	if contains(config.Modules, "recon") {
		s.log.Info("Starting reconnaissance phase", "scan_id", session.ID)
		reconResults, err := s.reconEngine.Scan(ctx, config)
		if err != nil {
			s.log.Error("Reconnaissance failed", "error", err)
			return nil, fmt.Errorf("reconnaissance phase failed: %w", err)
		}
		
		results.Subdomains = reconResults.Subdomains
		results.Endpoints = reconResults.Endpoints
		results.Technologies = reconResults.Technologies
		results.Certificates = reconResults.Certificates
		
		s.log.Info("Reconnaissance completed",
			"scan_id", session.ID,
			"subdomains", len(results.Subdomains),
			"endpoints", len(results.Endpoints))
	}
	
	// Phase 2: Vulnerability Scanning
	if contains(config.Modules, "vuln") {
		s.log.Info("Starting vulnerability scanning phase", "scan_id", session.ID)
		vulnResults, err := s.vulnEngine.Scan(ctx, config, results)
		if err != nil {
			s.log.Error("Vulnerability scanning failed", "error", err)
			return nil, fmt.Errorf("vulnerability scanning phase failed: %w", err)
		}
		
		results.Vulnerabilities = vulnResults.Vulnerabilities
		results.RiskScore = vulnResults.RiskScore
		
		s.log.Info("Vulnerability scanning completed",
			"scan_id", session.ID,
			"vulnerabilities", len(results.Vulnerabilities),
			"risk_score", results.RiskScore)
	}
	
	// Phase 3: AI Analysis
	if contains(config.Modules, "ai") && config.AITriage {
		s.log.Info("Starting AI analysis phase", "scan_id", session.ID)
		aiResults, err := s.aiEngine.Analyze(ctx, results)
		if err != nil {
			s.log.Error("AI analysis failed", "error", err)
			// Don't fail the entire scan for AI issues
		} else {
			results.AITriage = aiResults.Triage
			results.GeneratedPayloads = aiResults.Payloads
			results.Recommendations = aiResults.Recommendations
			
			s.log.Info("AI analysis completed",
				"scan_id", session.ID,
				"triage_updates", len(aiResults.Triage))
		}
	}
	
	// Finalize results
	results.EndTime = time.Now()
	results.Duration = results.EndTime.Sub(results.StartTime)
	results.Status = "completed"
	
	// Save results
	if err := s.saveResults(results); err != nil {
		s.log.Error("Failed to save results", "error", err)
		return nil, fmt.Errorf("failed to save results: %w", err)
	}
	
	s.log.Info("Scan completed successfully",
		"scan_id", session.ID,
		"duration", results.Duration,
		"vulnerabilities", len(results.Vulnerabilities))
	
	return results, nil
}

// GetActiveScan returns information about an active scan
func (s *Scanner) GetActiveScan(scanID string) (*models.ScanSession, bool) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	
	session, exists := s.activeScans[scanID]
	return session, exists
}

// ListActiveScans returns all active scan sessions
func (s *Scanner) ListActiveScans() []*models.ScanSession {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	
	sessions := make([]*models.ScanSession, 0, len(s.activeScans))
	for _, session := range s.activeScans {
		sessions = append(sessions, session)
	}
	
	return sessions
}

// StopScan cancels an active scan
func (s *Scanner) StopScan(scanID string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	
	session, exists := s.activeScans[scanID]
	if !exists {
		return fmt.Errorf("scan not found: %s", scanID)
	}
	
	session.Status = "cancelled"
	if session.CancelFunc != nil {
		session.CancelFunc()
	}
	
	return nil
}

func (s *Scanner) saveResults(results *models.ScanResults) error {
	// Save to database or file system
	// Implementation depends on storage backend
	s.log.Debug("Saving scan results", "scan_id", results.ScanID)
	return nil
}

func generateScanID() string {
	return fmt.Sprintf("scan-%d", time.Now().Unix())
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
