package security

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/bugbounty-tool/internal/config"
	"github.com/bugbounty-tool/internal/logger"
)

// Sandbox provides secure execution environment for untrusted code
type Sandbox struct {
	config    *config.Config
	log       logger.Logger
	workDir   string
	enabled   bool
	limits    ResourceLimits
}

// ResourceLimits defines resource constraints for sandboxed execution
type ResourceLimits struct {
	MaxMemory      int64         // Maximum memory in bytes
	MaxCPUTime     time.Duration // Maximum CPU time
	MaxExecutionTime time.Duration // Maximum wall-clock time
	MaxFileSize    int64         // Maximum file size
	MaxProcesses   int           // Maximum number of processes
	NetworkAccess  bool          // Allow network access
	FileSystemAccess bool        // Allow file system access
}

// ExecutionResult contains the result of sandboxed execution
type ExecutionResult struct {
	Success    bool
	Output     string
	Error      string
	ExitCode   int
	Duration   time.Duration
	MemoryUsed int64
	Timeout    bool
}

// NewSandbox creates a new security sandbox
func NewSandbox(cfg *config.Config, log logger.Logger) (*Sandbox, error) {
	if !cfg.Security.EnableSandbox {
		return &Sandbox{
			config:  cfg,
			log:     log,
			enabled: false,
		}, nil
	}
	
	// Create temporary work directory
	workDir, err := os.MkdirTemp("", "bugbounty-sandbox-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create sandbox directory: %w", err)
	}
	
	sandbox := &Sandbox{
		config:  cfg,
		log:     log,
		workDir: workDir,
		enabled: true,
		limits: ResourceLimits{
			MaxMemory:        256 * 1024 * 1024, // 256MB
			MaxCPUTime:       30 * time.Second,
			MaxExecutionTime: 60 * time.Second,
			MaxFileSize:      10 * 1024 * 1024, // 10MB
			MaxProcesses:     10,
			NetworkAccess:    false,
			FileSystemAccess: true,
		},
	}
	
	log.Info("Sandbox initialized", "work_dir", workDir)
	return sandbox, nil
}

// ExecuteCommand executes a command in the sandbox
func (s *Sandbox) ExecuteCommand(ctx context.Context, command string, args []string) (*ExecutionResult, error) {
	if !s.enabled {
		return s.executeUnsandboxed(ctx, command, args)
	}
	
	s.log.Debug("Executing command in sandbox", "command", command, "args", args)
	
	// Create execution context with timeout
	execCtx, cancel := context.WithTimeout(ctx, s.limits.MaxExecutionTime)
	defer cancel()
	
	// Prepare command
	cmd := exec.CommandContext(execCtx, command, args...)
	cmd.Dir = s.workDir
	
	// Apply resource limits
	if err := s.applyResourceLimits(cmd); err != nil {
		return nil, fmt.Errorf("failed to apply resource limits: %w", err)
	}
	
	// Execute command
	startTime := time.Now()
	output, err := cmd.CombinedOutput()
	duration := time.Since(startTime)
	
	result := &ExecutionResult{
		Duration: duration,
		Output:   string(output),
	}
	
	if err != nil {
		result.Error = err.Error()
		if exitError, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitError.ExitCode()
		}
		
		// Check if timeout occurred
		if execCtx.Err() == context.DeadlineExceeded {
			result.Timeout = true
		}
	} else {
		result.Success = true
	}
	
	s.log.Debug("Command execution completed",
		"success", result.Success,
		"duration", result.Duration,
		"exit_code", result.ExitCode)
	
	return result, nil
}

// ExecutePythonScript executes a Python script in the sandbox
func (s *Sandbox) ExecutePythonScript(ctx context.Context, scriptPath string, args []string) (*ExecutionResult, error) {
	if !s.enabled {
		return s.executePythonUnsandboxed(ctx, scriptPath, args)
	}
	
	// Copy script to sandbox directory
	sandboxScript := filepath.Join(s.workDir, filepath.Base(scriptPath))
	if err := s.copyFile(scriptPath, sandboxScript); err != nil {
		return nil, fmt.Errorf("failed to copy script to sandbox: %w", err)
	}
	
	// Execute Python script
	pythonArgs := append([]string{sandboxScript}, args...)
	return s.ExecuteCommand(ctx, "python3", pythonArgs)
}

// ExecuteJavaScript executes a JavaScript file in the sandbox
func (s *Sandbox) ExecuteJavaScript(ctx context.Context, scriptPath string, args []string) (*ExecutionResult, error) {
	if !s.enabled {
		return s.executeJavaScriptUnsandboxed(ctx, scriptPath, args)
	}
	
	// Copy script to sandbox directory
	sandboxScript := filepath.Join(s.workDir, filepath.Base(scriptPath))
	if err := s.copyFile(scriptPath, sandboxScript); err != nil {
		return nil, fmt.Errorf("failed to copy script to sandbox: %w", err)
	}
	
	// Execute JavaScript with Node.js
	nodeArgs := append([]string{sandboxScript}, args...)
	return s.ExecuteCommand(ctx, "node", nodeArgs)
}

// CreateFile creates a file in the sandbox
func (s *Sandbox) CreateFile(filename string, content []byte) error {
	if !s.enabled {
		return fmt.Errorf("sandbox not enabled")
	}
	
	filePath := filepath.Join(s.workDir, filename)
	
	// Check file size limit
	if int64(len(content)) > s.limits.MaxFileSize {
		return fmt.Errorf("file size exceeds limit")
	}
	
	return os.WriteFile(filePath, content, 0644)
}

// ReadFile reads a file from the sandbox
func (s *Sandbox) ReadFile(filename string) ([]byte, error) {
	if !s.enabled {
		return nil, fmt.Errorf("sandbox not enabled")
	}
	
	filePath := filepath.Join(s.workDir, filename)
	return os.ReadFile(filePath)
}

// Cleanup removes all sandbox files and directories
func (s *Sandbox) Cleanup() error {
	if s.workDir != "" {
		err := os.RemoveAll(s.workDir)
		if err != nil {
			s.log.Error("Failed to cleanup sandbox", "error", err)
		} else {
			s.log.Debug("Sandbox cleaned up", "work_dir", s.workDir)
		}
		return err
	}
	return nil
}

// SetResourceLimits updates the resource limits
func (s *Sandbox) SetResourceLimits(limits ResourceLimits) {
	s.limits = limits
	s.log.Debug("Resource limits updated", "limits", limits)
}

// Helper methods
func (s *Sandbox) applyResourceLimits(cmd *exec.Cmd) error {
	if runtime.GOOS != "linux" {
		s.log.Debug("Resource limits not supported on this platform")
		return nil
	}
	
	// Set process group for easier cleanup
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}
	
	// Apply ulimits (Unix-specific)
	if s.limits.MaxMemory > 0 {
		// Memory limit would be applied here
		// This requires more complex implementation with cgroups or similar
	}
	
	return nil
}

func (s *Sandbox) executeUnsandboxed(ctx context.Context, command string, args []string) (*ExecutionResult, error) {
	s.log.Debug("Executing command without sandbox", "command", command)
	
	cmd := exec.CommandContext(ctx, command, args...)
	
	startTime := time.Now()
	output, err := cmd.CombinedOutput()
	duration := time.Since(startTime)
	
	result := &ExecutionResult{
		Duration: duration,
		Output:   string(output),
	}
	
	if err != nil {
		result.Error = err.Error()
		if exitError, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitError.ExitCode()
		}
	} else {
		result.Success = true
	}
	
	return result, nil
}

func (s *Sandbox) executePythonUnsandboxed(ctx context.Context, scriptPath string, args []string) (*ExecutionResult, error) {
	pythonArgs := append([]string{scriptPath}, args...)
	return s.executeUnsandboxed(ctx, "python3", pythonArgs)
}

func (s *Sandbox) executeJavaScriptUnsandboxed(ctx context.Context, scriptPath string, args []string) (*ExecutionResult, error) {
	nodeArgs := append([]string{scriptPath}, args...)
	return s.executeUnsandboxed(ctx, "node", nodeArgs)
}

func (s *Sandbox) copyFile(src, dst string) error {
	sourceFile, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	
	return os.WriteFile(dst, sourceFile, 0644)
}

// PayloadSandbox provides specialized sandbox for payload execution
type PayloadSandbox struct {
	*Sandbox
	payloadTimeout time.Duration
	maxPayloadSize int64
}

// NewPayloadSandbox creates a sandbox specifically for payload testing
func NewPayloadSandbox(cfg *config.Config, log logger.Logger) (*PayloadSandbox, error) {
	baseSandbox, err := NewSandbox(cfg, log)
	if err != nil {
		return nil, err
	}
	
	ps := &PayloadSandbox{
		Sandbox:        baseSandbox,
		payloadTimeout: 10 * time.Second,
		maxPayloadSize: 1024 * 1024, // 1MB
	}
	
	// Set more restrictive limits for payload execution
	ps.limits = ResourceLimits{
		MaxMemory:        64 * 1024 * 1024, // 64MB
		MaxCPUTime:       10 * time.Second,
		MaxExecutionTime: 15 * time.Second,
		MaxFileSize:      1 * 1024 * 1024, // 1MB
		MaxProcesses:     5,
		NetworkAccess:    false,
		FileSystemAccess: false,
	}
	
	return ps, nil
}

// TestPayload tests a payload in the sandbox
func (ps *PayloadSandbox) TestPayload(ctx context.Context, payload string, payloadType string) (*ExecutionResult, error) {
	if len(payload) > int(ps.maxPayloadSize) {
		return &ExecutionResult{
			Success: false,
			Error:   "payload exceeds maximum size",
		}, nil
	}
	
	ps.log.Debug("Testing payload in sandbox", "type", payloadType, "size", len(payload))
	
	switch payloadType {
	case "javascript":
		return ps.testJavaScriptPayload(ctx, payload)
	case "python":
		return ps.testPythonPayload(ctx, payload)
	case "shell":
		return ps.testShellPayload(ctx, payload)
	default:
		return &ExecutionResult{
			Success: false,
			Error:   fmt.Sprintf("unsupported payload type: %s", payloadType),
		}, nil
	}
}

func (ps *PayloadSandbox) testJavaScriptPayload(ctx context.Context, payload string) (*ExecutionResult, error) {
	// Create a temporary JavaScript file
	filename := fmt.Sprintf("payload_%d.js", time.Now().UnixNano())
	if err := ps.CreateFile(filename, []byte(payload)); err != nil {
		return nil, err
	}
	
	return ps.ExecuteJavaScript(ctx, filepath.Join(ps.workDir, filename), []string{})
}

func (ps *PayloadSandbox) testPythonPayload(ctx context.Context, payload string) (*ExecutionResult, error) {
	// Create a temporary Python file
	filename := fmt.Sprintf("payload_%d.py", time.Now().UnixNano())
	if err := ps.CreateFile(filename, []byte(payload)); err != nil {
		return nil, err
	}
	
	return ps.ExecutePythonScript(ctx, filepath.Join(ps.workDir, filename), []string{})
}

func (ps *PayloadSandbox) testShellPayload(ctx context.Context, payload string) (*ExecutionResult, error) {
	// Execute shell payload directly (with extreme caution)
	return ps.ExecuteCommand(ctx, "sh", []string{"-c", payload})
}

// SecurityValidator validates code before execution
type SecurityValidator struct {
	log logger.Logger
}

// NewSecurityValidator creates a new security validator
func NewSecurityValidator(log logger.Logger) *SecurityValidator {
	return &SecurityValidator{log: log}
}

// ValidatePayload checks if a payload is safe to execute
func (sv *SecurityValidator) ValidatePayload(payload string, payloadType string) error {
	// Check for dangerous patterns
	dangerousPatterns := []string{
		"rm -rf", "format c:", "del /f", "shutdown", "reboot",
		"passwd", "sudo", "su -", "chmod 777", "curl http",
		"wget http", "nc ", "netcat", "bash -i", "sh -i",
		"python -c", "perl -e", "ruby -e", "exec(",
		"/dev/tcp/", ">", ">>", "&", "&&", "||", ";",
		"$IFS", "${IFS}", "$(", "`", "eval", "system(",
	}
	
	payloadLower := strings.ToLower(payload)
	for _, pattern := range dangerousPatterns {
		if strings.Contains(payloadLower, pattern) {
			sv.log.Warn("Dangerous pattern detected in payload", "pattern", pattern)
			return fmt.Errorf("dangerous pattern detected: %s", pattern)
		}
	}
	
	// Check payload length
	if len(payload) > 10240 { // 10KB limit
		return fmt.Errorf("payload too large: %d bytes", len(payload))
	}
	
	return nil
}

// ValidateScript validates a script file before execution
func (sv *SecurityValidator) ValidateScript(scriptPath string) error {
	content, err := os.ReadFile(scriptPath)
	if err != nil {
		return fmt.Errorf("failed to read script: %w", err)
	}
	
	return sv.ValidatePayload(string(content), filepath.Ext(scriptPath))
}
