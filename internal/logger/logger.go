package logger

import (
	"os"

	"github.com/sirupsen/logrus"
)

// Logger interface for structured logging
type Logger interface {
	Debug(msg string, fields ...interface{})
	Info(msg string, fields ...interface{})
	Warn(msg string, fields ...interface{})
	Error(msg string, fields ...interface{})
	Fatal(msg string, fields ...interface{})
	WithField(key string, value interface{}) Logger
	WithFields(fields map[string]interface{}) Logger
}

type logrusLogger struct {
	*logrus.Logger
}

// New creates a new logger instance
func New(level, format string) Logger {
	log := logrus.New()
	
	// Set log level
	switch level {
	case "debug":
		log.SetLevel(logrus.DebugLevel)
	case "info":
		log.SetLevel(logrus.InfoLevel)
	case "warn":
		log.SetLevel(logrus.WarnLevel)
	case "error":
		log.SetLevel(logrus.ErrorLevel)
	default:
		log.SetLevel(logrus.InfoLevel)
	}
	
	// Set format
	if format == "json" {
		log.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: "2006-01-02T15:04:05.000Z",
		})
	} else {
		log.SetFormatter(&logrus.TextFormatter{
			FullTimestamp:   true,
			TimestampFormat: "2006-01-02 15:04:05",
			ForceColors:     true,
		})
	}
	
	log.SetOutput(os.Stdout)
	
	return &logrusLogger{log}
}

func (l *logrusLogger) Debug(msg string, fields ...interface{}) {
	l.WithFields(parseFields(fields...)).Debug(msg)
}

func (l *logrusLogger) Info(msg string, fields ...interface{}) {
	l.WithFields(parseFields(fields...)).Info(msg)
}

func (l *logrusLogger) Warn(msg string, fields ...interface{}) {
	l.WithFields(parseFields(fields...)).Warn(msg)
}

func (l *logrusLogger) Error(msg string, fields ...interface{}) {
	l.WithFields(parseFields(fields...)).Error(msg)
}

func (l *logrusLogger) Fatal(msg string, fields ...interface{}) {
	l.WithFields(parseFields(fields...)).Fatal(msg)
}

func (l *logrusLogger) WithField(key string, value interface{}) Logger {
	return &logrusLogger{l.Logger.WithField(key, value).Logger}
}

func (l *logrusLogger) WithFields(fields map[string]interface{}) Logger {
	return &logrusLogger{l.Logger.WithFields(fields).Logger}
}

func parseFields(fields ...interface{}) logrus.Fields {
	result := make(logrus.Fields)
	
	for i := 0; i < len(fields)-1; i += 2 {
		if key, ok := fields[i].(string); ok {
			result[key] = fields[i+1]
		}
	}
	
	return result
}
