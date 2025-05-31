package monitoring

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/natefinch/lumberjack.v2"
)

// LogLevel logging levels
type LogLevel string

const (
	LevelDebug LogLevel = "debug"
	LevelInfo  LogLevel = "info"
	LevelWarn  LogLevel = "warn"
	LevelError LogLevel = "error"
)

// LogFormat logging format
type LogFormat string

const (
	FormatJSON    LogFormat = "json"
	FormatText    LogFormat = "text"
	FormatOpenVPN LogFormat = "openvpn" // OpenVPN-compatible format
)

// LogConfig logging configuration
type LogConfig struct {
	Level      LogLevel  `json:"level" yaml:"level"`
	Format     LogFormat `json:"format" yaml:"format"`
	Output     string    `json:"output" yaml:"output"`           // "stdout", "stderr", or file path
	MaxSize    int       `json:"max_size" yaml:"max_size"`       // maximum file size in MB
	MaxBackups int       `json:"max_backups" yaml:"max_backups"` // number of backup files
	MaxAge     int       `json:"max_age" yaml:"max_age"`         // maximum file age in days
	Compress   bool      `json:"compress" yaml:"compress"`       // compress backup files

	// Additional fields for OpenVPN compatibility
	EnableOpenVPNCompat bool   `json:"enable_openvpn_compat" yaml:"enable_openvpn_compat"`
	Facility            string `json:"facility" yaml:"facility"` // for syslog
	EnableSyslog        bool   `json:"enable_syslog" yaml:"enable_syslog"`
}

// DefaultLogConfig returns default logging configuration
func DefaultLogConfig() *LogConfig {
	return &LogConfig{
		Level:      LevelInfo,
		Format:     FormatJSON,
		Output:     "stdout",
		MaxSize:    100,
		MaxBackups: 3,
		MaxAge:     28,
		Compress:   true,
		Facility:   "daemon",
	}
}

// Logger structured logger for GoVPN
type Logger struct {
	*slog.Logger
	config *LogConfig
	closer io.Closer
}

// NewLogger creates a new structured logger
func NewLogger(config *LogConfig) (*Logger, error) {
	if config == nil {
		config = DefaultLogConfig()
	}

	var writer io.Writer
	var closer io.Closer

	// Determine where to write logs
	switch strings.ToLower(config.Output) {
	case "stdout":
		writer = os.Stdout
	case "stderr":
		writer = os.Stderr
	default:
		// Create directory if needed
		if dir := filepath.Dir(config.Output); dir != "." {
			if err := os.MkdirAll(dir, 0755); err != nil {
				return nil, fmt.Errorf("failed to create log directory: %w", err)
			}
		}

		// Use lumberjack for log rotation
		lumberjackLogger := &lumberjack.Logger{
			Filename:   config.Output,
			MaxSize:    config.MaxSize,
			MaxBackups: config.MaxBackups,
			MaxAge:     config.MaxAge,
			Compress:   config.Compress,
		}
		writer = lumberjackLogger
		closer = lumberjackLogger
	}

	// Determine logging level
	var level slog.Level
	switch config.Level {
	case LevelDebug:
		level = slog.LevelDebug
	case LevelInfo:
		level = slog.LevelInfo
	case LevelWarn:
		level = slog.LevelWarn
	case LevelError:
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	// Create handler depending on format
	var handler slog.Handler
	opts := &slog.HandlerOptions{
		Level: level,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			// Settings for OpenVPN compatibility
			if config.EnableOpenVPNCompat {
				if a.Key == slog.TimeKey {
					// OpenVPN time format
					return slog.Attr{
						Key:   slog.TimeKey,
						Value: slog.StringValue(a.Value.Time().Format("Mon Jan 2 15:04:05 2006")),
					}
				}
			}
			return a
		},
	}

	switch config.Format {
	case FormatJSON:
		handler = slog.NewJSONHandler(writer, opts)
	case FormatText:
		handler = slog.NewTextHandler(writer, opts)
	case FormatOpenVPN:
		// Special format for OpenVPN compatibility
		handler = NewOpenVPNHandler(writer, opts)
	default:
		handler = slog.NewJSONHandler(writer, opts)
	}

	logger := &Logger{
		Logger: slog.New(handler),
		config: config,
		closer: closer,
	}

	return logger, nil
}

// Close closes the logger and releases resources
func (l *Logger) Close() error {
	if l.closer != nil {
		return l.closer.Close()
	}
	return nil
}

// WithFields adds fields to the logger
func (l *Logger) WithFields(fields map[string]interface{}) *Logger {
	args := make([]interface{}, 0, len(fields)*2)
	for k, v := range fields {
		args = append(args, k, v)
	}
	return &Logger{
		Logger: l.Logger.With(args...),
		config: l.config,
		closer: l.closer,
	}
}

// Connection logging methods
func (l *Logger) LogConnection(event string, userID, clientIP, virtualIP string, attrs ...interface{}) {
	args := []interface{}{
		"event", event,
		"user_id", userID,
		"client_ip", clientIP,
		"virtual_ip", virtualIP,
	}
	args = append(args, attrs...)

	l.Info("VPN Connection Event", args...)
}

func (l *Logger) LogConnectionStart(userID, clientIP, virtualIP, protocol string) {
	l.LogConnection("connection_start", userID, clientIP, virtualIP,
		"protocol", protocol,
		"timestamp", time.Now(),
	)
}

func (l *Logger) LogConnectionEnd(userID, clientIP, reason string, duration time.Duration, bytesRx, bytesTx int64) {
	l.LogConnection("connection_end", userID, clientIP, "",
		"reason", reason,
		"duration", duration,
		"bytes_received", bytesRx,
		"bytes_transmitted", bytesTx,
	)
}

// Authentication logging methods
func (l *Logger) LogAuthEvent(event, userID, method, result, reason string) {
	args := []interface{}{
		"event", event,
		"user_id", userID,
		"method", method,
		"result", result,
	}

	if reason != "" {
		args = append(args, "reason", reason)
	}

	l.Info("Authentication Event", args...)
}

func (l *Logger) LogAuthSuccess(userID, method string) {
	l.LogAuthEvent("auth_success", userID, method, "success", "")
}

func (l *Logger) LogAuthFailure(userID, method, reason string) {
	l.LogAuthEvent("auth_failure", userID, method, "failure", reason)
}

// Obfuscation logging methods
func (l *Logger) LogObfuscation(event, method, region string, attrs ...interface{}) {
	args := []interface{}{
		"event", event,
		"method", method,
		"region", region,
	}
	args = append(args, attrs...)

	l.Info("Obfuscation Event", args...)
}

func (l *Logger) LogObfuscationSwitch(oldMethod, newMethod, reason, region string) {
	l.LogObfuscation("method_switch", newMethod, region,
		"old_method", oldMethod,
		"reason", reason,
	)
}

func (l *Logger) LogDPIDetection(method, region string, confidence float64) {
	l.LogObfuscation("dpi_detection", method, region,
		"confidence", confidence,
		"detected_at", time.Now(),
	)
}

// Security logging methods
func (l *Logger) LogSecurityEvent(event, severity, description string, attrs ...interface{}) {
	args := []interface{}{
		"event", event,
		"severity", severity,
		"description", description,
		"timestamp", time.Now(),
	}
	args = append(args, attrs...)

	l.Warn("Security Event", args...)
}

func (l *Logger) LogCertificateEvent(event, certType, commonName string, attrs ...interface{}) {
	args := []interface{}{
		"event", event,
		"type", certType,
		"common_name", commonName,
	}
	args = append(args, attrs...)

	l.Info("Certificate Event", args...)
}

// Performance logging methods
func (l *Logger) LogPerformanceMetric(metric string, value float64, unit string, attrs ...interface{}) {
	args := []interface{}{
		"metric", metric,
		"value", value,
		"unit", unit,
		"timestamp", time.Now(),
	}
	args = append(args, attrs...)

	l.Debug("Performance Metric", args...)
}

// System logging methods
func (l *Logger) LogSystemEvent(event, component, message string, attrs ...interface{}) {
	args := []interface{}{
		"event", event,
		"component", component,
		"message", message,
	}
	args = append(args, attrs...)

	l.Info("System Event", args...)
}

func (l *Logger) LogError(component, operation string, err error, attrs ...interface{}) {
	args := []interface{}{
		"component", component,
		"operation", operation,
		"error", err.Error(),
	}
	args = append(args, attrs...)

	l.Error("Error", args...)
}

// OpenVPN-compatible logging methods
func (l *Logger) LogOpenVPNEvent(level, message string) {
	if l.config.EnableOpenVPNCompat {
		// Format: LEVEL: MESSAGE
		l.Info(fmt.Sprintf("%s: %s", strings.ToUpper(level), message))
	} else {
		// Modern structured format
		l.Info("OpenVPN Event",
			slog.String("level", level),
			slog.String("message", message),
		)
	}
}

// OpenVPNHandler special handler for OpenVPN compatibility
type OpenVPNHandler struct {
	writer io.Writer
	opts   *slog.HandlerOptions
}

func NewOpenVPNHandler(w io.Writer, opts *slog.HandlerOptions) *OpenVPNHandler {
	if opts == nil {
		opts = &slog.HandlerOptions{}
	}
	return &OpenVPNHandler{
		writer: w,
		opts:   opts,
	}
}

func (h *OpenVPNHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return level >= h.opts.Level.Level()
}

func (h *OpenVPNHandler) Handle(ctx context.Context, r slog.Record) error {
	// OpenVPN format: Mon Jan 2 15:04:05 2006 LEVEL: MESSAGE
	timestamp := r.Time.Format("Mon Jan 2 15:04:05 2006")
	level := strings.ToUpper(r.Level.String())
	message := r.Message

	// Add attributes to message
	var attrs []string
	r.Attrs(func(a slog.Attr) bool {
		attrs = append(attrs, fmt.Sprintf("%s=%v", a.Key, a.Value))
		return true
	})

	if len(attrs) > 0 {
		message = fmt.Sprintf("%s [%s]", message, strings.Join(attrs, " "))
	}

	logLine := fmt.Sprintf("%s %s: %s\n", timestamp, level, message)
	_, err := h.writer.Write([]byte(logLine))
	return err
}

func (h *OpenVPNHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return h // For simplicity, in a real implementation, attributes need to be saved
}

func (h *OpenVPNHandler) WithGroup(name string) slog.Handler {
	return h // For simplicity, in a real implementation, groups need to be supported
}
