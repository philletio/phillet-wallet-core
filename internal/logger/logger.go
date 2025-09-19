package logger

import (
	"context"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Logger provides structured logging functionality
type Logger struct {
	*zap.Logger
}

// Config holds logger configuration
type Config struct {
	Level  string `json:"level"`
	Format string `json:"format"`
	Output string `json:"output"`
}

// NewLogger creates a new structured logger
func NewLogger(config *Config) *Logger {
	if config == nil {
		config = &Config{
			Level:  "info",
			Format: "json",
			Output: "stdout",
		}
	}

	var zapConfig zap.Config
	if config.Format == "console" {
		zapConfig = zap.NewDevelopmentConfig()
	} else {
		zapConfig = zap.NewProductionConfig()
	}

	// Set log level
	switch config.Level {
	case "debug":
		zapConfig.Level = zap.NewAtomicLevelAt(zapcore.DebugLevel)
	case "info":
		zapConfig.Level = zap.NewAtomicLevelAt(zapcore.InfoLevel)
	case "warn":
		zapConfig.Level = zap.NewAtomicLevelAt(zapcore.WarnLevel)
	case "error":
		zapConfig.Level = zap.NewAtomicLevelAt(zapcore.ErrorLevel)
	default:
		zapConfig.Level = zap.NewAtomicLevelAt(zapcore.InfoLevel)
	}

	// Set output
	if config.Output != "stdout" {
		zapConfig.OutputPaths = []string{config.Output}
	}

	// Add custom fields
	zapConfig.InitialFields = map[string]interface{}{
		"service": "phillet-wallet-core",
		"version": "1.0.0",
	}

	logger, err := zapConfig.Build()
	if err != nil {
		panic("Failed to create logger: " + err.Error())
	}

	return &Logger{Logger: logger}
}

// WithContext adds context fields to the logger
func (l *Logger) WithContext(ctx context.Context) *Logger {
	fields := []zap.Field{}

	// Add request ID if available
	if requestID := ctx.Value("request_id"); requestID != nil {
		fields = append(fields, zap.String("request_id", requestID.(string)))
	}

	// Add user ID if available
	if userID := ctx.Value("user_id"); userID != nil {
		fields = append(fields, zap.String("user_id", userID.(string)))
	}

	// Add correlation ID if available
	if correlationID := ctx.Value("correlation_id"); correlationID != nil {
		fields = append(fields, zap.String("correlation_id", correlationID.(string)))
	}

	return &Logger{Logger: l.Logger.With(fields...)}
}

// WithFields adds custom fields to the logger
func (l *Logger) WithFields(fields map[string]interface{}) *Logger {
	zapFields := make([]zap.Field, 0, len(fields))
	for key, value := range fields {
		zapFields = append(zapFields, zap.Any(key, value))
	}
	return &Logger{Logger: l.Logger.With(zapFields...)}
}

// LogRequest logs an incoming request
func (l *Logger) LogRequest(ctx context.Context, method, userID string, duration time.Duration, err error) {
	fields := []zap.Field{
		zap.String("method", method),
		zap.String("user_id", userID),
		zap.Duration("duration", duration),
	}

	if err != nil {
		fields = append(fields, zap.Error(err))
		l.Error("Request failed", fields...)
	} else {
		l.Info("Request completed", fields...)
	}
}

// LogSecurityEvent logs a security-related event
func (l *Logger) LogSecurityEvent(ctx context.Context, event string, details map[string]interface{}) {
	fields := []zap.Field{
		zap.String("event", event),
		zap.Time("timestamp", time.Now()),
	}

	for key, value := range details {
		fields = append(fields, zap.Any(key, value))
	}

	l.Warn("Security event", fields...)
}

// LogAuditEvent logs an audit event
func (l *Logger) LogAuditEvent(ctx context.Context, action, resourceType, resourceID, userID string, success bool, details map[string]interface{}) {
	fields := []zap.Field{
		zap.String("action", action),
		zap.String("resource_type", resourceType),
		zap.String("resource_id", resourceID),
		zap.String("user_id", userID),
		zap.Bool("success", success),
		zap.Time("timestamp", time.Now()),
	}

	for key, value := range details {
		fields = append(fields, zap.Any(key, value))
	}

	l.Info("Audit event", fields...)
}

// LogError logs an error with context
func (l *Logger) LogError(ctx context.Context, err error, message string, fields ...zap.Field) {
	allFields := append(fields, zap.Error(err))
	l.Error(message, allFields...)
}

// LogPerformance logs performance metrics
func (l *Logger) LogPerformance(ctx context.Context, operation string, duration time.Duration, metrics map[string]interface{}) {
	fields := []zap.Field{
		zap.String("operation", operation),
		zap.Duration("duration", duration),
		zap.Time("timestamp", time.Now()),
	}

	for key, value := range metrics {
		fields = append(fields, zap.Any(key, value))
	}

	l.Info("Performance metric", fields...)
}

// LogDatabaseOperation logs a database operation
func (l *Logger) LogDatabaseOperation(ctx context.Context, operation, table string, duration time.Duration, err error) {
	fields := []zap.Field{
		zap.String("operation", operation),
		zap.String("table", table),
		zap.Duration("duration", duration),
	}

	if err != nil {
		fields = append(fields, zap.Error(err))
		l.Error("Database operation failed", fields...)
	} else {
		l.Debug("Database operation completed", fields...)
	}
}

// LogCacheOperation logs a cache operation
func (l *Logger) LogCacheOperation(ctx context.Context, operation, key string, hit bool, duration time.Duration, err error) {
	fields := []zap.Field{
		zap.String("operation", operation),
		zap.String("key", key),
		zap.Bool("hit", hit),
		zap.Duration("duration", duration),
	}

	if err != nil {
		fields = append(fields, zap.Error(err))
		l.Error("Cache operation failed", fields...)
	} else {
		l.Debug("Cache operation completed", fields...)
	}
}

// LogRPCRequest logs an RPC request to external services
func (l *Logger) LogRPCRequest(ctx context.Context, service, method string, duration time.Duration, statusCode int, err error) {
	fields := []zap.Field{
		zap.String("service", service),
		zap.String("method", method),
		zap.Duration("duration", duration),
		zap.Int("status_code", statusCode),
	}

	if err != nil {
		fields = append(fields, zap.Error(err))
		l.Error("RPC request failed", fields...)
	} else {
		l.Info("RPC request completed", fields...)
	}
}

// LogWalletOperation logs wallet-specific operations
func (l *Logger) LogWalletOperation(ctx context.Context, operation, walletID, userID string, success bool, details map[string]interface{}) {
	fields := []zap.Field{
		zap.String("operation", operation),
		zap.String("wallet_id", walletID),
		zap.String("user_id", userID),
		zap.Bool("success", success),
		zap.Time("timestamp", time.Now()),
	}

	for key, value := range details {
		fields = append(fields, zap.Any(key, value))
	}

	if success {
		l.Info("Wallet operation completed", fields...)
	} else {
		l.Error("Wallet operation failed", fields...)
	}
}

// LogAddressGeneration logs address generation events
func (l *Logger) LogAddressGeneration(ctx context.Context, walletID, chain string, count int, duration time.Duration, err error) {
	fields := []zap.Field{
		zap.String("wallet_id", walletID),
		zap.String("chain", chain),
		zap.Int("count", count),
		zap.Duration("duration", duration),
	}

	if err != nil {
		fields = append(fields, zap.Error(err))
		l.Error("Address generation failed", fields...)
	} else {
		l.Info("Address generation completed", fields...)
	}
}

// LogSigningOperation logs signing operations
func (l *Logger) LogSigningOperation(ctx context.Context, operation, walletID, chain string, success bool, duration time.Duration, err error) {
	fields := []zap.Field{
		zap.String("operation", operation),
		zap.String("wallet_id", walletID),
		zap.String("chain", chain),
		zap.Bool("success", success),
		zap.Duration("duration", duration),
	}

	if err != nil {
		fields = append(fields, zap.Error(err))
		l.Error("Signing operation failed", fields...)
	} else {
		l.Info("Signing operation completed", fields...)
	}
}

// LogRateLimit logs rate limiting events
func (l *Logger) LogRateLimit(ctx context.Context, method, userID string, limit float64, burst int) {
	fields := []zap.Field{
		zap.String("method", method),
		zap.String("user_id", userID),
		zap.Float64("limit", limit),
		zap.Int("burst", burst),
		zap.Time("timestamp", time.Now()),
	}

	l.Warn("Rate limit exceeded", fields...)
}

// LogHealthCheck logs health check results
func (l *Logger) LogHealthCheck(ctx context.Context, component string, healthy bool, duration time.Duration, err error) {
	fields := []zap.Field{
		zap.String("component", component),
		zap.Bool("healthy", healthy),
		zap.Duration("duration", duration),
	}

	if err != nil {
		fields = append(fields, zap.Error(err))
		l.Error("Health check failed", fields...)
	} else {
		l.Debug("Health check completed", fields...)
	}
}

// Sync flushes any buffered log entries
func (l *Logger) Sync() error {
	return l.Logger.Sync()
}

// Close closes the logger
func (l *Logger) Close() error {
	return l.Logger.Sync()
}

// Global logger instance
var globalLogger *Logger

// InitGlobalLogger initializes the global logger
func InitGlobalLogger(config *Config) {
	globalLogger = NewLogger(config)
}

// GetGlobalLogger returns the global logger instance
func GetGlobalLogger() *Logger {
	if globalLogger == nil {
		globalLogger = NewLogger(nil)
	}
	return globalLogger
}

// SetGlobalLogger sets the global logger instance
func SetGlobalLogger(logger *Logger) {
	globalLogger = logger
}

// Default logger for quick access
func Default() *Logger {
	return GetGlobalLogger()
}
