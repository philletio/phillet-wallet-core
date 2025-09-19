package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics holds all Prometheus metrics for the wallet service
type Metrics struct {
	// Request metrics
	RequestTotal    *prometheus.CounterVec
	RequestDuration *prometheus.HistogramVec
	RequestErrors   *prometheus.CounterVec

	// Wallet metrics
	WalletsCreated     prometheus.Counter
	WalletsImported    prometheus.Counter
	AddressesGenerated prometheus.Counter

	// Blockchain metrics
	RPCRequests *prometheus.CounterVec
	RPCDuration *prometheus.HistogramVec
	RPCErrors   *prometheus.CounterVec

	// Cache metrics
	CacheHits       prometheus.Counter
	CacheMisses     prometheus.Counter
	CacheOperations *prometheus.CounterVec

	// Security metrics
	SigningOperations      *prometheus.CounterVec
	VerificationOperations *prometheus.CounterVec

	// System metrics
	ActiveConnections   prometheus.Gauge
	MemoryUsage         prometheus.Gauge
	DatabaseConnections prometheus.Gauge
}

// NewMetrics creates a new Metrics instance with all metrics initialized
func NewMetrics() *Metrics {
	return &Metrics{
		// Request metrics
		RequestTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "wallet_requests_total",
				Help: "Total number of wallet service requests",
			},
			[]string{"method", "status"},
		),

		RequestDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "wallet_request_duration_seconds",
				Help:    "Duration of wallet service requests",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"method"},
		),

		RequestErrors: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "wallet_request_errors_total",
				Help: "Total number of wallet service request errors",
			},
			[]string{"method", "error_type"},
		),

		// Wallet metrics
		WalletsCreated: promauto.NewCounter(
			prometheus.CounterOpts{
				Name: "wallet_wallets_created_total",
				Help: "Total number of wallets created",
			},
		),

		WalletsImported: promauto.NewCounter(
			prometheus.CounterOpts{
				Name: "wallet_wallets_imported_total",
				Help: "Total number of wallets imported",
			},
		),

		AddressesGenerated: promauto.NewCounter(
			prometheus.CounterOpts{
				Name: "wallet_addresses_generated_total",
				Help: "Total number of addresses generated",
			},
		),

		// Blockchain metrics
		RPCRequests: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "wallet_rpc_requests_total",
				Help: "Total number of RPC requests to blockchain networks",
			},
			[]string{"chain", "method"},
		),

		RPCDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "wallet_rpc_duration_seconds",
				Help:    "Duration of RPC requests to blockchain networks",
				Buckets: []float64{0.1, 0.5, 1.0, 2.0, 5.0, 10.0},
			},
			[]string{"chain", "method"},
		),

		RPCErrors: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "wallet_rpc_errors_total",
				Help: "Total number of RPC errors",
			},
			[]string{"chain", "error_type"},
		),

		// Cache metrics
		CacheHits: promauto.NewCounter(
			prometheus.CounterOpts{
				Name: "wallet_cache_hits_total",
				Help: "Total number of cache hits",
			},
		),

		CacheMisses: promauto.NewCounter(
			prometheus.CounterOpts{
				Name: "wallet_cache_misses_total",
				Help: "Total number of cache misses",
			},
		),

		CacheOperations: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "wallet_cache_operations_total",
				Help: "Total number of cache operations",
			},
			[]string{"operation", "status"},
		),

		// Security metrics
		SigningOperations: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "wallet_signing_operations_total",
				Help: "Total number of signing operations",
			},
			[]string{"chain", "operation"},
		),

		VerificationOperations: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "wallet_verification_operations_total",
				Help: "Total number of verification operations",
			},
			[]string{"chain", "status"},
		),

		// System metrics
		ActiveConnections: promauto.NewGauge(
			prometheus.GaugeOpts{
				Name: "wallet_active_connections",
				Help: "Number of active connections",
			},
		),

		MemoryUsage: promauto.NewGauge(
			prometheus.GaugeOpts{
				Name: "wallet_memory_usage_bytes",
				Help: "Memory usage in bytes",
			},
		),

		DatabaseConnections: promauto.NewGauge(
			prometheus.GaugeOpts{
				Name: "wallet_database_connections",
				Help: "Number of database connections",
			},
		),
	}
}

// RecordRequest records a request metric
func (m *Metrics) RecordRequest(method, status string, duration time.Duration) {
	m.RequestTotal.WithLabelValues(method, status).Inc()
	m.RequestDuration.WithLabelValues(method).Observe(duration.Seconds())
}

// RecordRequestError records a request error
func (m *Metrics) RecordRequestError(method, errorType string) {
	m.RequestErrors.WithLabelValues(method, errorType).Inc()
}

// RecordWalletCreated records a wallet creation
func (m *Metrics) RecordWalletCreated() {
	m.WalletsCreated.Inc()
}

// RecordWalletImported records a wallet import
func (m *Metrics) RecordWalletImported() {
	m.WalletsImported.Inc()
}

// RecordAddressGenerated records an address generation
func (m *Metrics) RecordAddressGenerated() {
	m.AddressesGenerated.Inc()
}

// RecordRPCRequest records an RPC request
func (m *Metrics) RecordRPCRequest(chain, method string, duration time.Duration) {
	m.RPCRequests.WithLabelValues(chain, method).Inc()
	m.RPCDuration.WithLabelValues(chain, method).Observe(duration.Seconds())
}

// RecordRPCError records an RPC error
func (m *Metrics) RecordRPCError(chain, errorType string) {
	m.RPCErrors.WithLabelValues(chain, errorType).Inc()
}

// RecordCacheHit records a cache hit
func (m *Metrics) RecordCacheHit() {
	m.CacheHits.Inc()
}

// RecordCacheMiss records a cache miss
func (m *Metrics) RecordCacheMiss() {
	m.CacheMisses.Inc()
}

// RecordCacheOperation records a cache operation
func (m *Metrics) RecordCacheOperation(operation, status string) {
	m.CacheOperations.WithLabelValues(operation, status).Inc()
}

// RecordSigningOperation records a signing operation
func (m *Metrics) RecordSigningOperation(chain, operation string) {
	m.SigningOperations.WithLabelValues(chain, operation).Inc()
}

// RecordVerificationOperation records a verification operation
func (m *Metrics) RecordVerificationOperation(chain, status string) {
	m.VerificationOperations.WithLabelValues(chain, status).Inc()
}

// SetActiveConnections sets the number of active connections
func (m *Metrics) SetActiveConnections(count float64) {
	m.ActiveConnections.Set(count)
}

// SetMemoryUsage sets the memory usage
func (m *Metrics) SetMemoryUsage(bytes float64) {
	m.MemoryUsage.Set(bytes)
}

// SetDatabaseConnections sets the number of database connections
func (m *Metrics) SetDatabaseConnections(count float64) {
	m.DatabaseConnections.Set(count)
}

// MetricsMiddleware provides middleware for recording metrics
type MetricsMiddleware struct {
	metrics *Metrics
}

// NewMetricsMiddleware creates a new metrics middleware
func NewMetricsMiddleware(metrics *Metrics) *MetricsMiddleware {
	return &MetricsMiddleware{
		metrics: metrics,
	}
}

// RecordGRPCMethod records metrics for a gRPC method call
func (m *MetricsMiddleware) RecordGRPCMethod(method string, duration time.Duration, err error) {
	status := "success"
	if err != nil {
		status = "error"
		m.metrics.RecordRequestError(method, "grpc_error")
	}

	m.metrics.RecordRequest(method, status, duration)
}

// RecordHTTPRequest records metrics for an HTTP request
func (m *MetricsMiddleware) RecordHTTPRequest(method, path string, statusCode int, duration time.Duration) {
	status := "success"
	if statusCode >= 400 {
		status = "error"
		m.metrics.RecordRequestError(method, "http_error")
	}

	m.metrics.RecordRequest(method, status, duration)
}
