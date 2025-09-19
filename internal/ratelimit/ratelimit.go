package ratelimit

import (
	"context"
	"fmt"
	"sync"
	"time"

	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// RateLimiter provides rate limiting functionality
type RateLimiter struct {
	limiters map[string]*rate.Limiter
	mu       sync.RWMutex
	config   *Config
}

// Config holds rate limiting configuration
type Config struct {
	// Default rate limit (requests per second)
	DefaultRate float64

	// Burst size for default rate
	DefaultBurst int

	// Per-method rate limits
	MethodLimits map[string]MethodLimit

	// Per-user rate limits
	UserLimits map[string]UserLimit

	// Cleanup interval for expired limiters
	CleanupInterval time.Duration
}

// MethodLimit defines rate limits for specific gRPC methods
type MethodLimit struct {
	Rate  float64 // requests per second
	Burst int     // burst size
}

// UserLimit defines rate limits for specific users
type UserLimit struct {
	Rate  float64 // requests per second
	Burst int     // burst size
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(config *Config) *RateLimiter {
	if config == nil {
		config = &Config{
			DefaultRate:     10.0, // 10 requests per second
			DefaultBurst:    20,   // burst of 20 requests
			MethodLimits:    make(map[string]MethodLimit),
			UserLimits:      make(map[string]UserLimit),
			CleanupInterval: 5 * time.Minute,
		}
	}

	rl := &RateLimiter{
		limiters: make(map[string]*rate.Limiter),
		config:   config,
	}

	// Start cleanup goroutine
	go rl.cleanup()

	return rl
}

// Allow checks if a request should be allowed based on rate limits
func (rl *RateLimiter) Allow(ctx context.Context, method, userID string) error {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Create key for this combination
	key := rl.getKey(method, userID)

	// Get or create limiter
	limiter, exists := rl.limiters[key]
	if !exists {
		limiter = rl.createLimiter(method, userID)
		rl.limiters[key] = limiter
	}

	// Check if request is allowed
	if !limiter.Allow() {
		return status.Errorf(codes.ResourceExhausted,
			"rate limit exceeded for method %s", method)
	}

	return nil
}

// AllowN checks if N requests should be allowed
func (rl *RateLimiter) AllowN(ctx context.Context, method, userID string, n int) error {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	key := rl.getKey(method, userID)

	limiter, exists := rl.limiters[key]
	if !exists {
		limiter = rl.createLimiter(method, userID)
		rl.limiters[key] = limiter
	}

	if !limiter.AllowN(time.Now(), n) {
		return status.Errorf(codes.ResourceExhausted,
			"rate limit exceeded for method %s (requested %d)", method, n)
	}

	return nil
}

// Wait blocks until the request can be processed
func (rl *RateLimiter) Wait(ctx context.Context, method, userID string) error {
	rl.mu.RLock()
	key := rl.getKey(method, userID)
	limiter, exists := rl.limiters[key]
	rl.mu.RUnlock()

	if !exists {
		rl.mu.Lock()
		limiter = rl.createLimiter(method, userID)
		rl.limiters[key] = limiter
		rl.mu.Unlock()
	}

	// Wait for rate limiter
	if err := limiter.Wait(ctx); err != nil {
		return status.Errorf(codes.DeadlineExceeded,
			"rate limiter wait timeout for method %s", method)
	}

	return nil
}

// getKey creates a unique key for the method-user combination
func (rl *RateLimiter) getKey(method, userID string) string {
	return fmt.Sprintf("%s:%s", method, userID)
}

// createLimiter creates a new rate limiter with appropriate limits
func (rl *RateLimiter) createLimiter(method, userID string) *rate.Limiter {
	// Check for method-specific limits first
	if methodLimit, exists := rl.config.MethodLimits[method]; exists {
		return rate.NewLimiter(rate.Limit(methodLimit.Rate), methodLimit.Burst)
	}

	// Check for user-specific limits
	if userLimit, exists := rl.config.UserLimits[userID]; exists {
		return rate.NewLimiter(rate.Limit(userLimit.Rate), userLimit.Burst)
	}

	// Use default limits
	return rate.NewLimiter(rate.Limit(rl.config.DefaultRate), rl.config.DefaultBurst)
}

// cleanup removes unused limiters to prevent memory leaks
func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(rl.config.CleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()

		// Remove limiters that haven't been used recently
		for key, limiter := range rl.limiters {
			// Simple cleanup: remove if limiter has no tokens and hasn't been used
			if limiter.Tokens() >= float64(limiter.Burst()) {
				// Check if limiter has been idle for too long
				// This is a simplified approach - in production you'd track last access time
				_ = now // Suppress unused variable warning
				delete(rl.limiters, key)
			}
		}

		rl.mu.Unlock()
	}
}

// GetStats returns current rate limiter statistics
func (rl *RateLimiter) GetStats() map[string]interface{} {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	stats := map[string]interface{}{
		"active_limiters": len(rl.limiters),
		"config": map[string]interface{}{
			"default_rate":  rl.config.DefaultRate,
			"default_burst": rl.config.DefaultBurst,
		},
	}

	return stats
}

// SetMethodLimit sets rate limit for a specific method
func (rl *RateLimiter) SetMethodLimit(method string, rate float64, burst int) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	rl.config.MethodLimits[method] = MethodLimit{
		Rate:  rate,
		Burst: burst,
	}
}

// SetUserLimit sets rate limit for a specific user
func (rl *RateLimiter) SetUserLimit(userID string, rate float64, burst int) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	rl.config.UserLimits[userID] = UserLimit{
		Rate:  rate,
		Burst: burst,
	}
}

// RemoveUserLimit removes rate limit for a specific user
func (rl *RateLimiter) RemoveUserLimit(userID string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	delete(rl.config.UserLimits, userID)

	// Remove existing limiters for this user
	for key := range rl.limiters {
		if len(key) > len(userID)+1 && key[len(key)-len(userID)-1:] == ":"+userID {
			delete(rl.limiters, key)
		}
	}
}

// RateLimitInterceptor creates a gRPC interceptor for rate limiting
func RateLimitInterceptor(limiter *RateLimiter) func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		// Extract user ID from context (you'd implement this based on your auth system)
		userID := getUserIDFromContext(ctx)

		// Apply rate limiting
		if err := limiter.Allow(ctx, info.FullMethod, userID); err != nil {
			return nil, err
		}

		// Call the actual handler
		return handler(ctx, req)
	}
}

// getUserIDFromContext extracts user ID from gRPC context
func getUserIDFromContext(ctx context.Context) string {
	// This is a placeholder - implement based on your authentication system
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "anonymous"
	}

	userIDs := md.Get("user_id")
	if len(userIDs) > 0 {
		return userIDs[0]
	}

	return "anonymous"
}
