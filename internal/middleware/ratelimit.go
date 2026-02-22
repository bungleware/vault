package middleware

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// IPRateLimiter manages rate limiters per IP address
type IPRateLimiter struct {
	limiters map[string]*limiterEntry
	mu       sync.RWMutex
	rate     rate.Limit
	burst    int
}

type limiterEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// NewIPRateLimiter creates a new rate limiter with the specified requests per minute and burst
func NewIPRateLimiter(requestsPerMin int, burst int) *IPRateLimiter {
	rl := &IPRateLimiter{
		limiters: make(map[string]*limiterEntry),
		rate:     rate.Limit(float64(requestsPerMin) / 60.0), // Convert per-minute to per-second
		burst:    burst,
	}

	// Start cleanup goroutine
	go rl.cleanupStaleEntries()

	return rl
}

// getLimiter gets or creates a rate limiter for an IP address
func (rl *IPRateLimiter) getLimiter(ip string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	entry, exists := rl.limiters[ip]
	if !exists {
		limiter := rate.NewLimiter(rl.rate, rl.burst)
		rl.limiters[ip] = &limiterEntry{
			limiter:  limiter,
			lastSeen: time.Now(),
		}
		return limiter
	}

	entry.lastSeen = time.Now()
	return entry.limiter
}

// cleanupStaleEntries removes rate limiters that haven't been used in over an hour
func (rl *IPRateLimiter) cleanupStaleEntries() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		for ip, entry := range rl.limiters {
			if now.Sub(entry.lastSeen) > 1*time.Hour {
				delete(rl.limiters, ip)
			}
		}
		rl.mu.Unlock()
	}
}

// extractIP gets the client IP from the request
func extractIP(r *http.Request) string {
	// Check X-Forwarded-For header first (for proxies/load balancers)
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		// Take the first IP in the list
		ips := strings.Split(forwarded, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check X-Real-IP header
	realIP := r.Header.Get("X-Real-IP")
	if realIP != "" {
		return realIP
	}

	// Fall back to RemoteAddr
	// RemoteAddr is in the format "IP:port", so we need to split it
	ip := r.RemoteAddr
	if colonIdx := strings.LastIndex(ip, ":"); colonIdx != -1 {
		ip = ip[:colonIdx]
	}

	return ip
}

// RateLimit returns a middleware that enforces rate limiting
func (rl *IPRateLimiter) RateLimit(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := extractIP(r)
		limiter := rl.getLimiter(ip)

		if !limiter.Allow() {
			// Calculate retry-after in seconds
			reservation := limiter.Reserve()
			retryAfter := int(reservation.Delay().Seconds()) + 1
			reservation.Cancel() // Cancel the reservation since we're not allowing the request

			w.Header().Set("Retry-After", fmt.Sprintf("%d", retryAfter))
			w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", int(rl.rate*60)))
			w.Header().Set("X-RateLimit-Remaining", "0")

			slog.WarnContext(r.Context(), "Rate limit exceeded",
				"ip", ip,
				"path", r.URL.Path,
				"retry_after", retryAfter,
			)

			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"error": "Rate limit exceeded. Please try again later."}`))
			return
		}

		// Add rate limit headers
		w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", int(rl.rate*60)))
		// Note: Remaining tokens is approximate due to concurrent requests
		w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", int(limiter.Tokens())))

		next(w, r)
	}
}
