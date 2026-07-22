package server

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type rateEntry struct {
	count       int
	windowStart time.Time
}

type rateLimiter struct {
	mu      sync.Mutex
	entries map[string]*rateEntry
	limit   int
	window  time.Duration
}

const (
	rateLimitCount   = 10
	rateLimitWindow  = 60 * time.Second
	rateLimitCleanup = 5 * time.Minute
)

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	rl := &rateLimiter{
		entries: make(map[string]*rateEntry),
		limit:   limit,
		window:  window,
	}
	go rl.cleanupLoop()
	return rl
}

func (rl *rateLimiter) cleanupLoop() {
	for {
		time.Sleep(rateLimitCleanup)
		rl.mu.Lock()
		now := time.Now()
		for ip, entry := range rl.entries {
			if entry.windowStart.Add(rl.window).Before(now) {
				delete(rl.entries, ip)
			}
		}
		rl.mu.Unlock()
	}
}

func (rl *rateLimiter) allow(ip string) (bool, int) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	entry, exists := rl.entries[ip]

	if !exists || entry.windowStart.Add(rl.window).Before(now) {
		rl.entries[ip] = &rateEntry{
			count:       1,
			windowStart: now,
		}
		return true, 1
	}

	entry.count++
	if entry.count > rl.limit {
		return false, entry.count
	}

	return true, entry.count
}

// withRateLimit wraps a handler with IP-based rate limiting.
// It is the outermost middleware: requests consume quota even on auth failure.
func (s *Server) withRateLimit(fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)

		ok, _ := s.rateLimiter.allow(ip)
		if !ok {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "60")
			w.WriteHeader(http.StatusTooManyRequests)
			_ = json.NewEncoder(w).Encode(map[string]string{"detail": "rate limit exceeded"})
			return
		}

		fn(w, r)
	}
}

// clientIP extracts the client IP from a request, checking headers first.
func clientIP(r *http.Request) string {
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.SplitN(xff, ",", 2)
		return strings.TrimSpace(parts[0])
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}