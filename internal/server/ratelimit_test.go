package server

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestRateLimiter_PerIP(t *testing.T) {
	rl := newRateLimiter(2, 60*time.Second)

	// IP 1: 2 requests should be allowed
	ok, _ := rl.allow("192.0.2.1")
	if !ok {
		t.Fatal("expected request 1 of IP 1 to be allowed")
	}
	ok, _ = rl.allow("192.0.2.1")
	if !ok {
		t.Fatal("expected request 2 of IP 1 to be allowed")
	}
	// 3rd request for IP 1 should be blocked
	ok, _ = rl.allow("192.0.2.1")
	if ok {
		t.Fatal("expected request 3 of IP 1 to be blocked")
	}

	// IP 2: should still get its own quota
	ok, _ = rl.allow("192.0.2.2")
	if !ok {
		t.Fatal("expected request 1 of IP 2 to be allowed")
	}
	ok, _ = rl.allow("192.0.2.2")
	if !ok {
		t.Fatal("expected request 2 of IP 2 to be allowed")
	}
	// 3rd request for IP 2 should also be blocked
	ok, _ = rl.allow("192.0.2.2")
	if ok {
		t.Fatal("expected request 3 of IP 2 to be blocked")
	}
}

func TestRateLimiter_BruteForce(t *testing.T) {
	rl := newRateLimiter(10, 60*time.Second)

	var wg sync.WaitGroup
	wg.Add(100)

	allowed := make(chan bool, 100)
	for range 100 {
		go func() {
			defer wg.Done()
			a, _ := rl.allow("10.0.0.1")
			allowed <- a
		}()
	}

	wg.Wait()
	close(allowed)

	allowedCount := 0
	for a := range allowed {
		if a {
			allowedCount++
		}
	}

	if allowedCount != 10 {
		t.Fatalf("expected exactly 10 allowed requests, got %d", allowedCount)
	}
}

func TestRateLimiter_Cleanup(t *testing.T) {
	rl := newRateLimiter(5, 100*time.Millisecond)

	// Fill quota for two IPs
	for range 5 {
		rl.allow("192.0.2.1")
	}
	for range 5 {
		rl.allow("192.0.2.2")
	}

	// Both should be blocked now
	ok, _ := rl.allow("192.0.2.1")
	if ok {
		t.Fatal("expected IP 1 to be rate-limited")
	}
	ok, _ = rl.allow("192.0.2.2")
	if ok {
		t.Fatal("expected IP 2 to be rate-limited")
	}

	// Wait for the window to expire
	time.Sleep(150 * time.Millisecond)

	// Now both should be allowed again (new window)
	ok, count := rl.allow("192.0.2.1")
	if !ok {
		t.Fatal("expected IP 1 to be allowed after window expiry")
	}
	if count != 1 {
		t.Fatalf("expected count 1 for IP 1, got %d", count)
	}

	ok, count = rl.allow("192.0.2.2")
	if !ok {
		t.Fatal("expected IP 2 to be allowed after window expiry")
	}
	if count != 1 {
		t.Fatalf("expected count 1 for IP 2, got %d", count)
	}
}

func TestRateLimiter_AllowInitially(t *testing.T) {
	rl := newRateLimiter(10, 60*time.Second)

	ok, count := rl.allow("192.0.2.1")
	if !ok {
		t.Fatal("expected first request to be allowed")
	}
	if count != 1 {
		t.Fatalf("expected count 1, got %d", count)
	}
}

func TestClientIP_FallbackToRemoteAddr(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.1:12345"

	ip := clientIP(r)
	if ip != "10.0.0.1" {
		t.Fatalf("expected 10.0.0.1, got %s", ip)
	}
}

func TestClientIP_XRealIP(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "192.168.1.1:54321"
	r.Header.Set("X-Real-IP", "203.0.113.1")

	ip := clientIP(r)
	if ip != "203.0.113.1" {
		t.Fatalf("expected 203.0.113.1, got %s", ip)
	}
}

func TestClientIP_XForwardedFor(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "192.168.1.1:54321"
	r.Header.Set("X-Forwarded-For", "198.51.100.1, 10.0.0.1")

	ip := clientIP(r)
	if ip != "198.51.100.1" {
		t.Fatalf("expected 198.51.100.1, got %s", ip)
	}
}

func TestWithRateLimit_Middleware(t *testing.T) {
	rl := newRateLimiter(1, 60*time.Second)

	s := &Server{rateLimiter: rl}
	handler := s.withRateLimit(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	// First request from IP should succeed
	r1 := httptest.NewRequest("GET", "/", nil)
	r1.RemoteAddr = "10.0.0.5:9999"
	w1 := httptest.NewRecorder()
	handler(w1, r1)
	if w1.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w1.Code)
	}

	// Second request from same IP should be rate-limited
	r2 := httptest.NewRequest("GET", "/", nil)
	r2.RemoteAddr = "10.0.0.5:9999"
	w2 := httptest.NewRecorder()
	handler(w2, r2)
	if w2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", w2.Code)
	}
	if w2.Header().Get("Retry-After") != "60" {
		t.Fatalf("expected Retry-After: 60, got %s", w2.Header().Get("Retry-After"))
	}
}