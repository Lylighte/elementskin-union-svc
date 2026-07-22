package session

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSetSessionCookieSecurityAttributes(t *testing.T) {
	rec := httptest.NewRecorder()
	SetSessionCookie(rec, "session-value", time.Hour)

	resp := rec.Result()
	cookies := resp.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
	c := cookies[0]

	if c.Name != cookieName {
		t.Errorf("Name = %q, want %q", c.Name, cookieName)
	}
	if c.Value != "session-value" {
		t.Errorf("Value = %q, want session-value", c.Value)
	}
	if c.Path != "/" {
		t.Errorf("Path = %q, want /", c.Path)
	}
	if c.MaxAge != int(time.Hour.Seconds()) {
		t.Errorf("MaxAge = %d, want %d", c.MaxAge, int(time.Hour.Seconds()))
	}
	if !c.HttpOnly {
		t.Error("HttpOnly = false, want true")
	}
	if !c.Secure {
		t.Error("Secure = false, want true")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want Lax", c.SameSite)
	}
}

func TestGetSessionCookieRoundTrip(t *testing.T) {
	rec := httptest.NewRecorder()
	SetSessionCookie(rec, "round-trip-value", time.Hour)

	resp := rec.Result()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, c := range resp.Cookies() {
		req.AddCookie(c)
	}

	got := GetSessionCookie(req)
	if got != "round-trip-value" {
		t.Errorf("GetSessionCookie = %q, want round-trip-value", got)
	}
}

func TestGetSessionCookieMissing(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	got := GetSessionCookie(req)
	if got != "" {
		t.Errorf("GetSessionCookie = %q, want empty", got)
	}
}

func TestClearSessionCookie(t *testing.T) {
	rec := httptest.NewRecorder()
	ClearSessionCookie(rec)

	resp := rec.Result()
	cookies := resp.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
	c := cookies[0]

	if c.Name != cookieName {
		t.Errorf("Name = %q, want %q", c.Name, cookieName)
	}
	if c.Value != "" {
		t.Errorf("Value = %q, want empty", c.Value)
	}
	if c.MaxAge != -1 {
		t.Errorf("MaxAge = %d, want -1", c.MaxAge)
	}
	if !c.HttpOnly {
		t.Error("HttpOnly = false, want true")
	}
	if !c.Secure {
		t.Error("Secure = false, want true")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want Lax", c.SameSite)
	}
}

func TestSetSessionCookieHeaderFlags(t *testing.T) {
	rec := httptest.NewRecorder()
	SetSessionCookie(rec, "flags-value", 2*time.Hour)

	header := rec.Header().Get("Set-Cookie")
	if header == "" {
		t.Fatal("missing Set-Cookie header")
	}
	lower := strings.ToLower(header)
	for _, want := range []string{"httponly", "secure", "samesite=lax", "path=/"} {
		if !strings.Contains(lower, want) {
			t.Errorf("Set-Cookie header %q missing %q", header, want)
		}
	}
}
