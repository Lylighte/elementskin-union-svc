package session

import (
	"net/http"
	"time"
)

const cookieName = "union_svc_session"

// SetSessionCookie writes the session cookie with the security flags expected
// for the Union service.
func SetSessionCookie(w http.ResponseWriter, sessionID string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    sessionID,
		Path:     "/",
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

// GetSessionCookie reads the session cookie from the request and returns its
// value. If the cookie is missing, it returns an empty string.
func GetSessionCookie(r *http.Request) string {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return ""
	}
	return c.Value
}

// ClearSessionCookie writes an empty session cookie that tells the browser to
// delete it.
func ClearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}
