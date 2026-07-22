package server

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Lylighte/elementskin-union-svc/internal/config"
	"github.com/Lylighte/elementskin-union-svc/internal/session"
)

const (
	// defaultScope is the scope requested when the authorize endpoint is called
	// without an explicit scope parameter.
	defaultScope = "account.read.self profile.read.owned"

	sessionTTL = 1 * time.Hour
)

func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	state, err := generateState()
	if err != nil {
		s.logger.Error("failed to generate state", "error", err)
		http.Error(w, "failed to initiate authorization", http.StatusInternalServerError)
		return
	}
	verifier, err := generateVerifier()
	if err != nil {
		s.logger.Error("failed to generate verifier", "error", err)
		http.Error(w, "failed to initiate authorization", http.StatusInternalServerError)
		return
	}
	challenge := challengeS256(verifier)

	redirectURI := s.cfg.Elementskin.OAuth.RedirectURI
	scope := r.URL.Query().Get("scope")
	if scope == "" {
		scope = defaultScope
	}

	entry := State{
		State:       state,
		Verifier:    verifier,
		RedirectURI: redirectURI,
		Scope:       scope,
		ExpiresAtMS: time.Now().UTC().Add(stateExpiry).UnixMilli(),
	}
	if err := s.stateStore.Save(r.Context(), entry); err != nil {
		s.logger.Error("failed to save oauth state", "error", err)
		http.Error(w, "failed to initiate authorization", http.StatusInternalServerError)
		return
	}

	authURL, err := buildAuthorizeURL(oAuthAuthorizeBase(s.cfg), s.cfg.Elementskin.OAuth.ClientID, redirectURI, scope, state, challenge)
	if err != nil {
		s.logger.Error("failed to build authorize url", "error", err)
		http.Error(w, "failed to initiate authorization", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, authURL, http.StatusFound)
}

func oAuthAuthorizeBase(cfg config.Config) string {
	if cfg.Elementskin.SiteURL != "" {
		return cfg.Elementskin.SiteURL
	}
	return cfg.Elementskin.BaseURL
}

func buildAuthorizeURL(baseURL, clientID, redirectURI, scope, state, challenge string) (string, error) {
	baseURL = strings.TrimRight(baseURL, "/")
	u, err := url.Parse(baseURL + "/oauth/authorize")
	if err != nil {
		return "", fmt.Errorf("parse authorize url: %w", err)
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", scope)
	q.Set("state", state)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	if code == "" || state == "" {
		http.Error(w, "missing code or state", http.StatusBadRequest)
		return
	}

	entry, err := s.stateStore.Load(r.Context(), state)
	if err != nil {
		http.Error(w, "invalid or expired state", http.StatusBadRequest)
		return
	}

	// Best-effort cleanup; failures are not fatal.
	_ = s.stateStore.Delete(r.Context(), state)

	if err := s.manager.ExchangeCode(r.Context(), code, entry.Verifier); err != nil {
		s.logger.Error("token exchange failed", "error", err)
		http.Error(w, "token exchange failed", http.StatusBadRequest)
		return
	}

	accessToken, err := s.manager.AccessToken(r.Context())
	if err != nil {
		s.logger.Error("failed to retrieve access token after exchange", "error", err)
	} else {
		sessionID, err := s.sessionStore.Create(r.Context(), accessToken, sessionTTL)
		if err != nil {
			s.logger.Error("failed to create session", "error", err)
		} else {
			session.SetSessionCookie(w, sessionID, sessionTTL)
		}
	}

	http.Redirect(w, r, s.cfg.Server.RootPath+"/?authorized=true", http.StatusFound)
}

// authorizeURLForConfig is a test helper that returns the redirect URL a
// browser would be sent to for the given configuration and state values.
func authorizeURLForConfig(cfg config.Config, scope, state, challenge string) (string, error) {
	return buildAuthorizeURL(oAuthAuthorizeBase(cfg), cfg.Elementskin.OAuth.ClientID, cfg.Elementskin.OAuth.RedirectURI, scope, state, challenge)
}
