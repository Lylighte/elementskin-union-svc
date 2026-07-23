package server

import (
	"embed"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/Lylighte/elementskin-union-svc/internal/bridge"
	"github.com/Lylighte/elementskin-union-svc/internal/config"
	"github.com/Lylighte/elementskin-union-svc/internal/oauth"
	"github.com/Lylighte/elementskin-union-svc/internal/session"
	"github.com/Lylighte/elementskin-union-svc/internal/union"
)

//go:embed static/index.html static/admin.html static/admin.js
var staticFiles embed.FS

func indexHTML(logger *slog.Logger) []byte {
	b, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		logger.Error("failed to read embedded static/index.html", "error", err)
	}
	return b
}

// Server is the union-svc HTTP server.
type Server struct {
	cfg           config.Config
	manager       *oauth.Manager
	serviceTokens *oauth.ServiceTokenManager
	unionClient   *union.Client
	bridge        *bridge.Bridge
	stateStore    *StateStore
	sessionStore  *session.Store
	httpClient    *http.Client
	logger        *slog.Logger
	mux           *http.ServeMux
	rateLimiter   *rateLimiter
}

// New creates a Server from configuration, opening the token and state stores.
func New(cfg config.Config, logger *slog.Logger) (*Server, error) {
	httpClient := &http.Client{Timeout: 30 * time.Second}

	manager, err := oauth.NewManager(cfg, httpClient)
	if err != nil {
		return nil, err
	}

	stateStore, err := OpenStateStore(cfg.Storage.Path)
	if err != nil {
		_ = manager.Close()
		return nil, err
	}

	sessionStore, err := session.OpenStore(cfg.Storage.Path)
	if err != nil {
		_ = stateStore.Close()
		_ = manager.Close()
		return nil, err
	}

	serviceTokens, err := oauth.NewServiceTokenManager(cfg, httpClient)
	if err != nil {
		_ = stateStore.Close()
		_ = manager.Close()
		return nil, err
	}

	unionClient, err := union.NewClient(cfg, httpClient)
	if err != nil {
		_ = serviceTokens.Close()
		_ = stateStore.Close()
		_ = manager.Close()
		return nil, err
	}

	b := bridge.New(cfg.Elementskin.BaseURL, unionClient, manager, serviceTokens, httpClient)

	s := &Server{
		cfg:           cfg,
		manager:       manager,
		serviceTokens: serviceTokens,
		unionClient:   unionClient,
		bridge:        b,
		stateStore:    stateStore,
		sessionStore:  sessionStore,
		httpClient:    httpClient,
		logger:        logger,
		mux:           http.NewServeMux(),
		rateLimiter:   newRateLimiter(rateLimitCount, rateLimitWindow),
	}
	s.routes()
	return s, nil
}

func (s *Server) route(pattern string) string {
	rp := s.cfg.Server.RootPath
	if rp == "" {
		return pattern
	}
	if idx := strings.Index(pattern, " "); idx != -1 {
		return pattern[:idx+1] + rp + pattern[idx+1:]
	}
	return rp + pattern
}

func (s *Server) routes() {
	root := s.route("/")
	s.mux.HandleFunc(s.route("/health"), func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	s.mux.HandleFunc(s.route("/oauth/authorize"), s.handleAuthorize)
	s.mux.HandleFunc(s.route("/oauth/callback"), s.handleCallback)
	s.mux.HandleFunc(s.route("/api/profiles"), s.withBearerOrSession(s.handleListProfiles))
	s.mux.HandleFunc(s.route("GET /api/union/member/"), s.handleUnionHello)
	s.mux.HandleFunc(s.route("POST /api/union/member/updatelist"), s.withUnionVerify(s.handleUpdateList))
	s.mux.HandleFunc(s.route("POST /api/union/member/updateprivatekey"), s.withUnionVerify(s.handleUpdatePrivateKey))
	s.mux.HandleFunc(s.route("POST /api/union/member/updatebackendkey"), s.withUnionVerify(s.handleUpdateBackendKey))
	s.mux.HandleFunc(s.route("POST /api/union/member/sync"), s.withUnionVerify(s.handleSync))
	s.mux.HandleFunc(s.route("GET /api/union/member/queryemail"), s.withUnionVerify(s.handleQueryEmail))
	s.mux.HandleFunc(s.route("POST /api/union/member/diagnose"), s.withUnionVerify(s.handleDiagnose))

	s.mux.HandleFunc(s.route("GET /api/union/member/oauth2/"), s.handleOAuth2GetSigPublicKey)
	s.mux.HandleFunc(s.route("GET /api/union/member/oauth2/grant"), s.handleOAuth2Grant)

	s.mux.HandleFunc(s.route("GET /api/union/admin/blacklist"), s.withRateLimit(s.withAdminAPIKey(s.handleBlacklistList)))
	s.mux.HandleFunc(s.route("POST /api/union/admin/blacklist"), s.withRateLimit(s.withAdminAPIKey(s.handleBlacklistCreate)))
	s.mux.HandleFunc(s.route("PUT /api/union/admin/blacklist/invalidate/{id}"), s.withRateLimit(s.withAdminAPIKey(s.handleBlacklistInvalidate)))
	s.mux.HandleFunc(s.route("DELETE /api/union/admin/blacklist/{id}"), s.withRateLimit(s.withAdminAPIKey(s.handleBlacklistDelete)))

	s.mux.HandleFunc(s.route("POST /api/union/admin/sync"), s.withRateLimit(s.withAdminAPIKey(s.handleAdminSync)))
	s.mux.HandleFunc(s.route("POST /api/union/admin/update-list"), s.withRateLimit(s.withAdminAPIKey(s.handleAdminUpdateList)))
	s.mux.HandleFunc(s.route("POST /api/union/admin/update-key"), s.withRateLimit(s.withAdminAPIKey(s.handleAdminUpdateKey)))
	s.mux.HandleFunc(s.route("POST /api/union/admin/diagnose"), s.withRateLimit(s.withAdminAPIKey(s.handleAdminDiagnose)))
	s.mux.HandleFunc(s.route("GET /api/union/admin/status"), s.withRateLimit(s.withAdminAPIKey(s.handleAdminStatus)))
	s.mux.HandleFunc(s.route("GET /api/union/admin/keypair-fingerprint"), s.withRateLimit(s.withAdminAPIKey(s.handleAdminKeypairFingerprint)))
	s.mux.HandleFunc(s.route("POST /api/union/admin/regenerate-keypair"), s.withRateLimit(s.withAdminAPIKey(s.handleAdminRegenerateKeypair)))

	s.mux.HandleFunc(s.route("POST /api/union/profile/bind"), s.withBearerOrSession(s.handleProfileBind))
	s.mux.HandleFunc(s.route("POST /api/union/profile/unbind"), s.withBearerOrSession(s.handleProfileUnbind))
	s.mux.HandleFunc(s.route("POST /api/union/profile/bindto"), s.withBearerOrSession(s.handleProfileBindTo))
	s.mux.HandleFunc(s.route("GET /api/union/security/level"), s.withBearerOrSession(s.handleSecurityLevel))

	s.mux.HandleFunc(s.route("POST /api/union/webhook/profile-sync"), s.withWebhookSecret(s.handleProfileSyncWebhook))

	s.mux.HandleFunc(s.route("/admin"), func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'")
		b, err := staticFiles.ReadFile("static/admin.html")
		if err != nil {
			s.logger.Error("failed to read embedded static/admin.html", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(b)
	})
	s.mux.HandleFunc(s.route("/admin.js"), func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		b, err := staticFiles.ReadFile("static/admin.js")
		if err != nil {
			s.logger.Error("failed to read embedded static/admin.js", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(b)
	})

	s.mux.HandleFunc(root, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != root {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(indexHTML(s.logger))
	})
}

// withUnionVerify wraps an inbound Union handler with Hub signature
// verification. On failure it returns HTTP 401 with a JSON detail body.
func (s *Server) withUnionVerify(fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := s.unionClient.VerifyInboundRequest(r.Context(), r); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"detail": err.Error()})
			return
		}
		fn(w, r)
	}
}

// settingsStore returns the Union runtime settings store used by inbound
// handlers to persist member keys and version numbers.
func (s *Server) settingsStore() *union.SettingsStore {
	return s.unionClient.SettingsStore()
}

// Handler returns the server's http.Handler.
func (s *Server) Handler() http.Handler {
	return s.mux
}

// Close closes the underlying stores.
func (s *Server) Close() error {
	var first error
	if err := s.manager.Close(); err != nil {
		first = err
	}
	if err := s.serviceTokens.Close(); err != nil && first == nil {
		first = err
	}
	if err := s.unionClient.Close(); err != nil && first == nil {
		first = err
	}
	if err := s.sessionStore.Close(); err != nil && first == nil {
		first = err
	}
	if err := s.stateStore.Close(); err != nil && first == nil {
		first = err
	}
	return first
}
