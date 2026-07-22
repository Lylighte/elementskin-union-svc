package server

import (
	"embed"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/Lylighte/elementskin-union-svc/internal/bridge"
	"github.com/Lylighte/elementskin-union-svc/internal/config"
	"github.com/Lylighte/elementskin-union-svc/internal/oauth"
	"github.com/Lylighte/elementskin-union-svc/internal/session"
	"github.com/Lylighte/elementskin-union-svc/internal/union"
)

//go:embed static/index.html
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
	}
	s.routes()
	return s, nil
}

func (s *Server) route(path string) string {
	return s.cfg.Server.RootPath + path
}

func (s *Server) routes() {
	root := s.route("/")
	s.mux.HandleFunc(s.route("/health"), func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	s.mux.HandleFunc(s.route("/oauth/authorize"), s.handleAuthorize)
	s.mux.HandleFunc(s.route("/oauth/callback"), s.handleCallback)
	s.mux.HandleFunc(s.route("/api/profiles"), s.withBearerToken(s.handleListProfiles))
	s.mux.HandleFunc(s.route("GET /api/union/member/"), s.handleUnionHello)
	s.mux.HandleFunc(s.route("POST /api/union/member/updatelist"), s.withUnionVerify(s.handleUpdateList))
	s.mux.HandleFunc(s.route("POST /api/union/member/updateprivatekey"), s.withUnionVerify(s.handleUpdatePrivateKey))
	s.mux.HandleFunc(s.route("POST /api/union/member/updatebackendkey"), s.withUnionVerify(s.handleUpdateBackendKey))
	s.mux.HandleFunc(s.route("POST /api/union/member/sync"), s.withUnionVerify(s.handleSync))
	s.mux.HandleFunc(s.route("GET /api/union/member/queryemail"), s.withUnionVerify(s.handleQueryEmail))
	s.mux.HandleFunc(s.route("POST /api/union/member/diagnose"), s.withUnionVerify(s.handleDiagnose))

	s.mux.HandleFunc(s.route("GET /api/union/member/oauth2/"), s.handleOAuth2GetSigPublicKey)
	s.mux.HandleFunc(s.route("GET /api/union/member/oauth2/grant"), s.handleOAuth2Grant)

	s.mux.HandleFunc(s.route("GET /api/union/admin/blacklist"), s.withAdminAPIKey(s.handleBlacklistList))
	s.mux.HandleFunc(s.route("POST /api/union/admin/blacklist"), s.withAdminAPIKey(s.handleBlacklistCreate))
	s.mux.HandleFunc(s.route("PUT /api/union/admin/blacklist/invalidate/{id}"), s.withAdminAPIKey(s.handleBlacklistInvalidate))
	s.mux.HandleFunc(s.route("DELETE /api/union/admin/blacklist/{id}"), s.withAdminAPIKey(s.handleBlacklistDelete))

	s.mux.HandleFunc(s.route("POST /api/union/profile/bind"), s.withBearerToken(s.handleProfileBind))
	s.mux.HandleFunc(s.route("POST /api/union/profile/unbind"), s.withBearerToken(s.handleProfileUnbind))
	s.mux.HandleFunc(s.route("POST /api/union/profile/bindto"), s.withBearerToken(s.handleProfileBindTo))
	s.mux.HandleFunc(s.route("GET /api/union/security/level"), s.withBearerToken(s.handleSecurityLevel))

	s.mux.HandleFunc(s.route("POST /api/union/webhook/profile-sync"), s.withWebhookSecret(s.handleProfileSyncWebhook))

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
