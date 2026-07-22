package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDefaults verifies that Load with all required fields set uses the
// expected default values for optional fields.
func TestDefaults(t *testing.T) {
	t.Setenv("UNION_ELEMENTSKIN_BASE_URL", "https://skin.example.com")
	t.Setenv("UNION_ELEMENTSKIN_OAUTH_CLIENT_ID", "cid")
	t.Setenv("UNION_ELEMENTSKIN_OAUTH_CLIENT_SECRET", "secret")
	t.Setenv("UNION_ELEMENTSKIN_OAUTH_REDIRECT_URI", "https://skin.example.com/oauth/callback")
	t.Setenv("UNION_ELEMENTSKIN_SERVICE_ACCOUNT_CLIENT_ID", "svc-cid")
	t.Setenv("UNION_ELEMENTSKIN_SERVICE_ACCOUNT_CLIENT_SECRET", "svc-secret")
	t.Setenv("UNION_UNION_HUB_URL", "https://hub.example.com")
	t.Setenv("UNION_UNION_MEMBER_KEY", "member-key")
	t.Setenv("UNION_UNION_ADMIN_API_KEY", "admin-key")
	t.Setenv("UNION_UNION_WEBHOOK_SECRET", "webhook-secret")
	t.Setenv("UNION_STORAGE_PATH", "/data/union.db")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load empty path: %v", err)
	}

	if cfg.Server.Addr != "" {
		t.Errorf("Server.Addr = %q, want empty", cfg.Server.Addr)
	}
	if cfg.Server.Port != 8001 {
		t.Errorf("Server.Port = %d, want 8001", cfg.Server.Port)
	}
	if cfg.Elementskin.BaseURL != "https://skin.example.com" {
		t.Errorf("Elementskin.BaseURL = %q, want https://skin.example.com", cfg.Elementskin.BaseURL)
	}
	if cfg.Elementskin.OAuth.RedirectURI != "https://skin.example.com/oauth/callback" {
		t.Errorf("Elementskin.OAuth.RedirectURI = %q, want https://skin.example.com/oauth/callback", cfg.Elementskin.OAuth.RedirectURI)
	}
	if cfg.Elementskin.ServiceAccount.Scope != "profile.read.any" {
		t.Errorf("Elementskin.ServiceAccount.Scope = %q, want profile.read.any", cfg.Elementskin.ServiceAccount.Scope)
	}
	if cfg.Storage.Path != "/data/union.db" {
		t.Errorf("Storage.Path = %q, want /data/union.db", cfg.Storage.Path)
	}
	if cfg.Union.TimeoutSeconds != 30 {
		t.Errorf("Union.TimeoutSeconds = %d, want 30", cfg.Union.TimeoutSeconds)
	}
	if cfg.Union.EnableOAuth2 != true {
		t.Errorf("Union.EnableOAuth2 = %v, want true", cfg.Union.EnableOAuth2)
	}
	if cfg.Union.OAuth2SigPrivateKeyPath != "./oauth2_sig_private.pem" {
		t.Errorf("Union.OAuth2SigPrivateKeyPath = %q, want ./oauth2_sig_private.pem", cfg.Union.OAuth2SigPrivateKeyPath)
	}
	if cfg.Union.OAuth2SigPublicKeyPath != "./oauth2_sig_public.pem" {
		t.Errorf("Union.OAuth2SigPublicKeyPath = %q, want ./oauth2_sig_public.pem", cfg.Union.OAuth2SigPublicKeyPath)
	}
	if cfg.Log.Level != "info" {
		t.Errorf("Log.Level = %q, want info", cfg.Log.Level)
	}
}

// TestLoadEmptyDefaultsFailsValidation verifies that Load without any config
// file or environment variables returns a validation error listing all missing
// required fields.
func TestLoadEmptyDefaultsFailsValidation(t *testing.T) {
	_, err := Load("")
	if err == nil {
		t.Fatal("expected validation error for empty config")
	}
	msg := err.Error()
	for _, field := range []string{
		"elementskin.base_url",
		"elementskin.oauth.client_id",
		"elementskin.oauth.client_secret",
		"elementskin.oauth.redirect_uri",
		"elementskin.service_account.client_id",
		"elementskin.service_account.client_secret",
		"union.hub_url",
		"union.member_key",
		"union.admin_api_key",
		"union.webhook_secret",
	} {
		if !strings.Contains(msg, field) {
			t.Errorf("validation error missing %q: %s", field, msg)
		}
	}
	// Storage.Path has a default so it is not expected in the error.
	if strings.Contains(msg, "storage.path") {
		t.Errorf("validation error should not include storage.path (has default): %s", msg)
	}
}

// TestLoadFromYAML verifies that a YAML file overrides default values.
func TestLoadFromYAML(t *testing.T) {
	dir := t.TempDir()
	yamlPath := filepath.Join(dir, "config.yaml")
	yamlContent := `
server:
  addr: "0.0.0.0"
  port: 9090
elementskin:
  base_url: "https://elementskin.example.com"
  oauth:
    client_id: "yaml-client"
    client_secret: "yaml-secret"
    redirect_uri: "https://elementskin.example.com/oauth/callback"
  service_account:
    client_id: "yaml-svc-id"
    client_secret: "yaml-svc-secret"
storage:
  path: "/data/custom.db"
union:
  hub_url: "https://hub.example.com"
  member_key: "yaml-key"
  admin_api_key: "yaml-admin-key"
  webhook_secret: "yaml-webhook-secret"
  timeout_seconds: 60
log:
  level: "debug"
`
	if err := os.WriteFile(yamlPath, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("write config file: %v", err)
	}

	cfg, err := Load(yamlPath)
	if err != nil {
		t.Fatalf("Load yaml: %v", err)
	}

	if cfg.Server.Addr != "0.0.0.0" {
		t.Errorf("Server.Addr = %q, want 0.0.0.0", cfg.Server.Addr)
	}
	if cfg.Server.Port != 9090 {
		t.Errorf("Server.Port = %d, want 9090", cfg.Server.Port)
	}
	if cfg.Elementskin.BaseURL != "https://elementskin.example.com" {
		t.Errorf("Elementskin.BaseURL = %q, want https://elementskin.example.com", cfg.Elementskin.BaseURL)
	}
	if cfg.Elementskin.OAuth.ClientID != "yaml-client" {
		t.Errorf("Elementskin.OAuth.ClientID = %q, want yaml-client", cfg.Elementskin.OAuth.ClientID)
	}
	if cfg.Elementskin.OAuth.ClientSecret != "yaml-secret" {
		t.Errorf("Elementskin.OAuth.ClientSecret = %q, want yaml-secret", cfg.Elementskin.OAuth.ClientSecret)
	}
	if cfg.Storage.Path != "/data/custom.db" {
		t.Errorf("Storage.Path = %q, want /data/custom.db", cfg.Storage.Path)
	}
	if cfg.Union.HubURL != "https://hub.example.com" {
		t.Errorf("Union.HubURL = %q, want https://hub.example.com", cfg.Union.HubURL)
	}
	if cfg.Union.MemberKey != "yaml-key" {
		t.Errorf("Union.MemberKey = %q, want yaml-key", cfg.Union.MemberKey)
	}
	if cfg.Union.TimeoutSeconds != 60 {
		t.Errorf("Union.TimeoutSeconds = %d, want 60", cfg.Union.TimeoutSeconds)
	}
	if cfg.Log.Level != "debug" {
		t.Errorf("Log.Level = %q, want debug", cfg.Log.Level)
	}
}

// TestEnvOverride verifies that UNION_* environment variables override both
// defaults and YAML values.
func TestEnvOverride(t *testing.T) {
	dir := t.TempDir()
	yamlPath := filepath.Join(dir, "config.yaml")
	// Write a YAML that sets port, elementskin base_url, and timeout.
	yamlContent := `
server:
  port: 9999
elementskin:
  base_url: "http://from-yaml:8000"
  service_account:
    client_id: "yaml-svc-id"
    scope: "profile.read.owned"
union:
  timeout_seconds: 10
`
	if err := os.WriteFile(yamlPath, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("write config file: %v", err)
	}

	// Set env vars that should override YAML values.
	t.Setenv("UNION_SERVER_PORT", "1234")
	t.Setenv("UNION_ELEMENTSKIN_BASE_URL", "http://from-env:9000")
	t.Setenv("UNION_ELEMENTSKIN_OAUTH_CLIENT_ID", "env-oauth-cid")
	t.Setenv("UNION_ELEMENTSKIN_OAUTH_CLIENT_SECRET", "env-oauth-secret")
	t.Setenv("UNION_ELEMENTSKIN_OAUTH_REDIRECT_URI", "https://from-env.example.com/oauth/callback")
	t.Setenv("UNION_ELEMENTSKIN_SERVICE_ACCOUNT_CLIENT_ID", "env-svc-id")
	t.Setenv("UNION_ELEMENTSKIN_SERVICE_ACCOUNT_CLIENT_SECRET", "env-svc-secret")
	t.Setenv("UNION_ELEMENTSKIN_SERVICE_ACCOUNT_SCOPE", "profile.write.any")
	t.Setenv("UNION_UNION_HUB_URL", "https://hub-from-env.example.com")
	t.Setenv("UNION_UNION_MEMBER_KEY", "env-member-key")
	t.Setenv("UNION_UNION_ADMIN_API_KEY", "env-admin-key")
	t.Setenv("UNION_UNION_WEBHOOK_SECRET", "env-webhook-secret")
	t.Setenv("UNION_STORAGE_PATH", "/env/storage.db")
	t.Setenv("UNION_LOG_LEVEL", "error")

	cfg, err := Load(yamlPath)
	if err != nil {
		t.Fatalf("Load with env: %v", err)
	}

	// Env overrides YAML.
	if cfg.Server.Port != 1234 {
		t.Errorf("Server.Port = %d, want 1234 (from env)", cfg.Server.Port)
	}
	if cfg.Elementskin.BaseURL != "http://from-env:9000" {
		t.Errorf("Elementskin.BaseURL = %q, want http://from-env:9000", cfg.Elementskin.BaseURL)
	}
	if cfg.Elementskin.OAuth.ClientID != "env-oauth-cid" {
		t.Errorf("Elementskin.OAuth.ClientID = %q, want env-oauth-cid", cfg.Elementskin.OAuth.ClientID)
	}
	if cfg.Elementskin.OAuth.ClientSecret != "env-oauth-secret" {
		t.Errorf("Elementskin.OAuth.ClientSecret = %q, want env-oauth-secret", cfg.Elementskin.OAuth.ClientSecret)
	}
	if cfg.Elementskin.ServiceAccount.ClientID != "env-svc-id" {
		t.Errorf("Elementskin.ServiceAccount.ClientID = %q, want env-svc-id", cfg.Elementskin.ServiceAccount.ClientID)
	}
	if cfg.Elementskin.ServiceAccount.ClientSecret != "env-svc-secret" {
		t.Errorf("Elementskin.ServiceAccount.ClientSecret = %q, want env-svc-secret", cfg.Elementskin.ServiceAccount.ClientSecret)
	}
	if cfg.Elementskin.ServiceAccount.Scope != "profile.write.any" {
		t.Errorf("Elementskin.ServiceAccount.Scope = %q, want profile.write.any", cfg.Elementskin.ServiceAccount.Scope)
	}
	if cfg.Union.HubURL != "https://hub-from-env.example.com" {
		t.Errorf("Union.HubURL = %q, want https://hub-from-env.example.com", cfg.Union.HubURL)
	}
	if cfg.Union.MemberKey != "env-member-key" {
		t.Errorf("Union.MemberKey = %q, want env-member-key", cfg.Union.MemberKey)
	}
	if cfg.Union.AdminAPIKey != "env-admin-key" {
		t.Errorf("Union.AdminAPIKey = %q, want env-admin-key", cfg.Union.AdminAPIKey)
	}
	if cfg.Union.WebhookSecret != "env-webhook-secret" {
		t.Errorf("Union.WebhookSecret = %q, want env-webhook-secret", cfg.Union.WebhookSecret)
	}
	if cfg.Storage.Path != "/env/storage.db" {
		t.Errorf("Storage.Path = %q, want /env/storage.db", cfg.Storage.Path)
	}
	if cfg.Log.Level != "error" {
		t.Errorf("Log.Level = %q, want error", cfg.Log.Level)
	}

	// Values from YAML that were NOT overridden by env should survive.
	if cfg.Union.TimeoutSeconds != 10 {
		t.Errorf("Union.TimeoutSeconds = %d, want 10 (from yaml, unchanged)", cfg.Union.TimeoutSeconds)
	}

	// Defaults that were not touched by YAML or env should remain.
	if cfg.Server.Addr != "" {
		t.Errorf("Server.Addr = %q, want empty (default)", cfg.Server.Addr)
	}
	if cfg.Elementskin.OAuth.RedirectURI != "https://from-env.example.com/oauth/callback" {
		t.Errorf("Elementskin.OAuth.RedirectURI = %q, want https://from-env.example.com/oauth/callback", cfg.Elementskin.OAuth.RedirectURI)
	}
}

// TestLoadFullyPopulatedYAMLPassesValidation verifies that a YAML file with
// all required fields passes validation.
func TestLoadFullyPopulatedYAMLPassesValidation(t *testing.T) {
	dir := t.TempDir()
	yamlPath := filepath.Join(dir, "config.yaml")
	yamlContent := `
server:
  addr: "0.0.0.0"
  port: 8001
elementskin:
  base_url: "https://skin.example.com"
  oauth:
    client_id: "client-id"
    client_secret: "client-secret"
    redirect_uri: "https://union.example.com/oauth/callback"
  service_account:
    client_id: "svc-client-id"
    client_secret: "svc-client-secret"
    scope: "profile.read.any"
storage:
  path: "/data/union.db"
union:
  hub_url: "https://hub.example.com"
  member_key: "member-key"
  admin_api_key: "admin-key"
  webhook_secret: "webhook-secret"
  cors_allow_origin: "https://skin.example.com"
  timeout_seconds: 30
log:
  level: "info"
tls:
  insecure_skip_verify: false
  ca_file: "/etc/ssl/certs/ca.crt"
`
	if err := os.WriteFile(yamlPath, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("write config file: %v", err)
	}

	cfg, err := Load(yamlPath)
	if err != nil {
		t.Fatalf("Load fully populated config: %v", err)
	}

	if cfg.Elementskin.BaseURL != "https://skin.example.com" {
		t.Errorf("BaseURL = %q, want https://skin.example.com", cfg.Elementskin.BaseURL)
	}
	if cfg.Union.AdminAPIKey != "admin-key" {
		t.Errorf("Union.AdminAPIKey = %q, want admin-key", cfg.Union.AdminAPIKey)
	}
	if cfg.Union.WebhookSecret != "webhook-secret" {
		t.Errorf("Union.WebhookSecret = %q, want webhook-secret", cfg.Union.WebhookSecret)
	}
	if cfg.Union.EnableOAuth2 != true {
		t.Errorf("Union.EnableOAuth2 = %v, want true", cfg.Union.EnableOAuth2)
	}
	if cfg.Union.OAuth2SigPrivateKeyPath != "./oauth2_sig_private.pem" {
		t.Errorf("Union.OAuth2SigPrivateKeyPath = %q, want ./oauth2_sig_private.pem", cfg.Union.OAuth2SigPrivateKeyPath)
	}
	if cfg.Union.OAuth2SigPublicKeyPath != "./oauth2_sig_public.pem" {
		t.Errorf("Union.OAuth2SigPublicKeyPath = %q, want ./oauth2_sig_public.pem", cfg.Union.OAuth2SigPublicKeyPath)
	}
	if cfg.Union.CORSAllowOrigin != "https://skin.example.com" {
		t.Errorf("CORSAllowOrigin = %q, want https://skin.example.com", cfg.Union.CORSAllowOrigin)
	}
	if cfg.Union.HubURL != "https://hub.example.com" {
		t.Errorf("HubURL = %q, want https://hub.example.com", cfg.Union.HubURL)
	}
	if cfg.TLS.CAFile != "/etc/ssl/certs/ca.crt" {
		t.Errorf("TLS.CAFile = %q, want /etc/ssl/certs/ca.crt", cfg.TLS.CAFile)
	}
	if cfg.TLS.InsecureSkipVerify != false {
		t.Errorf("TLS.InsecureSkipVerify = %v, want false", cfg.TLS.InsecureSkipVerify)
	}
}

func TestNewUnionConfig(t *testing.T) {
	baseYAML := `
server:
  port: 8001
elementskin:
  base_url: "https://skin.example.com"
  oauth:
    client_id: "client-id"
    client_secret: "client-secret"
    redirect_uri: "https://union.example.com/oauth/callback"
  service_account:
    client_id: "svc-client-id"
    client_secret: "svc-client-secret"
    scope: "profile.read.any"
storage:
  path: "/data/union.db"
union:
  hub_url: "https://hub.example.com"
  member_key: "member-key"
`

	tests := []struct {
		name           string
		yamlExtra      string
		wantErr        bool
		wantErrContain string
		assertFn       func(t *testing.T, cfg Config)
	}{
		{
			name:      "all fields set loads OK",
			yamlExtra: "  admin_api_key: \"admin-key\"\n  webhook_secret: \"webhook-secret\"\n  enable_oauth2: true\n  oauth2_sig_private_key_path: \"/keys/private.pem\"\n  oauth2_sig_public_key_path: \"/keys/public.pem\"\n",
			wantErr:   false,
			assertFn: func(t *testing.T, cfg Config) {
				if cfg.Union.AdminAPIKey != "admin-key" {
					t.Errorf("AdminAPIKey = %q, want admin-key", cfg.Union.AdminAPIKey)
				}
				if cfg.Union.WebhookSecret != "webhook-secret" {
					t.Errorf("WebhookSecret = %q, want webhook-secret", cfg.Union.WebhookSecret)
				}
				if cfg.Union.EnableOAuth2 != true {
					t.Errorf("EnableOAuth2 = %v, want true", cfg.Union.EnableOAuth2)
				}
				if cfg.Union.OAuth2SigPrivateKeyPath != "/keys/private.pem" {
					t.Errorf("OAuth2SigPrivateKeyPath = %q, want /keys/private.pem", cfg.Union.OAuth2SigPrivateKeyPath)
				}
				if cfg.Union.OAuth2SigPublicKeyPath != "/keys/public.pem" {
					t.Errorf("OAuth2SigPublicKeyPath = %q, want /keys/public.pem", cfg.Union.OAuth2SigPublicKeyPath)
				}
			},
		},
		{
			name:           "missing admin_api_key errors",
			yamlExtra:      "  webhook_secret: \"webhook-secret\"\n",
			wantErr:        true,
			wantErrContain: "union.admin_api_key",
		},
		{
			name:           "missing webhook_secret errors",
			yamlExtra:      "  admin_api_key: \"admin-key\"\n",
			wantErr:        true,
			wantErrContain: "union.webhook_secret",
		},
		{
			name:      "enable_oauth2 defaults true when omitted",
			yamlExtra: "  admin_api_key: \"admin-key\"\n  webhook_secret: \"webhook-secret\"\n",
			wantErr:   false,
			assertFn: func(t *testing.T, cfg Config) {
				if cfg.Union.EnableOAuth2 != true {
					t.Errorf("EnableOAuth2 = %v, want true (default)", cfg.Union.EnableOAuth2)
				}
			},
		},
		{
			name:      "sig key paths default when omitted",
			yamlExtra: "  admin_api_key: \"admin-key\"\n  webhook_secret: \"webhook-secret\"\n  enable_oauth2: false\n",
			wantErr:   false,
			assertFn: func(t *testing.T, cfg Config) {
				if cfg.Union.OAuth2SigPrivateKeyPath != "./oauth2_sig_private.pem" {
					t.Errorf("OAuth2SigPrivateKeyPath = %q, want ./oauth2_sig_private.pem", cfg.Union.OAuth2SigPrivateKeyPath)
				}
				if cfg.Union.OAuth2SigPublicKeyPath != "./oauth2_sig_public.pem" {
					t.Errorf("OAuth2SigPublicKeyPath = %q, want ./oauth2_sig_public.pem", cfg.Union.OAuth2SigPublicKeyPath)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			yamlPath := filepath.Join(dir, "config.yaml")
			if err := os.WriteFile(yamlPath, []byte(baseYAML+tt.yamlExtra), 0644); err != nil {
				t.Fatalf("write config file: %v", err)
			}

			cfg, err := Load(yamlPath)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !strings.Contains(err.Error(), tt.wantErrContain) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantErrContain)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if tt.assertFn != nil {
				tt.assertFn(t, cfg)
			}
		})
	}
}

// TestListenAddr verifies ListenAddr produces the expected host:port string.
func TestListenAddr(t *testing.T) {
	tests := []struct {
		name string
		addr string
		port int
		want string
	}{
		{"empty addr uses loopback", "", 8001, "127.0.0.1:8001"},
		{"specific addr", "0.0.0.0", 3000, "0.0.0.0:3000"},
		{"non-standard port", "192.168.1.1", 9000, "192.168.1.1:9000"},
		{"ipv6 localhost", "::1", 8001, "::1:8001"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cfg Config
			cfg.Server.Addr = tt.addr
			cfg.Server.Port = tt.port
			if got := cfg.ListenAddr(); got != tt.want {
				t.Errorf("ListenAddr() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestNonExistentFileDoesNotError verifies that Load does not fail when the
// config file path does not exist — it falls through to defaults + env.
// Required fields must be provided via env so that validation passes.
func TestNonExistentFileDoesNotError(t *testing.T) {
	t.Setenv("UNION_ELEMENTSKIN_BASE_URL", "https://skin.example.com")
	t.Setenv("UNION_ELEMENTSKIN_OAUTH_CLIENT_ID", "cid")
	t.Setenv("UNION_ELEMENTSKIN_OAUTH_CLIENT_SECRET", "secret")
	t.Setenv("UNION_ELEMENTSKIN_OAUTH_REDIRECT_URI", "https://skin.example.com/oauth/callback")
	t.Setenv("UNION_ELEMENTSKIN_SERVICE_ACCOUNT_CLIENT_ID", "svc-cid")
	t.Setenv("UNION_ELEMENTSKIN_SERVICE_ACCOUNT_CLIENT_SECRET", "svc-secret")
	t.Setenv("UNION_UNION_HUB_URL", "https://hub.example.com")
	t.Setenv("UNION_UNION_MEMBER_KEY", "member-key")
	t.Setenv("UNION_UNION_ADMIN_API_KEY", "admin-key")
	t.Setenv("UNION_UNION_WEBHOOK_SECRET", "webhook-secret")
	t.Setenv("UNION_STORAGE_PATH", "/data/union.db")

	_, err := Load("/nonexistent/path/config.yaml")
	if err != nil {
		t.Fatalf("Load with nonexistent file should not error, got: %v", err)
	}
}
