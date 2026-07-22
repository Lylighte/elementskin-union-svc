package config

import (
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config holds the union-svc runtime configuration.
type Config struct {
	Server struct {
		Addr string `yaml:"addr" env:"SERVER_ADDR"`
		Port int    `yaml:"port" env:"SERVER_PORT"`
	} `yaml:"server"`
	Elementskin struct {
		BaseURL string `yaml:"base_url" env:"ELEMENTSKIN_BASE_URL"`
		SiteURL string `yaml:"site_url" env:"ELEMENTSKIN_SITE_URL"`
		OAuth   struct {
			ClientID     string `yaml:"client_id" env:"ELEMENTSKIN_OAUTH_CLIENT_ID"`
			ClientSecret string `yaml:"client_secret" env:"ELEMENTSKIN_OAUTH_CLIENT_SECRET"`
			RedirectURI  string `yaml:"redirect_uri" env:"ELEMENTSKIN_OAUTH_REDIRECT_URI"`
		} `yaml:"oauth"`
		ServiceAccount struct {
			ClientID     string `yaml:"client_id" env:"ELEMENTSKIN_SERVICE_ACCOUNT_CLIENT_ID"`
			ClientSecret string `yaml:"client_secret" env:"ELEMENTSKIN_SERVICE_ACCOUNT_CLIENT_SECRET"`
			Scope        string `yaml:"scope" env:"ELEMENTSKIN_SERVICE_ACCOUNT_SCOPE"`
		} `yaml:"service_account"`
	} `yaml:"elementskin"`
	Storage struct {
		Path string `yaml:"path" env:"STORAGE_PATH"`
	} `yaml:"storage"`
	Union struct {
		HubURL                  string `yaml:"hub_url" env:"HUB_URL"`
		MemberKey               string `yaml:"member_key" env:"MEMBER_KEY"`
		CORSAllowOrigin         string `yaml:"cors_allow_origin" env:"CORS_ALLOW_ORIGIN"`
		TimeoutSeconds          int    `yaml:"timeout_seconds" env:"TIMEOUT_SECONDS"`
		AdminAPIKey             string `yaml:"admin_api_key" env:"ADMIN_API_KEY"`
		WebhookSecret           string `yaml:"webhook_secret" env:"WEBHOOK_SECRET"`
		EnableOAuth2            bool   `yaml:"enable_oauth2" env:"ENABLE_OAUTH2"`
		OAuth2SigPrivateKeyPath string `yaml:"oauth2_sig_private_key_path" env:"OAUTH2_SIG_PRIVATE_KEY_PATH"`
		OAuth2SigPublicKeyPath  string `yaml:"oauth2_sig_public_key_path" env:"OAUTH2_SIG_PUBLIC_KEY_PATH"`
	} `yaml:"union" env:"UNION"`
	// TLS holds optional TLS configuration for outbound connections.
	// TODO: wire this into HTTP clients for Element-Skin and Union Hub.
	TLS struct {
		InsecureSkipVerify bool   `yaml:"insecure_skip_verify" env:"INSECURE_SKIP_VERIFY"`
		CAFile             string `yaml:"ca_file" env:"CA_FILE"`
	} `yaml:"tls" env:"TLS"`
	Log struct {
		Level string `yaml:"level" env:"LOG_LEVEL"`
	} `yaml:"log"`
}

// defaults returns a Config populated with default values.
func defaults() Config {
	var cfg Config
	cfg.Server.Addr = ""
	cfg.Server.Port = 8001
	// Network-address defaults are intentionally empty — they must be
	// provided explicitly via config file or environment variable in production.
	cfg.Elementskin.BaseURL = ""
	cfg.Elementskin.OAuth.RedirectURI = ""
	cfg.Elementskin.ServiceAccount.Scope = "profile.read.any"
	cfg.Storage.Path = "./union-svc.db"
	cfg.Union.TimeoutSeconds = 30
	cfg.Union.EnableOAuth2 = true
	cfg.Union.OAuth2SigPrivateKeyPath = "./oauth2_sig_private.pem"
	cfg.Union.OAuth2SigPublicKeyPath = "./oauth2_sig_public.pem"
	cfg.Log.Level = "info"
	return cfg
}

// Load reads the YAML file at path, applies default values, and then overrides
// with environment variables that carry the UNION_ prefix.
func Load(path string) (Config, error) {
	cfg := defaults()

	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil && !os.IsNotExist(err) {
			return cfg, fmt.Errorf("read config file: %w", err)
		}
		if err == nil {
			if err := yaml.Unmarshal(data, &cfg); err != nil {
				return cfg, fmt.Errorf("parse config file: %w", err)
			}
		}
	}

	if err := applyEnv("UNION", reflect.ValueOf(&cfg).Elem()); err != nil {
		return cfg, fmt.Errorf("apply env vars: %w", err)
	}

	if err := validateRequiredConfig(cfg); err != nil {
		return cfg, err
	}

	return cfg, nil
}

// validateRequiredConfig returns an error when production-critical
// configuration values are empty. Defaults alone are insufficient; every
// deployment must explicitly supply these values.
func validateRequiredConfig(cfg Config) error {
	var missing []string

	if cfg.Elementskin.BaseURL == "" {
		missing = append(missing, "elementskin.base_url")
	}
	if cfg.Elementskin.OAuth.ClientID == "" {
		missing = append(missing, "elementskin.oauth.client_id")
	}
	if cfg.Elementskin.OAuth.ClientSecret == "" {
		missing = append(missing, "elementskin.oauth.client_secret")
	}
	if cfg.Elementskin.OAuth.RedirectURI == "" {
		missing = append(missing, "elementskin.oauth.redirect_uri")
	}
	if cfg.Elementskin.ServiceAccount.ClientID == "" {
		missing = append(missing, "elementskin.service_account.client_id")
	}
	if cfg.Elementskin.ServiceAccount.ClientSecret == "" {
		missing = append(missing, "elementskin.service_account.client_secret")
	}
	if cfg.Union.HubURL == "" {
		missing = append(missing, "union.hub_url")
	}
	if cfg.Union.MemberKey == "" {
		missing = append(missing, "union.member_key")
	}
	if cfg.Union.AdminAPIKey == "" {
		missing = append(missing, "union.admin_api_key")
	}
	if cfg.Union.WebhookSecret == "" {
		missing = append(missing, "union.webhook_secret")
	}
	if cfg.Storage.Path == "" {
		missing = append(missing, "storage.path")
	}

	if len(missing) > 0 {
		return fmt.Errorf("missing required config: %s", strings.Join(missing, ", "))
	}
	return nil
}

// applyEnv walks v recursively and, for each struct field that carries an
// `env` tag, checks for a matching environment variable under prefix. Nested
// structs are walked with a combined prefix.
func applyEnv(prefix string, v reflect.Value) error {
	t := v.Type()
	for i := range t.NumField() {
		field := t.Field(i)
		fv := v.Field(i)

		if fv.Kind() == reflect.Struct {
			nextPrefix := prefix
			if tag := field.Tag.Get("env"); tag != "" {
				nextPrefix = joinEnv(nextPrefix, tag)
			}
			if err := applyEnv(nextPrefix, fv); err != nil {
				return err
			}
			continue
		}

		tag := field.Tag.Get("env")
		if tag == "" {
			continue
		}
		key := joinEnv(prefix, tag)
		value, ok := os.LookupEnv(key)
		if !ok {
			continue
		}
		if err := setField(fv, value); err != nil {
			return fmt.Errorf("set %s: %w", key, err)
		}
	}
	return nil
}

func joinEnv(prefix, suffix string) string {
	return prefix + "_" + suffix
}

func setField(v reflect.Value, value string) error {
	switch v.Kind() {
	case reflect.String:
		v.SetString(value)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return err
		}
		v.SetInt(n)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		n, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			return err
		}
		v.SetUint(n)
	case reflect.Bool:
		b, err := strconv.ParseBool(value)
		if err != nil {
			return err
		}
		v.SetBool(b)
	default:
		return fmt.Errorf("unsupported kind %s", v.Kind())
	}
	return nil
}

// ListenAddr returns the host:port string derived from Server config.
func (c Config) ListenAddr() string {
	if c.Server.Addr == "" {
		return fmt.Sprintf("127.0.0.1:%d", c.Server.Port)
	}
	return fmt.Sprintf("%s:%d", c.Server.Addr, c.Server.Port)
}
