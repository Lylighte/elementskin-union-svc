package union

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Lylighte/elementskin-union-svc/internal/config"
)

// Client communicates with the Union Hub using the member_key protocol.
type Client struct {
	hubURL    string
	memberKey string
	timeout   time.Duration
	http      *http.Client
	nonces    *NonceStore
	settings  *SettingsStore

	mu       sync.RWMutex
	pubKey   string
	pubKeyAt time.Time

	oauth2PubKey   string
	oauth2PubKeyAt time.Time
}

// NewClient constructs a Union Hub client from configuration, opening the
// nonce store and settings store at the configured storage path.
func NewClient(cfg config.Config, httpClient *http.Client) (*Client, error) {
	nonces, err := OpenNonceStore(cfg.Storage.Path)
	if err != nil {
		return nil, fmt.Errorf("open nonce store: %w", err)
	}

	settings, err := OpenSettingsStore(cfg.Storage.Path)
	if err != nil {
		_ = nonces.Close()
		return nil, fmt.Errorf("open settings store: %w", err)
	}

	// Seed the runtime member_key from configuration when the settings store
	// does not already have one. SQLite is the runtime authority after startup.
	if cfg.Union.MemberKey != "" {
		ctx := context.Background()
		existing, err := settings.Get(ctx, "member_key")
		if err != nil {
			_ = settings.Close()
			_ = nonces.Close()
			return nil, fmt.Errorf("read member_key setting: %w", err)
		}
		if existing == "" {
			if err := settings.Set(ctx, "member_key", cfg.Union.MemberKey); err != nil {
				_ = settings.Close()
				_ = nonces.Close()
				return nil, fmt.Errorf("seed member_key setting: %w", err)
			}
		}
	}

	return newClient(cfg.Union.HubURL, cfg.Union.MemberKey, cfg.Union.TimeoutSeconds, httpClient, nonces, settings), nil
}

// NewClientWithDeps constructs a client with explicit dependencies. It is
// intended for tests.
func NewClientWithDeps(hubURL, memberKey string, timeoutSeconds int, httpClient *http.Client, nonces *NonceStore, settings *SettingsStore) *Client {
	return newClient(hubURL, memberKey, timeoutSeconds, httpClient, nonces, settings)
}

func newClient(hubURL, memberKey string, timeoutSeconds int, httpClient *http.Client, nonces *NonceStore, settings *SettingsStore) *Client {
	timeout := time.Duration(timeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	c := &Client{
		hubURL:    strings.TrimRight(hubURL, "/"),
		memberKey: memberKey,
		timeout:   timeout,
		nonces:    nonces,
		settings:  settings,
	}

	if httpClient != nil {
		c.http = httpClient
	}

	return c
}

// Close closes the nonce store and settings store.
func (c *Client) Close() error {
	var firstErr error
	if c.nonces != nil {
		if err := c.nonces.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if c.settings != nil {
		if err := c.settings.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// SettingsStore returns the client's runtime settings store. Handlers use it
// to read and write Union configuration such as member_key and list versions.
func (c *Client) SettingsStore() *SettingsStore {
	return c.settings
}

func (c *Client) configured() error {
	if c.hubURL == "" {
		return ErrUnionNotConfigured
	}
	if c.memberKey == "" && (c.settings == nil || c.memberKeyFromSettings(context.Background()) == "") {
		return ErrUnionNotConfigured
	}
	return nil
}

// memberKeyFromSettings returns the current member_key from the settings store,
// or an empty string if the store is nil or the key is missing.
func (c *Client) memberKeyFromSettings(ctx context.Context) string {
	if c.settings == nil {
		return ""
	}
	key, err := c.settings.Get(ctx, "member_key")
	if err != nil {
		return ""
	}
	return key
}

// currentMemberKey returns the runtime member_key: the value from settings if
// present, otherwise the configured fallback.
func (c *Client) currentMemberKey(ctx context.Context) string {
	if key := c.memberKeyFromSettings(ctx); key != "" {
		return key
	}
	return c.memberKey
}

// FetchServerList pulls the current Union server list from the Hub.
// It returns the raw server list JSON and the version reported by the Hub.
func (c *Client) FetchServerList(ctx context.Context) (json.RawMessage, int, error) {
	body, err := c.request(ctx, http.MethodGet, "/serverlist", nil, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("fetch server list: %w", err)
	}

	var resp struct {
		Servers json.RawMessage `json:"servers"`
		Version int             `json:"version"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, 0, fmt.Errorf("decode server list response: %w", err)
	}

	return resp.Servers, resp.Version, nil
}

// FetchPrivateKey pulls the current private key PEM and version from the Hub.
// The PEM itself is not persisted; only the version is stored by callers.
func (c *Client) FetchPrivateKey(ctx context.Context) (string, int, error) {
	body, err := c.request(ctx, http.MethodGet, "/privatekey", nil, nil)
	if err != nil {
		return "", 0, fmt.Errorf("fetch private key: %w", err)
	}

	var resp struct {
		PrivateKey        string `json:"privateKey"`
		PrivateKeyVersion int    `json:"privateKeyVersion"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", 0, fmt.Errorf("decode private key response: %w", err)
	}

	return resp.PrivateKey, resp.PrivateKeyVersion, nil
}

// SyncProfiles reports the local profile name-to-UUID mapping to the Union Hub.
func (c *Client) SyncProfiles(ctx context.Context, profileList map[string]string) error {
	_, err := c.request(ctx, http.MethodPost, "/sync", map[string]any{
		"profileList": profileList,
	}, nil)
	if err != nil {
		return fmt.Errorf("sync profiles: %w", err)
	}
	return nil
}

// ProxyToHub forwards a raw HTTP request to the Union Hub using the current
// member key. It returns the raw response body and status code without
// interpreting HTTP errors, so callers can handle HTTP >= 400 themselves.
// Transport-level failures return (nil, 0, err).
func (c *Client) ProxyToHub(ctx context.Context, method, path string, body []byte) ([]byte, int, error) {
	if err := c.configured(); err != nil {
		return nil, 0, err
	}

	url := c.hubURL + "/" + strings.TrimLeft(path, "/")

	var bodyReader io.Reader
	if len(body) > 0 {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, 0, fmt.Errorf("build proxy request: %w", err)
	}

	SignOutbound(req, c.currentMemberKey(ctx))
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}

	client := c.http
	if client == nil {
		client = &http.Client{Timeout: c.timeout}
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("execute proxy request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, fmt.Errorf("read proxy response body: %w", err)
	}

	return respBody, resp.StatusCode, nil
}

// GetOAuth2BackendPublicKey fetches the OAuth2 backend public key from the
// Union Hub and caches it for 60 seconds.
func (c *Client) GetOAuth2BackendPublicKey(ctx context.Context) (string, error) {
	c.mu.RLock()
	if c.oauth2PubKey != "" && time.Since(c.oauth2PubKeyAt) < publicKeyCacheTTL {
		defer c.mu.RUnlock()
		return c.oauth2PubKey, nil
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.oauth2PubKey != "" && time.Since(c.oauth2PubKeyAt) < publicKeyCacheTTL {
		return c.oauth2PubKey, nil
	}

	body, err := c.request(ctx, http.MethodGet, "/oauth2/backend", nil, nil)
	if err != nil {
		return "", err
	}

	var resp struct {
		PublicKey string `json:"publicKey"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("decode oauth2 backend public key response: %w", err)
	}
	if resp.PublicKey == "" {
		return "", fmt.Errorf("oauth2 backend public key missing from response")
	}

	c.oauth2PubKey = resp.PublicKey
	c.oauth2PubKeyAt = time.Now()
	return c.oauth2PubKey, nil
}

// ProfileBind binds a profile to the current member on the Union Hub.
func (c *Client) ProfileBind(ctx context.Context, uuid string) ([]byte, int, error) {
	body, err := json.Marshal(map[string]string{"uuid": uuid})
	if err != nil {
		return nil, 0, fmt.Errorf("marshal profile bind request: %w", err)
	}
	return c.ProxyToHub(ctx, http.MethodPost, "/profile/bind", body)
}

// ProfileUnbind unbinds a profile from the current member on the Union Hub.
func (c *Client) ProfileUnbind(ctx context.Context, uuid string) ([]byte, int, error) {
	body, err := json.Marshal(map[string]string{"uuid": uuid})
	if err != nil {
		return nil, 0, fmt.Errorf("marshal profile unbind request: %w", err)
	}
	return c.ProxyToHub(ctx, http.MethodPost, "/profile/unbind", body)
}

// ProfileBindTo binds a profile to another member identified by token on the
// Union Hub.
func (c *Client) ProfileBindTo(ctx context.Context, uuid, token string) ([]byte, int, error) {
	body, err := json.Marshal(map[string]string{"uuid": uuid, "token": token})
	if err != nil {
		return nil, 0, fmt.Errorf("marshal profile bindto request: %w", err)
	}
	return c.ProxyToHub(ctx, http.MethodPost, "/profile/bindto", body)
}
