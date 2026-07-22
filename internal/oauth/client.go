package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// TokenResponse mirrors the Element-Skin /oauth/token success body.
type TokenResponse struct {
	AccessToken  string   `json:"access_token"`
	TokenType    string   `json:"token_type"`
	ExpiresIn    int64    `json:"expires_in"`
	RefreshToken string   `json:"refresh_token"`
	Scope        string   `json:"scope"`
	Permissions  []string `json:"permissions"`
}

// ElementSkinClient calls the Element-Skin /oauth/token endpoint.
type ElementSkinClient struct {
	baseURL      string
	clientID     string
	clientSecret string
	redirectURI  string
	httpClient   *http.Client
}

// NewElementSkinClient creates a client for the upstream token endpoint.
func NewElementSkinClient(baseURL, clientID, clientSecret, redirectURI string, httpClient *http.Client) *ElementSkinClient {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &ElementSkinClient{
		baseURL:      strings.TrimRight(baseURL, "/"),
		clientID:     clientID,
		clientSecret: clientSecret,
		redirectURI:  redirectURI,
		httpClient:   httpClient,
	}
}

// ExchangeCode exchanges an authorization code and PKCE verifier for tokens.
func (c *ElementSkinClient) ExchangeCode(ctx context.Context, code, verifier string) (*TokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", c.redirectURI)
	form.Set("client_id", c.clientID)
	form.Set("client_secret", c.clientSecret)
	form.Set("code_verifier", verifier)
	return c.postToken(ctx, form)
}

// Refresh uses a refresh token to obtain a new access token.
func (c *ElementSkinClient) Refresh(ctx context.Context, refreshToken string) (*TokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	form.Set("client_id", c.clientID)
	form.Set("client_secret", c.clientSecret)
	return c.postToken(ctx, form)
}

// ClientCredentials exchanges client credentials for an access token.
func (c *ElementSkinClient) ClientCredentials(ctx context.Context, scope string) (*TokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", c.clientID)
	form.Set("client_secret", c.clientSecret)
	if scope != "" {
		form.Set("scope", scope)
	}
	return c.postToken(ctx, form)
}

func (c *ElementSkinClient) postToken(ctx context.Context, form url.Values) (*TokenResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("post token request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	var tr TokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("decode token response: %w", err)
	}
	return &tr, nil
}
