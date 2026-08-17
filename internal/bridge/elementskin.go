package bridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// maxAdminProfilePages caps the pagination loop in ListAllProfiles.
// With a page size of 100, this limits the result set to 10 000 profiles.
const maxAdminProfilePages = 100

// UserInfo mirrors the Element-Skin GET /v1/users/me response body.
type UserInfo struct {
	ID           string   `json:"id"`
	DisplayName  string   `json:"display_name"`
	Email        string   `json:"email"`
	Lang         string   `json:"lang"`
	BannedUntil  *int64   `json:"banned_until"`
	AvatarHash   string   `json:"avatar_hash"`
	Permissions  []string `json:"permissions"`
	Protected    bool     `json:"protected"`
	ProfileCount int      `json:"profile_count"`
	TextureCount int      `json:"texture_count"`
}

// AdminProfile mirrors the Element-Skin GET /v1/admin/profiles item shape.
type AdminProfile struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	UserID     string `json:"user_id"`
	OwnerEmail string `json:"owner_email"`
}

type adminProfilesResponse struct {
	Items      []AdminProfile `json:"items"`
	HasNext    bool           `json:"has_next"`
	NextCursor string         `json:"next_cursor"`
	PageSize   int            `json:"page_size"`
}

// APIError describes a non-success HTTP response from the Element-Skin API.
type APIError struct {
	Status int
	Detail string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("element-skin API returned HTTP %d: %s", e.Status, e.Detail)
}

// ElementSkinClient calls the Element-Skin public API using a Bearer token.
type ElementSkinClient struct {
	baseURL    string
	httpClient *http.Client
}

// NewElementSkinClient creates a client for the upstream Element-Skin API.
// When httpClient is nil, a default client with a 30-second timeout is used.
func NewElementSkinClient(baseURL string, httpClient *http.Client) *ElementSkinClient {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &ElementSkinClient{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: httpClient,
	}
}

func extractDetail(body []byte) string {
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return string(body)
	}
	if d, ok := m["detail"].(string); ok {
		return d
	}
	return string(body)
}

// ListAllProfiles lists every profile through the Element-Skin admin API,
// following cursor pagination until the result set is exhausted.
func (c *ElementSkinClient) ListAllProfiles(ctx context.Context, token, query string) ([]AdminProfile, error) {
	var all []AdminProfile
	cursor := ""
	pages := 0
	for {
		pages++
		if pages > maxAdminProfilePages {
			return nil, errors.New("admin profiles pagination exceeded maximum pages")
		}
		u, err := url.Parse(c.baseURL + "/v2/admin/profiles")
		if err != nil {
			return nil, fmt.Errorf("build admin profiles URL: %w", err)
		}
		q := u.Query()
		q.Set("limit", "100")
		if query != "" {
			q.Set("q", query)
		}
		if cursor != "" {
			q.Set("next_cursor", cursor)
		}
		u.RawQuery = q.Encode()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return nil, fmt.Errorf("build admin profiles request: %w", err)
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("execute admin profiles request: %w", err)
		}

		respBody, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("read admin profiles response: %w", err)
		}

		if resp.StatusCode >= http.StatusBadRequest {
			detail := extractDetail(respBody)
			if detail == "" {
				detail = string(respBody)
			}
			return nil, &APIError{Status: resp.StatusCode, Detail: detail}
		}

		var page adminProfilesResponse
		if err := json.Unmarshal(respBody, &page); err != nil {
			return nil, fmt.Errorf("decode admin profiles response: %w", err)
		}
		all = append(all, page.Items...)

		if !page.HasNext || page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}
	return all, nil
}

// GetUserInfo returns the current user from Element-Skin using a bearer token.
func (c *ElementSkinClient) GetUserInfo(ctx context.Context, bearerToken string) (*UserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v1/users/me", nil)
	if err != nil {
		return nil, fmt.Errorf("build get user info request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearerToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute get user info request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read get user info response: %w", err)
	}

	if resp.StatusCode >= http.StatusBadRequest {
		detail := extractDetail(respBody)
		if detail == "" {
			detail = string(respBody)
		}
		return nil, &APIError{Status: resp.StatusCode, Detail: detail}
	}

	var ui UserInfo
	if err := json.Unmarshal(respBody, &ui); err != nil {
		return nil, fmt.Errorf("decode get user info response: %w", err)
	}
	return &ui, nil
}

// ListUserProfiles returns the profile IDs owned by the authenticated user
// via GET /v1/users/me/profiles. Requires the profile.read.owned scope.
func (c *ElementSkinClient) ListUserProfiles(ctx context.Context, token string) ([]string, error) {
	u, err := url.Parse(c.baseURL + "/v1/users/me/profiles")
	if err != nil {
		return nil, fmt.Errorf("build user profiles URL: %w", err)
	}
	q := u.Query()
	q.Set("limit", "100")
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("build user profiles request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute user profiles request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read user profiles response: %w", err)
	}

	if resp.StatusCode >= http.StatusBadRequest {
		detail := extractDetail(respBody)
		if detail == "" {
			detail = string(respBody)
		}
		return nil, &APIError{Status: resp.StatusCode, Detail: detail}
	}

	var page struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	if err := json.Unmarshal(respBody, &page); err != nil {
		return nil, fmt.Errorf("decode user profiles response: %w", err)
	}

	ids := make([]string, 0, len(page.Items))
	for _, item := range page.Items {
		ids = append(ids, item.ID)
	}
	return ids, nil
}

// SearchProfilesByName queries the admin profiles API and returns only
// profiles whose Name exactly matches name.
func (c *ElementSkinClient) SearchProfilesByName(ctx context.Context, token, name string) ([]AdminProfile, error) {
	profiles, err := c.ListAllProfiles(ctx, token, name)
	if err != nil {
		return nil, err
	}
	var matched []AdminProfile
	for _, p := range profiles {
		if p.Name == name {
			matched = append(matched, p)
		}
	}
	return matched, nil
}

// minecraftProfileResponse mirrors the Element-Skin
// GET /v2/minecraft/profiles/{profile_id} response body.
type minecraftProfileResponse struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// GetProfileNameByID resolves a profile ID to its current name via the
// Element-Skin public Minecraft profile endpoint. It requires the
// minecraft_profile.read.public scope on the service account token.
// A nil error with an empty name indicates the profile was not found.
func (c *ElementSkinClient) GetProfileNameByID(ctx context.Context, token, profileID string) (string, error) {
	profileID = strings.ReplaceAll(profileID, "-", "")
	u, err := url.Parse(c.baseURL + "/v2/minecraft/profiles/" + url.PathEscape(profileID))
	if err != nil {
		return "", fmt.Errorf("build minecraft profile URL: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", fmt.Errorf("build minecraft profile request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("execute minecraft profile request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read minecraft profile response: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound {
		return "", nil
	}
	if resp.StatusCode >= http.StatusBadRequest {
		detail := extractDetail(respBody)
		if detail == "" {
			detail = string(respBody)
		}
		return "", &APIError{Status: resp.StatusCode, Detail: detail}
	}

	var profile minecraftProfileResponse
	if err := json.Unmarshal(respBody, &profile); err != nil {
		return "", fmt.Errorf("decode minecraft profile response: %w", err)
	}
	return profile.Name, nil
}
