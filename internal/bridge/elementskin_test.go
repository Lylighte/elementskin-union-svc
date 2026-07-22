package bridge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewElementSkinClientNilFallbackHasTimeout(t *testing.T) {
	c := NewElementSkinClient("http://127.0.0.1:1", nil)
	if c.httpClient == nil {
		t.Fatal("NewElementSkinClient with nil httpClient: httpClient is nil")
	}
	if c.httpClient.Timeout != 30*time.Second {
		t.Errorf("httpClient.Timeout = %v, want 30s", c.httpClient.Timeout)
	}
}

func TestListAllProfilesStopsAfterMaxPages(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(adminProfilesResponse{
			Items:      []AdminProfile{},
			HasNext:    true,
			NextCursor: "cursor-next",
			PageSize:   100,
		})
	}))
	defer srv.Close()

	client := NewElementSkinClient(srv.URL, srv.Client())
	_, err := client.ListAllProfiles(context.Background(), "token", "")

	if callCount != maxAdminProfilePages {
		t.Errorf("expected %d admin API calls, got %d", maxAdminProfilePages, callCount)
	}
	if err == nil {
		t.Fatal("expected error from pagination limit, got nil")
	}
	if err.Error() != "admin profiles pagination exceeded maximum pages" {
		t.Errorf("error = %q, want 'admin profiles pagination exceeded maximum pages'", err.Error())
	}
}

func TestGetUserInfoValidToken(t *testing.T) {
	want := UserInfo{
		ID:           "user-abc",
		DisplayName:  "Alice",
		Email:        "alice@example.com",
		Lang:         "zh_CN",
		AvatarHash:   "deadbeef",
		Permissions:  []string{"profile.read", "texture.read"},
		Protected:    true,
		ProfileCount: 2,
		TextureCount: 5,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(want)
	}))
	defer srv.Close()

	client := NewElementSkinClient(srv.URL, srv.Client())
	info, err := client.GetUserInfo(context.Background(), "valid-token")
	if err != nil {
		t.Fatalf("GetUserInfo returned error: %v", err)
	}
	if info.ID != want.ID {
		t.Errorf("ID = %q, want %q", info.ID, want.ID)
	}
	if info.DisplayName != want.DisplayName {
		t.Errorf("DisplayName = %q, want %q", info.DisplayName, want.DisplayName)
	}
	if info.Email != want.Email {
		t.Errorf("Email = %q, want %q", info.Email, want.Email)
	}
}

func TestGetUserInfoRequestPathAndHeader(t *testing.T) {
	var gotPath, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(UserInfo{ID: "x"})
	}))
	defer srv.Close()

	client := NewElementSkinClient(srv.URL, srv.Client())
	_, err := client.GetUserInfo(context.Background(), "my-bearer-token")
	if err != nil {
		t.Fatalf("GetUserInfo returned error: %v", err)
	}
	if gotPath != "/v1/users/me" {
		t.Errorf("path = %q, want /v1/users/me", gotPath)
	}
	if gotAuth != "Bearer my-bearer-token" {
		t.Errorf("Authorization header = %q, want Bearer my-bearer-token", gotAuth)
	}
}

func TestGetUserInfoUnauthorizedReturnsAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"detail": "invalid token"})
	}))
	defer srv.Close()

	client := NewElementSkinClient(srv.URL, srv.Client())
	_, err := client.GetUserInfo(context.Background(), "bad-token")
	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}
	if apiErr.Status != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", apiErr.Status, http.StatusUnauthorized)
	}
}

func TestGetUserInfoServerErrorReturnsAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"detail": "database error"})
	}))
	defer srv.Close()

	client := NewElementSkinClient(srv.URL, srv.Client())
	_, err := client.GetUserInfo(context.Background(), "token")
	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}
	if apiErr.Status != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", apiErr.Status, http.StatusInternalServerError)
	}
}
