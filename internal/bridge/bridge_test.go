package bridge

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/Lylighte/elementskin-union-svc/internal/config"
	"github.com/Lylighte/elementskin-union-svc/internal/oauth"
	"github.com/Lylighte/elementskin-union-svc/internal/union"

	_ "modernc.org/sqlite"
)

func testOAuthManager(t *testing.T, accessToken string) *oauth.Manager {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "oauth.db"))
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	store, err := oauth.NewStore(db)
	if err != nil {
		t.Fatalf("create token store: %v", err)
	}
	if accessToken != "" {
		row := oauth.TokenRow{
			AccessToken:  accessToken,
			RefreshToken: "refresh-token",
			ExpiresAtMS:  time.Now().Add(time.Hour).UnixMilli(),
		}
		if err := store.Save(context.Background(), row); err != nil {
			t.Fatalf("save token: %v", err)
		}
	}
	return oauth.NewManagerWithDeps(config.Config{}, store, nil)
}

func testServiceTokenManager(t *testing.T, accessToken string) *oauth.ServiceTokenManager {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "service_oauth.db"))
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	store, err := oauth.NewServiceTokenStore(db)
	if err != nil {
		t.Fatalf("create service token store: %v", err)
	}
	if accessToken != "" {
		row := oauth.ServiceTokenRow{
			AccessToken: accessToken,
			ExpiresAtMS: time.Now().Add(time.Hour).UnixMilli(),
			Scope:       "profile.read.any",
		}
		if err := store.Save(context.Background(), row); err != nil {
			t.Fatalf("save service token: %v", err)
		}
	}
	return oauth.NewServiceTokenManagerWithDeps(config.Config{}, store, nil)
}

func TestBridgeListProfilesMapsUnionResponse(t *testing.T) {
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/profile/unmapped/byname/Steve" {
			t.Errorf("unexpected hub path %s", r.URL.Path)
		}
		if got := r.Header.Get("X-Union-Member-Key"); got != "member-key" {
			t.Errorf("member key = %q, want member-key", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]union.Profile{
			{UUID: "uuid-1", Name: "Steve"},
			{UUID: "uuid-2", Name: "Steve2"},
		})
	}))
	defer hub.Close()

	uc := union.NewClientWithDeps(hub.URL, "member-key", 30, hub.Client(), nil, nil)
	b := New("http://127.0.0.1:1", uc, testOAuthManager(t, ""), nil, hub.Client())

	items, err := b.ListProfiles(context.Background(), "Steve")
	if err != nil {
		t.Fatalf("list profiles: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("len(items) = %d, want 2", len(items))
	}
	if items[0].UUID != "uuid-1" || items[0].Name != "Steve" {
		t.Errorf("items[0] = %+v, want uuid-1/Steve", items[0])
	}
	if items[1].UUID != "uuid-2" || items[1].Name != "Steve2" {
		t.Errorf("items[1] = %+v, want uuid-2/Steve2", items[1])
	}
}

func TestBridgeListProfilesReturnsNotConfiguredWhenUnionHubMissing(t *testing.T) {
	uc := union.NewClientWithDeps("", "", 30, nil, nil, nil)
	b := New("http://127.0.0.1:1", uc, testOAuthManager(t, ""), nil, nil)

	_, err := b.ListProfiles(context.Background(), "Steve")
	if !errors.Is(err, union.ErrUnionNotConfigured) {
		t.Fatalf("expected ErrUnionNotConfigured, got %v", err)
	}
}

func TestBridgeListProfilesReturnsEmptyListWhenHubReturnsEmpty(t *testing.T) {
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	defer hub.Close()

	uc := union.NewClientWithDeps(hub.URL, "member-key", 30, hub.Client(), nil, nil)
	b := New("http://127.0.0.1:1", uc, testOAuthManager(t, ""), nil, hub.Client())

	items, err := b.ListProfiles(context.Background(), "Steve")
	if err != nil {
		t.Fatalf("list profiles with empty hub response: %v", err)
	}
	if items == nil {
		t.Fatal("expected non-nil empty slice, got nil")
	}
	if len(items) != 0 {
		t.Fatalf("len(items) = %d, want 0", len(items))
	}
}

func TestBridgeListProfilesReturnsErrorWhenHubFails(t *testing.T) {
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer hub.Close()

	uc := union.NewClientWithDeps(hub.URL, "member-key", 30, hub.Client(), nil, nil)
	b := New("http://127.0.0.1:1", uc, testOAuthManager(t, ""), nil, hub.Client())

	_, err := b.ListProfiles(context.Background(), "Steve")
	if err == nil {
		t.Fatal("expected error from hub failure")
	}
	var hubErr *union.HubError
	if !errors.As(err, &hubErr) {
		t.Fatalf("expected *union.HubError, got %T", err)
	}
	if hubErr.Status != http.StatusInternalServerError {
		t.Errorf("hub error status = %d, want 500", hubErr.Status)
	}
}

func TestBridgeAdminListAllProfilesForSyncAggregatesPaginatedProfiles(t *testing.T) {
	callCount := 0
	elementskin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if r.URL.Path != "/v1/admin/profiles" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer service-token" {
			t.Errorf("authorization = %q, want Bearer service-token", got)
		}
		if got := r.URL.Query().Get("limit"); got != "100" {
			t.Errorf("limit = %q, want 100", got)
		}
		if q := r.URL.Query().Get("q"); q != "" {
			t.Errorf("q = %q, want empty", q)
		}

		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("next_cursor") == "" {
			_ = json.NewEncoder(w).Encode(adminProfilesResponse{
				Items: []AdminProfile{
					{ID: "uuid-1", Name: "Steve", UserID: "u1", OwnerEmail: "steve@example.com"},
				},
				HasNext:    true,
				NextCursor: "cursor-2",
				PageSize:   100,
			})
			return
		}
		if r.URL.Query().Get("next_cursor") != "cursor-2" {
			t.Errorf("next_cursor = %q, want cursor-2", r.URL.Query().Get("next_cursor"))
		}
		_ = json.NewEncoder(w).Encode(adminProfilesResponse{
			Items: []AdminProfile{
				{ID: "uuid-2", Name: "Alex", UserID: "u2", OwnerEmail: "alex@example.com"},
			},
			HasNext:  false,
			PageSize: 100,
		})
	}))
	defer elementskin.Close()

	uc := union.NewClientWithDeps("http://127.0.0.1:1", "key", 30, nil, nil, nil)
	b := New(elementskin.URL, uc, testOAuthManager(t, ""), testServiceTokenManager(t, "service-token"), elementskin.Client())

	profiles, err := b.ListAllProfilesForSync(context.Background())
	if err != nil {
		t.Fatalf("list all profiles for sync: %v", err)
	}
	if callCount != 2 {
		t.Errorf("admin API calls = %d, want 2", callCount)
	}
	if len(profiles) != 2 {
		t.Fatalf("len(profiles) = %d, want 2", len(profiles))
	}
	if profiles[0].ID != "uuid-1" || profiles[0].OwnerEmail != "steve@example.com" {
		t.Errorf("profiles[0] = %+v", profiles[0])
	}
	if profiles[1].ID != "uuid-2" || profiles[1].OwnerEmail != "alex@example.com" {
		t.Errorf("profiles[1] = %+v", profiles[1])
	}
}

func TestBridgeGetUserEmailByProfileNameUsesSingleAdminCall(t *testing.T) {
	callCount := 0
	elementskin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if r.URL.Path != "/v1/admin/profiles" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer service-token" {
			t.Errorf("authorization = %q, want Bearer service-token", got)
		}
		if got := r.URL.Query().Get("q"); got != "Steve" {
			t.Errorf("q = %q, want Steve", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(adminProfilesResponse{
			Items: []AdminProfile{
				{ID: "uuid-1", Name: "Steve", UserID: "u1", OwnerEmail: "steve@example.com"},
				{ID: "uuid-2", Name: "Steveee", UserID: "u2", OwnerEmail: "steveee@example.com"},
			},
			HasNext:  false,
			PageSize: 100,
		})
	}))
	defer elementskin.Close()

	uc := union.NewClientWithDeps("http://127.0.0.1:1", "key", 30, nil, nil, nil)
	b := New(elementskin.URL, uc, testOAuthManager(t, ""), testServiceTokenManager(t, "service-token"), elementskin.Client())

	email, err := b.GetUserEmailByProfileName(context.Background(), "Steve")
	if err != nil {
		t.Fatalf("get user email by profile name: %v", err)
	}
	if callCount != 1 {
		t.Errorf("admin API calls = %d, want 1", callCount)
	}
	if email != "steve@example.com" {
		t.Errorf("email = %q, want steve@example.com", email)
	}
}

func TestBridgeAdminGetUserEmailByProfileNameReturnsEmptyWhenNotFound(t *testing.T) {
	elementskin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("q"); got != "Unknown" {
			t.Errorf("q = %q, want Unknown", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(adminProfilesResponse{
			Items:    []AdminProfile{},
			HasNext:  false,
			PageSize: 100,
		})
	}))
	defer elementskin.Close()

	uc := union.NewClientWithDeps("http://127.0.0.1:1", "key", 30, nil, nil, nil)
	b := New(elementskin.URL, uc, testOAuthManager(t, ""), testServiceTokenManager(t, "service-token"), elementskin.Client())

	email, err := b.GetUserEmailByProfileName(context.Background(), "Unknown")
	if err != nil {
		t.Fatalf("get user email by profile name: %v", err)
	}
	if email != "" {
		t.Errorf("email = %q, want empty", email)
	}
}

func TestBridgeGetUserEmailByProfileNamePropagatesAdminError(t *testing.T) {
	elementskin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{"detail": "insufficient permissions"})
	}))
	defer elementskin.Close()

	uc := union.NewClientWithDeps("http://127.0.0.1:1", "key", 30, nil, nil, nil)
	b := New(elementskin.URL, uc, testOAuthManager(t, ""), testServiceTokenManager(t, "service-token"), elementskin.Client())

	_, err := b.GetUserEmailByProfileName(context.Background(), "Steve")
	if err == nil {
		t.Fatal("expected error")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *APIError, got %T", err)
	}
	if apiErr.Status != http.StatusForbidden {
		t.Errorf("status = %d, want %d", apiErr.Status, http.StatusForbidden)
	}
}

func TestElementSkinClientAdminListAllProfilesOmitsQWhenQueryEmpty(t *testing.T) {
	elementskin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Has("q") {
			t.Errorf("q should be omitted when query is empty")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(adminProfilesResponse{
			Items:    []AdminProfile{},
			HasNext:  false,
			PageSize: 100,
		})
	}))
	defer elementskin.Close()

	client := NewElementSkinClient(elementskin.URL, elementskin.Client())
	_, err := client.ListAllProfiles(context.Background(), "token", "")
	if err != nil {
		t.Fatalf("list all profiles: %v", err)
	}
}
