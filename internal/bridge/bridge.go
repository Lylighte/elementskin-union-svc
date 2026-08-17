package bridge

import (
	"context"
	"fmt"
	"net/http"

	"github.com/Lylighte/elementskin-union-svc/internal/oauth"
	"github.com/Lylighte/elementskin-union-svc/internal/union"
)

// ListProfileItem is a single profile returned by the list endpoint.
type ListProfileItem struct {
	UUID string `json:"uuid"`
	Name string `json:"name"`
}

// Bridge orchestrates Union profile discovery and Element-Skin profile import.
type Bridge struct {
	union         *union.Client
	oauth         *oauth.Manager
	serviceTokens *oauth.ServiceTokenManager
	elementskin   *ElementSkinClient
}

// New creates a Bridge from runtime dependencies.
func New(elementskinBaseURL string, unionClient *union.Client, manager *oauth.Manager, serviceTokens *oauth.ServiceTokenManager, httpClient *http.Client) *Bridge {
	return &Bridge{
		union:         unionClient,
		oauth:         manager,
		serviceTokens: serviceTokens,
		elementskin:   NewElementSkinClient(elementskinBaseURL, httpClient),
	}
}

// ListProfiles queries the Union Hub for profiles matching username.
func (b *Bridge) ListProfiles(ctx context.Context, username string) ([]ListProfileItem, error) {
	profiles, err := b.union.GetProfiles(ctx, username)
	if err != nil {
		return nil, fmt.Errorf("list union profiles: %w", err)
	}

	items := make([]ListProfileItem, len(profiles))
	for i, p := range profiles {
		items[i] = ListProfileItem{
			UUID: p.UUID,
			Name: p.Name,
		}
	}
	return items, nil
}

// ListAllProfilesForSync returns every local Element-Skin profile for the
// Union sync handler, using the service account token.
func (b *Bridge) ListAllProfilesForSync(ctx context.Context) ([]AdminProfile, error) {
	token, err := b.serviceTokens.ServiceAccessToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("get service access token: %w", err)
	}
	return b.elementskin.ListAllProfiles(ctx, token, "")
}

// GetUserEmailByProfileName resolves a profile name to the profile owner's
// email using a single admin profiles list call.
func (b *Bridge) GetUserEmailByProfileName(ctx context.Context, name string) (string, error) {
	token, err := b.serviceTokens.ServiceAccessToken(ctx)
	if err != nil {
		return "", fmt.Errorf("get service access token: %w", err)
	}
	profiles, err := b.elementskin.ListAllProfiles(ctx, token, name)
	if err != nil {
		return "", fmt.Errorf("list admin profiles: %w", err)
	}
	for _, p := range profiles {
		if p.Name == name {
			return p.OwnerEmail, nil
		}
	}
	return "", nil
}

// GetProfileNameByID resolves a profile ID to its current name using the
// service account token. It calls the Element-Skin public Minecraft profile
// endpoint, which requires the minecraft_profile.read.public scope.
// An empty name with a nil error means the profile no longer exists.
func (b *Bridge) GetProfileNameByID(ctx context.Context, profileID string) (string, error) {
	token, err := b.serviceTokens.ServiceAccessToken(ctx)
	if err != nil {
		return "", fmt.Errorf("get service access token: %w", err)
	}
	name, err := b.elementskin.GetProfileNameByID(ctx, token, profileID)
	if err != nil {
		return "", fmt.Errorf("get profile name by id: %w", err)
	}
	return name, nil
}
