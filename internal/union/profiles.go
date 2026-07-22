package union

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

// SyncProfileAdd notifies the Union Hub that a new profile was created locally.
func (c *Client) SyncProfileAdd(ctx context.Context, name, uuid string) error {
	_, err := c.request(ctx, http.MethodPost, "/profile", map[string]string{
		"id":   uuid,
		"name": name,
	}, nil)
	if err != nil {
		return fmt.Errorf("sync profile add: %w", err)
	}
	return nil
}

// SyncProfileUpdate notifies the Union Hub that a profile was renamed.
func (c *Client) SyncProfileUpdate(ctx context.Context, uuid, name string) error {
	path := "/profile/" + url.PathEscape(uuid)
	_, err := c.request(ctx, http.MethodPut, path, map[string]string{
		"name": name,
	}, nil)
	if err != nil {
		return fmt.Errorf("sync profile update: %w", err)
	}
	return nil
}

// SyncProfileDelete notifies the Union Hub that a profile was deleted.
func (c *Client) SyncProfileDelete(ctx context.Context, uuid string) error {
	path := "/profile/" + url.PathEscape(uuid)
	_, err := c.request(ctx, http.MethodDelete, path, nil, nil)
	if err != nil {
		return fmt.Errorf("sync profile delete: %w", err)
	}
	return nil
}

// GetProfiles queries the Union Hub for profiles matching username.
func (c *Client) GetProfiles(ctx context.Context, username string) ([]Profile, error) {
	path := "/profile/unmapped/byname/" + url.PathEscape(username)
	body, err := c.request(ctx, http.MethodGet, path, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("get profiles: %w", err)
	}

	return decodeProfiles(body)
}

// decodeProfiles attempts to unmarshal a JSON response into a []Profile,
// supporting three shapes for backward compatibility with different Hub
// response versions:
//
//  1. A bare JSON array of Profile objects:
//     [{"id":"...", "name":"...", ...}]
//
//  2. A wrapped object with a "data" key containing the array:
//     {"data": [{"id":"...", "name":"...", ...}]}
//
//  3. A single Profile object (legacy shape for queries that return exactly
//     one result):
//     {"id":"...", "name":"...", ...}
//
// Fallback ordering means shape 1 is the most efficient and preferred.
func decodeProfiles(body []byte) ([]Profile, error) {
	var err error

	var list []Profile
	if err = json.Unmarshal(body, &list); err == nil {
		return list, nil
	}

	var wrapped struct {
		Data []Profile `json:"data"`
	}
	if err = json.Unmarshal(body, &wrapped); err == nil {
		return wrapped.Data, nil
	}

	var single Profile
	if err = json.Unmarshal(body, &single); err == nil {
		if single.InternalID != "" || single.UUID != "" || single.Name != "" {
			return []Profile{single}, nil
		}
	}

	return nil, fmt.Errorf("decode profiles response: %w", err)
}
