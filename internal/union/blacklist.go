package union

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

// SearchBlacklist searches the Union Hub blacklist with the given query and
// returns all matching entries unfiltered.
func (c *Client) SearchBlacklist(ctx context.Context, query string) ([]BlacklistEntry, error) {
	path := "/blacklist/query?q=" + url.QueryEscape(query)
	body, err := c.request(ctx, http.MethodGet, path, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("search blacklist: %w", err)
	}

	var entries []BlacklistEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("decode blacklist response: %w", err)
	}
	return entries, nil
}

// CreateBlacklist submits a new blacklist entry to the Union Hub.
func (c *Client) CreateBlacklist(ctx context.Context, entry BlacklistEntry) error {
	_, err := c.request(ctx, http.MethodPost, "/blacklist/restful", map[string]string{
		"email":  entry.Email,
		"reason": entry.Reason,
	}, nil)
	if err != nil {
		return fmt.Errorf("create blacklist: %w", err)
	}
	return nil
}

// DeleteBlacklist removes a blacklist entry from the Union Hub by entry ID.
func (c *Client) DeleteBlacklist(ctx context.Context, entryID string) error {
	path := "/blacklist/restful/" + url.PathEscape(entryID)
	if _, err := c.request(ctx, http.MethodDelete, path, nil, nil); err != nil {
		return fmt.Errorf("delete blacklist: %w", err)
	}
	return nil
}

// InvalidateBlacklist marks a blacklist entry as invalid by entry ID.
func (c *Client) InvalidateBlacklist(ctx context.Context, entryID string) error {
	path := "/blacklist/invalidate/" + url.PathEscape(entryID)
	if _, err := c.request(ctx, http.MethodPut, path, nil, nil); err != nil {
		return fmt.Errorf("invalidate blacklist: %w", err)
	}
	return nil
}
