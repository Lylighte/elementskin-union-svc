package union

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

// GetSecurityLevel returns the Union Hub security level for this member.
// The username argument is accepted for API symmetry but the current member_key
// protocol does not pass it to the Hub.
func (c *Client) GetSecurityLevel(ctx context.Context, username string) (int, error) {
	_ = username

	var codeResp struct {
		Code string `json:"code"`
	}
	if _, err := c.request(ctx, http.MethodPost, "/code", map[string]string{
		"token": c.currentMemberKey(ctx),
	}, &codeResp); err != nil {
		return 0, fmt.Errorf("exchange code: %w", err)
	}
	if codeResp.Code == "" {
		return 0, ErrSecurityLevelCodeMissing
	}

	var level int
	path := "/backend/" + url.PathEscape(codeResp.Code) + "/security/level"
	if _, err := c.request(ctx, http.MethodGet, path, nil, &level); err != nil {
		return 0, fmt.Errorf("fetch security level: %w", err)
	}

	return level, nil
}
