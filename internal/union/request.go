package union

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// request performs an authenticated HTTP request against the Union Hub.
// If out is non-nil, the response body is unmarshaled into it. The raw
// response body is also returned.
func (c *Client) request(ctx context.Context, method, path string, body, out any) ([]byte, error) {
	if err := c.configured(); err != nil {
		return nil, err
	}

	url := c.hubURL + "/" + strings.TrimLeft(path, "/")

	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}

	SignOutbound(req, c.currentMemberKey(ctx))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

	client := c.http
	if client == nil {
		client = &http.Client{Timeout: c.timeout}
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	if resp.StatusCode >= http.StatusBadRequest {
		detail := fmt.Sprintf("union hub returned HTTP %d: %s", resp.StatusCode, truncateBody(respBody, 512))
		return nil, &HubError{Status: resp.StatusCode, Detail: detail}
	}

	if out != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, out); err != nil {
			return nil, fmt.Errorf("decode response body: %w", err)
		}
	}

	return respBody, nil
}

// truncateBody returns the first maxLen bytes of body as a string, appending
// "..." when the body exceeds maxLen.
func truncateBody(body []byte, maxLen int) string {
	if len(body) <= maxLen {
		return string(body)
	}
	return string(body[:maxLen]) + "..."
}
