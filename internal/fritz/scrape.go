package fritz

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// ScrapeDataLUA fetches a page via the internal data.lua endpoint.
//
// WARNING: This is a best-effort, version-fragile API.
// AVM frequently changes the data.lua structure, endpoints, and variables
// across FRITZ!OS updates. Use TR-064 or AHA whenever possible instead.
func (c *Client) ScrapeDataLUA(ctx context.Context, page string, params url.Values) (string, error) {
	sid, err := c.SID(ctx)
	if err != nil {
		return "", err
	}

	data := url.Values{
		"sid":  {sid},
		"page": {page},
	}
	for k, vs := range params {
		for _, v := range vs {
			data.Add(k, v)
		}
	}

	u := c.baseHTTP() + "/data.lua"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(data.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("scrape: contacting %s: %w", c.Host, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20)) // limit to 5MB
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("scrape: data.lua returned HTTP %d", resp.StatusCode)
	}
	if !json.Valid(bytes.TrimSpace(body)) {
		contentType := resp.Header.Get("Content-Type")
		if contentType == "" {
			contentType = "unknown"
		}
		if looksLikeHTML(body, contentType) {
			return "", fmt.Errorf("scrape: data.lua returned an HTML login page instead of JSON; run 'symfritz auth test' to verify credentials and retry")
		}
		return "", fmt.Errorf("scrape: data.lua returned a non-JSON response (content type %q)", contentType)
	}

	return string(body), nil
}

func looksLikeHTML(body []byte, contentType string) bool {
	if strings.Contains(strings.ToLower(contentType), "text/html") {
		return true
	}
	prefix := bytes.TrimSpace(body)
	if len(prefix) > 512 {
		prefix = prefix[:512]
	}
	lower := strings.ToLower(string(prefix))
	return strings.HasPrefix(lower, "<!doctype html") || strings.HasPrefix(lower, "<html")
}
