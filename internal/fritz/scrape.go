package fritz

import (
	"context"
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

	return string(body), nil
}
