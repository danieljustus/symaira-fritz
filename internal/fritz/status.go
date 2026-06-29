package fritz

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// Status is a high-level overview of the box, assembled from several TR-064
// actions. It is intentionally a convenience aggregate for `symfritz status`;
// for anything finer-grained call Call directly.
type Status struct {
	ModelName       string
	FirmwareVersion string
	ExternalIP      string
	ConnectionState string // e.g. "Connected"
	Uptime          string // seconds, as reported by the box
	UpdateAvailable string // firmware version if update available, otherwise empty
}

// Status fetches an overview of the box. Individual sub-queries that fail are
// left blank rather than failing the whole call, so a partial result is still
// useful on locked-down boxes.
func (c *Client) Status(ctx context.Context) (*Status, error) {
	s := &Status{}

	if info, err := c.Call(ctx, ServiceDeviceInfo, "GetInfo", nil); err == nil {
		s.ModelName = info["NewModelName"]
		s.FirmwareVersion = info["NewSoftwareVersion"]
		s.Uptime = info["NewUpTime"]
	}

	if conn, err := c.Call(ctx, ServiceWANIPConnection, "GetInfo", nil); err == nil {
		s.ConnectionState = conn["NewConnectionStatus"]
	}
	if ip, err := c.Call(ctx, ServiceWANIPConnection, "GetExternalIPAddress", nil); err == nil {
		s.ExternalIP = ip["NewExternalIPAddress"]
	}
	if upd, err := c.UpdateAvailable(ctx); err == nil {
		s.UpdateAvailable = upd
	}

	return s, nil
}

// UpdateAvailable checks if a firmware upgrade is available and returns the new version.
func (c *Client) UpdateAvailable(ctx context.Context) (string, error) {
	resp, err := c.Call(ctx, ServiceUserInterface, "GetInfo", nil)
	if err != nil {
		return "", err
	}
	if resp["NewUpgradeAvailable"] == "1" {
		return resp["NewX_AVM-DE_Version"], nil
	}
	return "", nil
}

// CPUTemperatures retrieves the last measured CPU temperatures in °C.
// This uses the undocumented, experimental query.lua interface.
func (c *Client) CPUTemperatures(ctx context.Context) ([]int, error) {
	sid, err := c.SID(ctx)
	if err != nil {
		return nil, err
	}
	u := c.baseHTTP() + "/query.lua?sid=" + sid
	body := `{"CPUTEMP":"cpu:status/StatTemperature"}`
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden {
		c.invalidateSID()
		sid, err = c.SID(ctx)
		if err != nil {
			return nil, err
		}
		u = c.baseHTTP() + "/query.lua?sid=" + sid
		req2, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(body))
		if err != nil {
			return nil, err
		}
		req2.Header.Set("Content-Type", "application/json")
		resp2, err := c.http.Do(req2)
		if err != nil {
			return nil, err
		}
		defer resp2.Body.Close()
		resp = resp2
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("query.lua returned HTTP %d", resp.StatusCode)
	}

	var resMap map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&resMap); err != nil {
		return nil, err
	}

	tempStr := resMap["CPUTEMP"]
	if tempStr == "" {
		return nil, fmt.Errorf("query.lua response missing CPUTEMP key")
	}

	parts := strings.Split(tempStr, ",")
	var temps []int
	for _, p := range parts {
		if val, err := strconv.Atoi(p); err == nil {
			temps = append(temps, val)
		}
	}
	return temps, nil
}
