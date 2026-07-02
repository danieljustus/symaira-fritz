package fritz

import (
	"context"
	"encoding/json"
	"errors"
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
	Partial         bool
	Errors          []StatusError
}

// StatusError records a single sub-query failure inside Status.
type StatusError struct {
	Service string    `json:"service"`
	Action  string    `json:"action"`
	Message string    `json:"message"`
	Kind    ErrorKind `json:"kind,omitempty"`
	Err     error     `json:"-"`
}

func (e StatusError) Error() string {
	return fmt.Sprintf("%s/%s: %s", e.Service, e.Action, e.Message)
}

func serviceName(s Service) string {
	parts := strings.Split(s.Type, ":")
	if len(parts) >= 5 {
		return parts[3]
	}
	return s.Type
}

// Status fetches an overview of the box. Individual sub-queries that fail are
// recorded in Errors and Partial is set, so callers can distinguish "all data
// missing" (auth failure, unreachable box) from "some data missing" (locked
// down box, unsupported model).
func (c *Client) Status(ctx context.Context) (*Status, error) {
	s := &Status{}
	var errs []StatusError

	addErr := func(service, action string, err error) {
		var kind ErrorKind
		var fe *FritzError
		if errors.As(err, &fe) {
			kind = fe.Kind
		}
		errs = append(errs, StatusError{
			Service: service,
			Action:  action,
			Message: err.Error(),
			Kind:    kind,
			Err:     err,
		})
	}

	if info, err := c.Call(ctx, ServiceDeviceInfo, "GetInfo", nil); err == nil {
		s.ModelName = info["NewModelName"]
		s.FirmwareVersion = info["NewSoftwareVersion"]
		s.Uptime = info["NewUpTime"]
	} else {
		addErr(serviceName(ServiceDeviceInfo), "GetInfo", err)
	}

	if conn, err := c.wanConnectionCall(ctx, "GetInfo"); err == nil {
		s.ConnectionState = conn["NewConnectionStatus"]
	} else {
		addErr("WANConnection", "GetInfo", err)
	}
	if ip, err := c.wanConnectionCall(ctx, "GetExternalIPAddress"); err == nil {
		s.ExternalIP = ip["NewExternalIPAddress"]
	} else {
		addErr("WANConnection", "GetExternalIPAddress", err)
	}
	if upd, err := c.UpdateAvailable(ctx); err == nil {
		s.UpdateAvailable = upd
	} else {
		addErr(serviceName(ServiceUserInterface), "GetInfo", err)
	}

	s.Errors = errs
	s.Partial = len(errs) > 0

	isEmpty := s.ModelName == "" && s.FirmwareVersion == "" && s.ExternalIP == "" && s.ConnectionState == "" && s.Uptime == ""

	if len(errs) == 4 || (isEmpty && s.Partial) {
		var prioErr error
		for _, e := range errs {
			if IsUnauthorized(e.Err) {
				prioErr = e.Err
				break
			}
		}
		if prioErr == nil && len(errs) > 0 {
			prioErr = errs[0].Err
		}
		if prioErr == nil {
			prioErr = fmt.Errorf("all status sub-queries failed; check connection and credentials")
		}
		return s, prioErr
	}

	return s, nil
}

func (c *Client) wanConnectionCall(ctx context.Context, action string) (map[string]string, error) {
	res, err := c.Call(ctx, ServiceWANIPConnection, action, nil)
	if err == nil {
		return res, nil
	}
	if !IsUnsupportedAction(err) {
		return nil, err
	}
	res, pppErr := c.Call(ctx, ServiceWANPPPConnection, action, nil)
	if pppErr == nil {
		return res, nil
	}
	return nil, fmt.Errorf("WANIPConnection.%s failed: %w; WANPPPConnection.%s fallback failed: %v", action, err, action, pppErr)
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
