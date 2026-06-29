package fritz

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// AHA-HTTP is the FRITZ!Box "Home Automation" interface for DECT actors:
// smart plugs (FRITZ!DECT 200/210), thermostats (FRITZ!DECT 301), buttons, and
// groups. It is a simple GET API at /webservices/homeautoswitch.lua that takes
// a session id (sid) and a switchcmd. See session.go for SID acquisition.
//
// Full command reference: AVM "AHA-HTTP-Interface" PDF.

// DeviceList is the parsed result of the getdevicelistinfos command.
type DeviceList struct {
	XMLName xml.Name `xml:"devicelist"`
	Devices []Device `xml:"device"`
}

// Device is one DECT actor. Only the commonly used fields are mapped; extend as
// needed (the XML carries many more per-capability sub-elements).
type Device struct {
	Identifier string `xml:"identifier,attr"` // AIN
	ID         string `xml:"id,attr"`
	Name       string `xml:"name"`
	Present    int    `xml:"present"` // 1 = connected
	Switch     struct {
		State string `xml:"state"` // "1"/"0"
	} `xml:"switch"`
	Temperature struct {
		Celsius string `xml:"celsius"` // tenths of a degree as integer string
	} `xml:"temperature"`
	Hkr struct {
		Tist  string `xml:"tist"`  // current temp (half-degrees)
		Tsoll string `xml:"tsoll"` // target temp (half-degrees)
	} `xml:"hkr"`
}

// Home performs an AHA-HTTP switchcmd and returns the raw response text.
// params are extra query parameters such as "ain" or "param".
//
// A 403 usually means the cached session id expired. Home transparently drops
// the SID, re-logs in once, and retries before surfacing the error — so a
// long-running process doesn't appear to "randomly" break.
func (c *Client) Home(ctx context.Context, switchcmd string, params url.Values) (string, error) {
	body, status, err := c.doHome(ctx, switchcmd, params)
	if err != nil {
		return "", err
	}
	if status == http.StatusForbidden {
		c.invalidateSID()
		body, status, err = c.doHome(ctx, switchcmd, params)
		if err != nil {
			return "", err
		}
	}
	if status == http.StatusForbidden {
		return "", fmt.Errorf("aha: forbidden after re-login — user lacks smart-home permission?")
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("aha: %s returned HTTP %d", switchcmd, status)
	}
	return strings.TrimSpace(body), nil
}

// doHome performs one AHA request and returns the body and status code.
func (c *Client) doHome(ctx context.Context, switchcmd string, params url.Values) (string, int, error) {
	sid, err := c.SID(ctx)
	if err != nil {
		return "", 0, err
	}
	q := url.Values{"sid": {sid}, "switchcmd": {switchcmd}}
	for k, vs := range params {
		for _, v := range vs {
			q.Add(k, v)
		}
	}
	u := c.baseHTTP() + "/webservices/homeautoswitch.lua?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", 0, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("aha: contacting %s: %w", c.Host, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", resp.StatusCode, err
	}
	return string(body), resp.StatusCode, nil
}

// Devices returns the parsed list of DECT smart-home actors.
func (c *Client) Devices(ctx context.Context) ([]Device, error) {
	raw, err := c.Home(ctx, "getdevicelistinfos", nil)
	if err != nil {
		return nil, err
	}
	var list DeviceList
	if err := xml.Unmarshal([]byte(raw), &list); err != nil {
		return nil, fmt.Errorf("aha: parsing device list: %w", err)
	}
	return list.Devices, nil
}

// SwitchOn turns a switch actor on. ain is the actor identifier (AIN).
func (c *Client) SwitchOn(ctx context.Context, ain string) error {
	_, err := c.Home(ctx, "setswitchon", url.Values{"ain": {ain}})
	return err
}

// SwitchOff turns a switch actor off.
func (c *Client) SwitchOff(ctx context.Context, ain string) error {
	_, err := c.Home(ctx, "setswitchoff", url.Values{"ain": {ain}})
	return err
}

// SetHkrTemp sets the target temperature of a thermostat (HKR).
// tempCelsius should be the target temperature (e.g. 20.5), or special values:
// 254 for "ON" (max) and 253 for "OFF" (min).
func (c *Client) SetHkrTemp(ctx context.Context, ain string, tempCelsius float64) error {
	// AVM expects temperature in half degrees, e.g. 20.0 °C -> 40.
	// Special values: 254 (ON), 253 (OFF) are passed as is.
	var param string
	if tempCelsius == 254 || tempCelsius == 253 {
		param = fmt.Sprintf("%.0f", tempCelsius)
	} else {
		param = fmt.Sprintf("%.0f", tempCelsius*2)
	}
	_, err := c.Home(ctx, "sethkrtsoll", url.Values{"ain": {ain}, "param": {param}})
	return err
}
