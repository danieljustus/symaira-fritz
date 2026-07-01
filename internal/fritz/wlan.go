package fritz

import (
	"context"
	"fmt"
	"strconv"
)

// WLAN lives across several WLANConfiguration services, one per radio:
//
//	wlanconfig1  2.4 GHz
//	wlanconfig2  5 GHz       (absent on single-band boxes)
//	wlanconfig3  guest WLAN  (index varies by model/firmware)
//
// The guest index is model-dependent, so guest operations take an explicit
// index (default 3) rather than guessing.

// wlanService builds the WLANConfiguration service for radio index n (1-based).
func wlanService(n int) Service {
	return Service{
		Type:       fmt.Sprintf("urn:dslforum-org:service:WLANConfiguration:%d", n),
		ControlURL: fmt.Sprintf("/upnp/control/wlanconfig%d", n),
	}
}

// Radio is the state of one WLAN radio.
type Radio struct {
	Index    int    `json:"index"`
	SSID     string `json:"ssid"`
	Enabled  bool   `json:"enabled"`
	Channel  string `json:"channel"`
	Standard string `json:"standard"`
	BSSID    string `json:"bssid"`
	Status   string `json:"status"`
}

// WLANClient is a device associated with a WLAN radio.
type WLANClient struct {
	RadioIndex int    `json:"radio_index"`
	MAC        string `json:"mac"`
	IP         string `json:"ip"`
	Signal     string `json:"signal_strength,omitempty"` // percent, AVM extension
	Speed      string `json:"speed,omitempty"`           // Mbit/s, AVM extension
	Authorized bool   `json:"authorized"`
}

// Radios returns the state of each present WLAN radio. It probes indices 1..maxN
// and stops at the first that does not respond.
func (c *Client) Radios(ctx context.Context, maxN int) ([]Radio, error) {
	if maxN <= 0 {
		maxN = 3
	}
	var radios []Radio
	for n := 1; n <= maxN; n++ {
		info, err := c.Call(ctx, wlanService(n), "GetInfo", nil)
		if err != nil {
			if n == 1 || IsUnauthorized(err) || IsTimeout(err) || IsTransport(err) {
				return nil, err
			}
			break // no such radio on this box
		}
		radios = append(radios, Radio{
			Index:    n,
			SSID:     info["NewSSID"],
			Enabled:  info["NewEnable"] == "1",
			Channel:  info["NewChannel"],
			Standard: info["NewStandard"],
			BSSID:    info["NewBSSID"],
			Status:   info["NewStatus"],
		})
	}
	if len(radios) == 0 {
		return nil, fmt.Errorf("wlan: no WLANConfiguration service responded")
	}
	return radios, nil
}

// WLANClients returns devices associated with radio index n.
func (c *Client) WLANClients(ctx context.Context, n int) ([]WLANClient, error) {
	svc := wlanService(n)
	tot, err := c.Call(ctx, svc, "GetTotalAssociations", nil)
	if err != nil {
		return nil, err
	}
	count, _ := strconv.Atoi(tot["NewTotalAssociations"])
	clients := make([]WLANClient, 0, count)
	for i := 0; i < count; i++ {
		info, err := c.Call(ctx, svc, "GetGenericAssociatedDeviceInfo", map[string]string{
			"NewAssociatedDeviceIndex": strconv.Itoa(i),
		})
		if err != nil {
			continue
		}
		clients = append(clients, WLANClient{
			RadioIndex: n,
			MAC:        info["NewAssociatedDeviceMACAddress"],
			IP:         info["NewAssociatedDeviceIPAddress"],
			Signal:     info["NewX_AVM-DE_SignalStrength"],
			Speed:      info["NewX_AVM-DE_Speed"],
			Authorized: info["NewAssociatedDeviceAuthState"] == "1",
		})
	}
	return clients, nil
}

// AllWLANClients aggregates associated devices across radios 1..maxN.
func (c *Client) AllWLANClients(ctx context.Context, maxN int) ([]WLANClient, error) {
	radios, err := c.Radios(ctx, maxN)
	if err != nil {
		return nil, err
	}
	var all []WLANClient
	for _, r := range radios {
		cl, err := c.WLANClients(ctx, r.Index)
		if err != nil {
			continue
		}
		all = append(all, cl...)
	}
	return all, nil
}

// GuestWLANStatus returns whether the guest radio (index guestIdx) is enabled.
func (c *Client) GuestWLANStatus(ctx context.Context, guestIdx int) (*Radio, error) {
	info, err := c.Call(ctx, wlanService(guestIdx), "GetInfo", nil)
	if err != nil {
		return nil, err
	}
	return &Radio{
		Index:    guestIdx,
		SSID:     info["NewSSID"],
		Enabled:  info["NewEnable"] == "1",
		Channel:  info["NewChannel"],
		Standard: info["NewStandard"],
		Status:   info["NewStatus"],
	}, nil
}

// SetGuestWLAN enables or disables the guest radio (index guestIdx).
func (c *Client) SetGuestWLAN(ctx context.Context, guestIdx int, enable bool) error {
	v := "0"
	if enable {
		v = "1"
	}
	_, err := c.Call(ctx, wlanService(guestIdx), "SetEnable", map[string]string{
		"NewEnable": v,
	})
	return err
}
