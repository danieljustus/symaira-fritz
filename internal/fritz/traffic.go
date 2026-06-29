package fritz

import (
	"context"
	"fmt"
	"strings"
)

// TrafficData holds online monitor statistics.
type TrafficData struct {
	DownstreamInternet      []float64
	DownstreamMedia         []float64
	DownstreamGuest         []float64
	UpstreamRealtime        []float64
	UpstreamHighPriority    []float64
	UpstreamDefaultPriority []float64
	UpstreamLowPriority     []float64
	UpstreamGuest           []float64
}

// OnlineMonitor queries real-time traffic statistics from the router.
func (c *Client) OnlineMonitor(ctx context.Context) (*TrafficData, error) {
	resp, err := c.Call(ctx, ServiceWANCommonIFC, "X_AVM-DE_GetOnlineMonitor", map[string]string{
		"NewSyncGroupIndex": "0",
	})
	if err != nil {
		return nil, err
	}

	return &TrafficData{
		DownstreamInternet:      parseCommaFloats(resp["Newds_current_bps"]),
		DownstreamMedia:         parseCommaFloats(resp["Newmc_current_bps"]),
		DownstreamGuest:         parseCommaFloats(resp["Newds_guest_bps"]),
		UpstreamRealtime:        parseCommaFloats(resp["Newprio_realtime_bps"]),
		UpstreamHighPriority:    parseCommaFloats(resp["Newprio_high_bps"]),
		UpstreamDefaultPriority: parseCommaFloats(resp["Newprio_default_bps"]),
		UpstreamLowPriority:     parseCommaFloats(resp["Newprio_low_bps"]),
		UpstreamGuest:           parseCommaFloats(resp["Newus_guest_bps"]),
	}, nil
}

func parseCommaFloats(s string) []float64 {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	res := make([]float64, 0, len(parts))
	for _, p := range parts {
		var f float64
		if _, err := fmt.Sscan(p, &f); err == nil {
			res = append(res, f)
		}
	}
	return res
}
