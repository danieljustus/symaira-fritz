package fritz

import (
	"context"
	"fmt"
	"strings"
)

// TrafficData holds online monitor statistics.
type TrafficData struct {
	DownstreamInternet      []float64 `json:"downstream_internet,omitempty"`
	DownstreamMedia         []float64 `json:"downstream_media,omitempty"`
	DownstreamGuest         []float64 `json:"downstream_guest,omitempty"`
	UpstreamRealtime        []float64 `json:"upstream_realtime,omitempty"`
	UpstreamHighPriority    []float64 `json:"upstream_high_priority,omitempty"`
	UpstreamDefaultPriority []float64 `json:"upstream_default_priority,omitempty"`
	UpstreamLowPriority     []float64 `json:"upstream_low_priority,omitempty"`
	UpstreamGuest           []float64 `json:"upstream_guest,omitempty"`
	IsReducedDataset        bool      `json:"is_reduced_dataset,omitempty"`
}

// OnlineMonitor queries real-time traffic statistics from the router.
func (c *Client) OnlineMonitor(ctx context.Context) (*TrafficData, error) {
	resp, err := c.Call(ctx, ServiceWANCommonIFC, "X_AVM-DE_GetOnlineMonitor", map[string]string{
		"NewSyncGroupIndex": "0",
	})
	if err == nil {
		return &TrafficData{
			DownstreamInternet:      parseCommaFloats(resp["Newds_current_bps"]),
			DownstreamMedia:         parseCommaFloats(resp["Newmc_current_bps"]),
			DownstreamGuest:         parseCommaFloats(resp["Newds_guest_bps"]),
			UpstreamRealtime:        parseCommaFloats(resp["Newprio_realtime_bps"]),
			UpstreamHighPriority:    parseCommaFloats(resp["Newprio_high_bps"]),
			UpstreamDefaultPriority: parseCommaFloats(resp["Newprio_default_bps"]),
			UpstreamLowPriority:     parseCommaFloats(resp["Newprio_low_bps"]),
			UpstreamGuest:           parseCommaFloats(resp["Newus_guest_bps"]),
			IsReducedDataset:        false,
		}, nil
	}

	// Fallback to unauthenticated IGD interface on auth or credential errors
	if err == ErrNoCredential || IsUnauthorized(err) {
		igdResp, igdErr := c.Call(ctx, ServiceIGDWANCommonIFC, "GetAddonInfos", nil)
		if igdErr == nil {
			rxBytes := parseFloat(igdResp["NewByteReceiveRate"])
			txBytes := parseFloat(igdResp["NewByteSendRate"])
			return &TrafficData{
				DownstreamInternet:      []float64{rxBytes * 8},
				UpstreamDefaultPriority: []float64{txBytes * 8},
				IsReducedDataset:        true,
			}, nil
		}
	}

	return nil, err
}

func parseFloat(s string) float64 {
	var f float64
	_, _ = fmt.Sscan(s, &f)
	return f
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
