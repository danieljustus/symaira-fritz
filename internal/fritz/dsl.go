package fritz

import (
	"context"
	"strconv"
)

// DSLLineStats holds DSL line statistics.
type DSLLineStats struct {
	UpstreamNoiseMargin   int  `json:"upstream_noise_margin,omitempty"`
	DownstreamNoiseMargin int  `json:"downstream_noise_margin,omitempty"`
	UpstreamAttenuation   int  `json:"upstream_attenuation,omitempty"`
	DownstreamAttenuation int  `json:"downstream_attenuation,omitempty"`
	UpstreamMaxBitRate    int  `json:"upstream_max_bit_rate,omitempty"`
	DownstreamMaxBitRate  int  `json:"downstream_max_bit_rate,omitempty"`
	IsReducedDataset      bool `json:"is_reduced_dataset,omitempty"`
}

// DSLLineStats queries DSL line statistics from the router.
func (c *Client) DSLLineStats(ctx context.Context) (*DSLLineStats, error) {
	dslInfo, err := c.Call(ctx, ServiceWANDSLInterfaceConfig, "GetInfo", nil)
	if err == nil {
		commonInfo, err := c.Call(ctx, ServiceWANCommonIFC, "GetCommonLinkProperties", nil)
		if err == nil {
			return &DSLLineStats{
				UpstreamNoiseMargin:   parseInt(dslInfo["NewUpstreamNoiseMargin"]),
				DownstreamNoiseMargin: parseInt(dslInfo["NewDownstreamNoiseMargin"]),
				UpstreamAttenuation:   parseInt(dslInfo["NewUpstreamAttenuation"]),
				DownstreamAttenuation: parseInt(dslInfo["NewDownstreamAttenuation"]),
				UpstreamMaxBitRate:    parseInt(commonInfo["NewLayer1UpstreamMaxBitRate"]),
				DownstreamMaxBitRate:  parseInt(commonInfo["NewLayer1DownstreamMaxBitRate"]),
				IsReducedDataset:      false,
			}, nil
		}
	}

	// Fallback to unauthenticated IGD interface on auth or credential errors
	if err == ErrNoCredential || IsUnauthorized(err) {
		igdCommonInfo, igdErr := c.Call(ctx, ServiceIGDWANCommonIFC, "GetCommonLinkProperties", nil)
		if igdErr == nil {
			return &DSLLineStats{
				UpstreamMaxBitRate:   parseInt(igdCommonInfo["NewLayer1UpstreamMaxBitRate"]),
				DownstreamMaxBitRate: parseInt(igdCommonInfo["NewLayer1DownstreamMaxBitRate"]),
				IsReducedDataset:     true,
			}, nil
		}
	}

	return nil, err
}

func parseInt(s string) int {
	v, _ := strconv.Atoi(s)
	return v
}
