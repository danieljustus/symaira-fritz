package fritz

import (
	"context"
	"strconv"
)

// DSLLineStats holds DSL line statistics.
type DSLLineStats struct {
	UpstreamNoiseMargin   int
	DownstreamNoiseMargin int
	UpstreamAttenuation   int
	DownstreamAttenuation int
	UpstreamMaxBitRate    int
	DownstreamMaxBitRate  int
}

// DSLLineStats queries DSL line statistics from the router.
func (c *Client) DSLLineStats(ctx context.Context) (*DSLLineStats, error) {
	dslInfo, err := c.Call(ctx, ServiceWANDSLInterfaceConfig, "GetInfo", nil)
	if err != nil {
		return nil, err
	}

	commonInfo, err := c.Call(ctx, ServiceWANCommonIFC, "GetCommonLinkProperties", nil)
	if err != nil {
		return nil, err
	}

	return &DSLLineStats{
		UpstreamNoiseMargin:   parseInt(dslInfo["NewUpstreamNoiseMargin"]),
		DownstreamNoiseMargin: parseInt(dslInfo["NewDownstreamNoiseMargin"]),
		UpstreamAttenuation:   parseInt(dslInfo["NewUpstreamAttenuation"]),
		DownstreamAttenuation: parseInt(dslInfo["NewDownstreamAttenuation"]),
		UpstreamMaxBitRate:    parseInt(commonInfo["NewLayer1UpstreamMaxBitRate"]),
		DownstreamMaxBitRate:  parseInt(commonInfo["NewLayer1DownstreamMaxBitRate"]),
	}, nil
}

func parseInt(s string) int {
	v, _ := strconv.Atoi(s)
	return v
}
