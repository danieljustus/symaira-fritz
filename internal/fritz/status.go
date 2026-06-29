package fritz

import "context"

// Status is a high-level overview of the box, assembled from several TR-064
// actions. It is intentionally a convenience aggregate for `symfritz status`;
// for anything finer-grained call Call directly.
type Status struct {
	ModelName       string
	FirmwareVersion string
	ExternalIP      string
	ConnectionState string // e.g. "Connected"
	Uptime          string // seconds, as reported by the box
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

	return s, nil
}
