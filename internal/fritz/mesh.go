package fritz

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Mesh topology comes from a two-step dance: the Hosts service hands out a path
// (X_AVM-DE_GetMeshListPath), which is then fetched from the web port with the
// session id. The JSON describes nodes (box, repeaters, clients) and the links
// between their interfaces.

// MeshTopology is the parsed mesh list.
type MeshTopology struct {
	SchemaVersion string     `json:"schema_version"`
	Nodes         []MeshNode `json:"nodes"`
}

// MeshNode is one device in the mesh.
type MeshNode struct {
	UID         string          `json:"uid"`
	DeviceName  string          `json:"device_name"`
	DeviceModel string          `json:"device_model"`
	IsMeshed    bool            `json:"is_meshed"`
	MeshRole    string          `json:"mesh_role"` // "master" / "slave" / "unknown"
	Interfaces  []MeshInterface `json:"node_interfaces"`
}

// MeshInterface is one network interface of a node.
type MeshInterface struct {
	UID   string     `json:"uid"`
	Name  string     `json:"name"`
	Type  string     `json:"type"` // "LAN" / "WLAN"
	Links []MeshLink `json:"node_links"`
}

// MeshLink is a connection between two node interfaces.
type MeshLink struct {
	State         string `json:"state"`
	Node1         string `json:"node_1"`
	Node2         string `json:"node_2"`
	MaxDataRateRx int    `json:"max_data_rate_rx"`
	MaxDataRateTx int    `json:"max_data_rate_tx"`
	CurDataRateRx int    `json:"cur_data_rate_rx"`
	CurDataRateTx int    `json:"cur_data_rate_tx"`
}

// MeshTopology fetches and parses the FRITZ!Box mesh list.
func (c *Client) MeshTopology(ctx context.Context) (*MeshTopology, error) {
	res, err := c.Call(ctx, ServiceHosts, "X_AVM-DE_GetMeshListPath", nil)
	if err != nil {
		return nil, fmt.Errorf("mesh: %w", err)
	}
	path := res["NewX_AVM-DE_MeshListPath"]
	if path == "" {
		return nil, fmt.Errorf("mesh: box returned no mesh list path (unsupported firmware?)")
	}

	if !strings.Contains(strings.ToLower(path), "sid=") {
		sid, err := c.SID(ctx)
		if err != nil {
			return nil, err
		}
		path = appendQueryParam(path, "sid", sid)
	}

	resp, err := c.fetchMeshList(ctx, path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	// Limit to 8MB — large residential meshes with many nodes/links can
	// produce substantial JSON, but 8MB is a safe upper bound.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	var topo MeshTopology
	if err := json.Unmarshal(body, &topo); err != nil {
		return nil, fmt.Errorf("mesh: parsing mesh list JSON: %w", err)
	}
	return &topo, nil
}

func (c *Client) fetchMeshList(ctx context.Context, path string) (*http.Response, error) {
	var lastErr error
	for _, u := range c.meshListURLCandidates(path) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		resp, err := c.http.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("mesh: fetching mesh list from %s: %w", safeURLForError(u), err)
			continue
		}
		if resp.StatusCode == http.StatusOK {
			return resp, nil
		}
		lastErr = fmt.Errorf("mesh: mesh list returned HTTP %d from %s", resp.StatusCode, safeURLForError(u))
		resp.Body.Close()
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("mesh: no mesh list URL candidates")
}

func (c *Client) meshListURLCandidates(path string) []string {
	if u, err := url.Parse(path); err == nil && u.IsAbs() {
		return []string{path}
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	candidates := []string{c.tr064Base() + path}
	web := c.baseHTTP() + path
	if web != candidates[0] {
		candidates = append(candidates, web)
	}
	return candidates
}

func appendQueryParam(rawURL, key, value string) string {
	sep := "?"
	if strings.Contains(rawURL, "?") {
		sep = "&"
	}
	return rawURL + sep + url.QueryEscape(key) + "=" + url.QueryEscape(value)
}

func safeURLForError(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	q := u.Query()
	if q.Has("sid") {
		q.Set("sid", "REDACTED")
		u.RawQuery = q.Encode()
	}
	return u.String()
}

// NodeName resolves a node UID to its device name for readable link output.
func (t *MeshTopology) NodeName(uid string) string {
	for _, n := range t.Nodes {
		if n.UID == uid {
			return n.DeviceName
		}
		for _, iface := range n.Interfaces {
			if iface.UID == uid {
				return n.DeviceName
			}
		}
	}
	return uid
}
