package fritz

import (
	"context"
	"encoding/xml"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Host is a device known to the FRITZ!Box host table (TR-064 Hosts service).
type Host struct {
	Name               string `json:"name"`
	IP                 string `json:"ip"`
	MAC                string `json:"mac"`
	Active             bool   `json:"active"`
	InterfaceType      string `json:"interface_type"`       // "Ethernet", "802.11", "" …
	AddressSource      string `json:"address_source"`       // "DHCP", "Static" …
	LeaseTimeRemaining int    `json:"lease_time_remaining"` // seconds, 0 = static/unknown
}

// Link returns a human label for the connection medium.
func (h Host) Link() string {
	switch {
	case strings.HasPrefix(h.InterfaceType, "802.11"):
		return "WLAN"
	case h.InterfaceType == "Ethernet":
		return "LAN"
	case h.InterfaceType == "":
		return "—"
	default:
		return h.InterfaceType
	}
}

// Hosts returns the full FRITZ!Box host table. It attempts the fast bulk path
// (X_AVM-DE_GetHostListPath) first and falls back to iterating GetGenericHostEntry
// (N+1 SOAP calls) when unsupported or on fetch/parse failure.
func (c *Client) Hosts(ctx context.Context) ([]Host, error) {
	if hosts, err := c.bulkHosts(ctx); err == nil {
		return hosts, nil
	}
	return c.hostsFromIndex(ctx)
}

func (c *Client) bulkHosts(ctx context.Context) ([]Host, error) {
	resp, err := c.Call(ctx, ServiceHosts, "X_AVM-DE_GetHostListPath", nil)
	if err != nil {
		return nil, err
	}
	path := resp["NewX_AVM-DE_HostListPath"]
	if path == "" {
		path = resp["NewHostListPath"]
	}
	if path == "" {
		return nil, fmt.Errorf("tr064: GetHostListPath returned empty path")
	}

	targetURL := path
	if u, err := url.Parse(path); err != nil || !u.IsAbs() {
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		targetURL = c.tr064Base() + path
	}

	xmlData, err := c.fetchAuthenticatedURL(ctx, targetURL)
	if err != nil {
		return nil, err
	}

	type xmlHostItem struct {
		IPAddress          string `xml:"IPAddress"`
		MACAddress         string `xml:"MACAddress"`
		Active             string `xml:"Active"`
		HostName           string `xml:"HostName"`
		InterfaceType      string `xml:"InterfaceType"`
		AddressSource      string `xml:"AddressSource"`
		LeaseTimeRemaining string `xml:"LeaseTimeRemaining"`
	}
	type xmlHostList struct {
		XMLName xml.Name      `xml:"List"`
		Items   []xmlHostItem `xml:"Item"`
	}

	var list xmlHostList
	if err := xml.Unmarshal(xmlData, &list); err != nil {
		return nil, err
	}

	hosts := make([]Host, 0, len(list.Items))
	for _, item := range list.Items {
		lease, _ := strconv.Atoi(item.LeaseTimeRemaining)
		hosts = append(hosts, Host{
			Name:               item.HostName,
			IP:                 item.IPAddress,
			MAC:                strings.ToUpper(item.MACAddress),
			Active:             item.Active == "1",
			InterfaceType:      item.InterfaceType,
			AddressSource:      item.AddressSource,
			LeaseTimeRemaining: lease,
		})
	}
	return hosts, nil
}

func (c *Client) hostsFromIndex(ctx context.Context) ([]Host, error) {
	cnt, err := c.Call(ctx, ServiceHosts, "GetHostNumberOfEntries", nil)
	if err != nil {
		return nil, err
	}
	n, _ := strconv.Atoi(cnt["NewHostNumberOfEntries"])
	hosts := make([]Host, 0, n)
	for i := 0; i < n; i++ {
		entry, err := c.Call(ctx, ServiceHosts, "GetGenericHostEntry", map[string]string{
			"NewIndex": strconv.Itoa(i),
		})
		if err != nil {
			// A single bad index shouldn't abort the whole listing.
			continue
		}
		hosts = append(hosts, hostFromEntry(entry))
	}
	return hosts, nil
}

// ActiveHosts returns only the hosts the box currently reports as active.
func (c *Client) ActiveHosts(ctx context.Context) ([]Host, error) {
	all, err := c.Hosts(ctx)
	if err != nil {
		return nil, err
	}
	active := all[:0]
	for _, h := range all {
		if h.Active {
			active = append(active, h)
		}
	}
	return active, nil
}

// HostByMAC looks up a single host by MAC address via the box's index, which is
// faster and more reliable than scanning the full table.
func (c *Client) HostByMAC(ctx context.Context, mac string) (*Host, error) {
	entry, err := c.Call(ctx, ServiceHosts, "GetSpecificHostEntry", map[string]string{
		"NewMACAddress": strings.ToUpper(mac),
	})
	if err != nil {
		return nil, err
	}
	h := hostFromEntry(entry)
	h.MAC = strings.ToUpper(mac)
	return &h, nil
}

// HostByIP looks up a single host by IP address using the AVM extension.
func (c *Client) HostByIP(ctx context.Context, ip string) (*Host, error) {
	entry, err := c.Call(ctx, ServiceHosts, "X_AVM-DE_GetSpecificHostEntryByIP", map[string]string{
		"NewIPAddress": ip,
	})
	if err != nil {
		return nil, err
	}
	h := hostFromEntry(entry)
	h.IP = ip
	return &h, nil
}

// HostByName resolves a host by (case-insensitive) name from the full table.
// Returns an error if zero or more than one host matches.
func (c *Client) HostByName(ctx context.Context, name string) (*Host, error) {
	all, err := c.Hosts(ctx)
	if err != nil {
		return nil, err
	}
	var matches []Host
	lname := strings.ToLower(name)
	for _, h := range all {
		if strings.ToLower(h.Name) == lname {
			matches = append(matches, h)
		}
	}
	switch len(matches) {
	case 0:
		return nil, fmt.Errorf("no host named %q in the FRITZ!Box host table", name)
	case 1:
		return &matches[0], nil
	default:
		return nil, fmt.Errorf("%d hosts named %q; use --mac or --ip to disambiguate", len(matches), name)
	}
}

// ResolveHost accepts a name, MAC, or IP and returns the matching host. The form
// is auto-detected: an IP-looking string uses HostByIP, a MAC-looking string
// uses HostByMAC, otherwise it is treated as a name.
func (c *Client) ResolveHost(ctx context.Context, ref string) (*Host, error) {
	switch {
	case looksLikeIP(ref):
		return c.HostByIP(ctx, ref)
	case looksLikeMAC(ref):
		return c.HostByMAC(ctx, ref)
	default:
		return c.HostByName(ctx, ref)
	}
}

// WakeOnLAN sends a Wake-on-LAN magic packet to the given MAC via the box.
func (c *Client) WakeOnLAN(ctx context.Context, mac string) error {
	_, err := c.Call(ctx, ServiceHosts, "X_AVM-DE_WakeOnLANByMACAddress", map[string]string{
		"NewMACAddress": strings.ToUpper(mac),
	})
	return err
}

func hostFromEntry(e map[string]string) Host {
	lease, _ := strconv.Atoi(e["NewLeaseTimeRemaining"])
	return Host{
		Name:               e["NewHostName"],
		IP:                 e["NewIPAddress"],
		MAC:                strings.ToUpper(e["NewMACAddress"]),
		Active:             e["NewActive"] == "1",
		InterfaceType:      e["NewInterfaceType"],
		AddressSource:      e["NewAddressSource"],
		LeaseTimeRemaining: lease,
	}
}

func looksLikeIP(s string) bool {
	return net.ParseIP(s) != nil
}

func looksLikeMAC(s string) bool {
	if strings.Count(s, ":") == 5 {
		return true
	}
	if strings.Count(s, "-") == 5 {
		return true
	}
	return false
}
