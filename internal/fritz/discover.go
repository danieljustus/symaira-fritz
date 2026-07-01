package fritz

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
)

// TR-064 service discovery. The box publishes /tr64desc.xml describing every
// service it offers — service type plus the control URL to call it on. Parsing
// it lets symfritz call services that aren't in the hardcoded shortcut list and
// adapts to model/firmware differences.

// scpdDevice mirrors the nested device tree in tr64desc.xml.
type scpdDevice struct {
	DeviceType  string        `xml:"deviceType"`
	ServiceList []scpdService `xml:"serviceList>service"`
	DeviceList  []scpdDevice  `xml:"deviceList>device"`
}

type scpdService struct {
	ServiceType string `xml:"serviceType"`
	ControlURL  string `xml:"controlURL"`
}

type scpdRoot struct {
	XMLName xml.Name   `xml:"root"`
	Device  scpdDevice `xml:"device"`
}

// Discover fetches and parses /tr64desc.xml, returning all advertised services
// keyed by service type. The description document is unauthenticated.
func (c *Client) Discover(ctx context.Context) ([]Service, error) {
	if err := c.checkHostDNS(ctx); err != nil {
		return nil, err
	}
	u := c.tr064Base() + "/tr64desc.xml"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		// If the host resolves to a public IP, suggest running detect.
		if hint := publicHostHint(ctx, c.Host); hint != "" {
			return nil, fmt.Errorf("discover: contacting %s: %w\n\n%s", c.Host, err, hint)
		}
		return nil, fmt.Errorf("discover: contacting %s: %w", c.Host, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discover: tr64desc.xml returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	var root scpdRoot
	if err := xml.Unmarshal(body, &root); err != nil {
		return nil, fmt.Errorf("discover: parsing tr64desc.xml: %w", err)
	}

	var services []Service
	var walk func(d scpdDevice)
	walk = func(d scpdDevice) {
		for _, s := range d.ServiceList {
			services = append(services, Service{
				Type:       s.ServiceType,
				ControlURL: s.ControlURL,
			})
		}
		for _, sub := range d.DeviceList {
			walk(sub)
		}
	}
	walk(root.Device)

	sort.Slice(services, func(i, j int) bool { return services[i].Type < services[j].Type })
	return services, nil
}

// ServiceByName finds a discovered service whose type contains the given
// (case-insensitive) substring, e.g. "WANIPConnection" or "Hosts". Returns an
// error if zero or many match.
func (c *Client) ServiceByName(ctx context.Context, name string) (Service, error) {
	services, err := c.Discover(ctx)
	if err != nil {
		return Service{}, err
	}
	lname := strings.ToLower(name)
	var matches []Service
	for _, s := range services {
		if strings.Contains(strings.ToLower(s.Type), lname) {
			matches = append(matches, s)
		}
	}
	switch len(matches) {
	case 0:
		return Service{}, fmt.Errorf("no discovered service matches %q", name)
	case 1:
		return matches[0], nil
	default:
		// Prefer an exact local-name match (":<name>:") if present.
		for _, m := range matches {
			if strings.Contains(strings.ToLower(m.Type), ":"+lname+":") {
				return m, nil
			}
		}
		return Service{}, fmt.Errorf("%d services match %q; be more specific", len(matches), name)
	}
}
