package fritz

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// TR-064 is the SOAP administration interface. Each service (e.g.
// WANIPConnection, DeviceInfo, Hosts, WLANConfiguration) exposes actions
// (GetExternalIPAddress, GetInfo, …). Service metadata lives in tr64desc.xml on
// the box; this scaffold calls services by their well-known control URL and
// type so you don't need to parse the SCPD up front.
//
// TODO: parse /tr64desc.xml to auto-discover services, control URLs, and the
// argument lists for each action (this is what fritzconnection does). Until
// then, callers pass the service triple explicitly via Service.

// Service identifies a TR-064 service endpoint.
type Service struct {
	// Type is the full service type, e.g.
	// "urn:dslforum-org:service:WANIPConnection:1".
	Type string
	// ControlURL is the SOAP control path, e.g.
	// "/upnp/control/wanipconnection1".
	ControlURL string
}

// Common services. Extend this set as commands are added.
var (
	ServiceDeviceInfo            = Service{"urn:dslforum-org:service:DeviceInfo:1", "/upnp/control/deviceinfo"}
	ServiceWANIPConnection       = Service{"urn:dslforum-org:service:WANIPConnection:1", "/upnp/control/wanipconnection1"}
	ServiceWANCommonIFC          = Service{"urn:dslforum-org:service:WANCommonInterfaceConfig:1", "/upnp/control/wancommonifconfig1"}
	ServiceHosts                 = Service{"urn:dslforum-org:service:Hosts:1", "/upnp/control/hosts"}
	ServiceWLANConfig1           = Service{"urn:dslforum-org:service:WLANConfiguration:1", "/upnp/control/wlanconfig1"}
	ServiceWANDSLInterfaceConfig = Service{"urn:dslforum-org:service:WANDSLInterfaceConfig:1", "/upnp/control/wandslifconfig1"}
	ServiceVoIP                  = Service{"urn:dslforum-org:service:X_VoIP:1", "/upnp/control/x_voip"}
	ServiceOnTel                 = Service{"urn:dslforum-org:service:X_AVM-DE_OnTel:1", "/upnp/control/x_contact"}
	ServiceUserInterface         = Service{"urn:dslforum-org:service:UserInterface:1", "/upnp/control/userif"}
	ServiceHomeauto              = Service{"urn:dslforum-org:service:X_AVM-DE_Homeauto:1", "/upnp/control/x_homeauto"}
)

// Call invokes a TR-064 action and returns the output arguments as a map.
// args are the input arguments (may be nil). It transparently performs the HTTP
// digest auth handshake.
func (c *Client) Call(ctx context.Context, svc Service, action string, args map[string]string) (map[string]string, error) {
	body := buildSOAPRequest(svc.Type, action, args)
	soapAction := svc.Type + "#" + action
	url := c.tr064Base() + svc.ControlURL

	// First attempt — expect a 401 carrying the digest challenge.
	resp, raw, err := c.doSOAP(ctx, url, svc.ControlURL, soapAction, body, "")
	if err != nil {
		return nil, classifyError(err, svc, action)
	}
	if resp.StatusCode == http.StatusUnauthorized {
		dc, ok := parseDigestChallenge(resp.Header.Get("WWW-Authenticate"))
		if !ok {
			return nil, &FritzError{Kind: ErrUnauthorized, Service: shortService(svc.Type), Action: action, Raw: "401 without a parseable digest challenge", HTTPStatus: 401}
		}
		auth := digestAuthHeader(dc, c.User, c.Password, http.MethodPost, svc.ControlURL)
		resp, raw, err = c.doSOAP(ctx, url, svc.ControlURL, soapAction, body, auth)
		if err != nil {
			return nil, classifyError(err, svc, action)
		}
	}

	if resp.StatusCode != http.StatusOK {
		fault := soapFaultString(raw)
		fe := &FritzError{
			Service:    shortService(svc.Type),
			Action:     action,
			Raw:        fault,
			HTTPStatus: resp.StatusCode,
		}
		switch {
		case resp.StatusCode == http.StatusUnauthorized:
			fe.Kind = ErrUnauthorized
		case strings.Contains(fault, "Invalid Action"):
			fe.Kind = ErrUnsupportedAction
		case resp.StatusCode >= 500:
			fe.Kind = ErrServiceUnavailable
		default:
			fe.Kind = ErrServiceUnavailable
		}
		return nil, fe
	}
	return parseSOAPResponse(raw, action)
}

// doSOAP performs one POST. controlPath is the URI used in the digest header.
func (c *Client) doSOAP(ctx context.Context, url, controlPath, soapAction string, body []byte, auth string) (*http.Response, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
	req.Header.Set("SoapAction", soapAction)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("tr064: contacting %s: %w", c.Host, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, nil, err
	}
	return resp, raw, nil
}

func buildSOAPRequest(serviceType, action string, args map[string]string) []byte {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="utf-8"?>`)
	b.WriteString(`<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">`)
	b.WriteString(`<s:Body>`)
	fmt.Fprintf(&b, `<u:%s xmlns:u="%s">`, action, serviceType)
	for k, v := range args {
		fmt.Fprintf(&b, "<%s>%s</%s>", k, xmlEscape(v), k)
	}
	fmt.Fprintf(&b, `</u:%s>`, action)
	b.WriteString(`</s:Body></s:Envelope>`)
	return []byte(b.String())
}

// parseSOAPResponse extracts the children of the <u:ActionResponse> element
// into a flat map. It is namespace-agnostic by matching on local names.
func parseSOAPResponse(raw []byte, action string) (map[string]string, error) {
	out := map[string]string{}
	dec := xml.NewDecoder(bytes.NewReader(raw))
	var (
		inResponse bool
		curKey     string
	)
	respLocal := action + "Response"
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("tr064: parsing response: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if t.Name.Local == respLocal {
				inResponse = true
			} else if inResponse {
				curKey = t.Name.Local
			}
		case xml.CharData:
			if inResponse && curKey != "" {
				out[curKey] += string(t)
			}
		case xml.EndElement:
			if t.Name.Local == respLocal {
				inResponse = false
			} else if inResponse {
				curKey = ""
			}
		}
	}
	if len(out) == 0 {
		return out, nil // action may legitimately return no out-args
	}
	return out, nil
}

// soapFaultString pulls a human-readable error out of a SOAP fault body.
func soapFaultString(raw []byte) string {
	s := string(raw)
	if i := strings.Index(s, "errorDescription"); i >= 0 {
		seg := s[i:]
		if j := strings.Index(seg, "</"); j >= 0 {
			if k := strings.Index(seg, ">"); k >= 0 && k < j {
				return strings.TrimSpace(seg[k+1 : j])
			}
		}
	}
	if len(s) > 200 {
		return s[:200]
	}
	return s
}

func xmlEscape(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// fetchAuthenticatedURL downloads a resource URL from the box, executing
// HTTP digest authentication if the box returns 401.
func (c *Client) fetchAuthenticatedURL(ctx context.Context, rawURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		parsedURL, err := url.Parse(rawURL)
		if err != nil {
			return nil, err
		}
		dc, ok := parseDigestChallenge(resp.Header.Get("WWW-Authenticate"))
		if !ok {
			return nil, fmt.Errorf("fetch: 401 without digest challenge")
		}
		auth := digestAuthHeader(dc, c.User, c.Password, http.MethodGet, parsedURL.RequestURI())
		req2, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			return nil, err
		}
		req2.Header.Set("Authorization", auth)
		resp2, err := c.http.Do(req2)
		if err != nil {
			return nil, err
		}
		defer resp2.Body.Close()
		if resp2.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("fetch: HTTP %d", resp2.StatusCode)
		}
		return io.ReadAll(resp2.Body)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch: HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}
