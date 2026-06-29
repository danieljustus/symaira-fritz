package fritz

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeBox is a minimal TR-064 SOAP server for tests. It returns 200 directly
// (no digest challenge) so tests focus on request routing and response parsing.
func fakeBox(t *testing.T, handler func(action, body string) string) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		action := r.Header.Get("SoapAction")
		if i := strings.LastIndex(action, "#"); i >= 0 {
			action = action[i+1:]
		}
		resp := handler(action, string(body))
		w.Header().Set("Content-Type", `text/xml; charset="utf-8"`)
		_, _ = io.WriteString(w, resp)
	}))
	t.Cleanup(srv.Close)
	c := New("fritz.box")
	c.tr064BaseURL = srv.URL
	c.httpBaseURL = srv.URL
	return c
}

func soapEnvelope(action string, args map[string]string) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>`)
	b.WriteString("<u:" + action + "Response>")
	for k, v := range args {
		b.WriteString("<" + k + ">" + v + "</" + k + ">")
	}
	b.WriteString("</u:" + action + "Response>")
	b.WriteString(`</s:Body></s:Envelope>`)
	return b.String()
}

func TestHosts_ListAndParse(t *testing.T) {
	c := fakeBox(t, func(action, body string) string {
		switch action {
		case "GetHostNumberOfEntries":
			return soapEnvelope(action, map[string]string{"NewHostNumberOfEntries": "2"})
		case "GetGenericHostEntry":
			if strings.Contains(body, "<NewIndex>0</NewIndex>") {
				return soapEnvelope(action, map[string]string{
					"NewHostName": "macmini", "NewIPAddress": "192.168.188.65",
					"NewMACAddress": "f0:18:98:f3:64:b5", "NewActive": "1",
					"NewInterfaceType": "Ethernet", "NewAddressSource": "DHCP",
					"NewLeaseTimeRemaining": "3600",
				})
			}
			return soapEnvelope(action, map[string]string{
				"NewHostName": "macbook", "NewIPAddress": "192.168.188.40",
				"NewMACAddress": "aa:bb:cc:dd:ee:ff", "NewActive": "0",
				"NewInterfaceType": "802.11", "NewAddressSource": "DHCP",
			})
		}
		return soapEnvelope(action, nil)
	})

	hosts, err := c.Hosts(context.Background())
	if err != nil {
		t.Fatalf("Hosts: %v", err)
	}
	if len(hosts) != 2 {
		t.Fatalf("want 2 hosts, got %d", len(hosts))
	}
	if hosts[0].Name != "macmini" || hosts[0].IP != "192.168.188.65" {
		t.Errorf("host0 = %+v", hosts[0])
	}
	if hosts[0].MAC != "F0:18:98:F3:64:B5" {
		t.Errorf("MAC not upper-cased: %q", hosts[0].MAC)
	}
	if !hosts[0].Active || hosts[0].Link() != "LAN" {
		t.Errorf("host0 active/link wrong: %+v", hosts[0])
	}
	if hosts[1].Link() != "WLAN" {
		t.Errorf("host1 link = %q, want WLAN", hosts[1].Link())
	}
	if hosts[1].Active {
		t.Errorf("host1 should be inactive")
	}
}

func TestActiveHosts_Filters(t *testing.T) {
	c := fakeBox(t, func(action, body string) string {
		switch action {
		case "GetHostNumberOfEntries":
			return soapEnvelope(action, map[string]string{"NewHostNumberOfEntries": "2"})
		case "GetGenericHostEntry":
			active := "1"
			if strings.Contains(body, "<NewIndex>1</NewIndex>") {
				active = "0"
			}
			return soapEnvelope(action, map[string]string{"NewHostName": "h", "NewActive": active})
		}
		return soapEnvelope(action, nil)
	})
	hosts, err := c.ActiveHosts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 1 {
		t.Fatalf("want 1 active host, got %d", len(hosts))
	}
}

func TestResolveHost_Detection(t *testing.T) {
	if !looksLikeIP("192.168.1.1") || looksLikeIP("not.an.ip.addr") {
		t.Error("looksLikeIP misclassified")
	}
	if !looksLikeMAC("aa:bb:cc:dd:ee:ff") || looksLikeMAC("hostname") {
		t.Error("looksLikeMAC misclassified")
	}
}
