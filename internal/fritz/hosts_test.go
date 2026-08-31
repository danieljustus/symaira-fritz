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

func TestHostByMAC_Found(t *testing.T) {
	c := fakeBox(t, func(action, body string) string {
		if action == "GetSpecificHostEntry" && strings.Contains(body, "F0:18:98:F3:64:B5") {
			return soapEnvelope(action, map[string]string{
				"NewHostName": "macmini", "NewIPAddress": "192.168.188.65",
				"NewMACAddress": "f0:18:98:f3:64:b5", "NewActive": "1",
				"NewInterfaceType": "Ethernet", "NewAddressSource": "DHCP",
				"NewLeaseTimeRemaining": "3600",
			})
		}
		return soapEnvelope(action, nil)
	})
	h, err := c.HostByMAC(context.Background(), "f0:18:98:f3:64:b5")
	if err != nil {
		t.Fatalf("HostByMAC: %v", err)
	}
	if h.Name != "macmini" {
		t.Errorf("Name = %q, want macmini", h.Name)
	}
	if h.IP != "192.168.188.65" {
		t.Errorf("IP = %q", h.IP)
	}
	if h.MAC != "F0:18:98:F3:64:B5" {
		t.Errorf("MAC = %q, want upper-cased", h.MAC)
	}
	if !h.Active {
		t.Error("expected active host")
	}
}

func TestHostByMAC_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `<s:Fault><faultcode>s:Client</faultcode><faultstring>No such entry</faultstring></s:Fault>`)
	}))
	t.Cleanup(srv.Close)
	c := New("fritz.box")
	c.tr064BaseURL = srv.URL

	_, err := c.HostByMAC(context.Background(), "aa:bb:cc:dd:ee:ff")
	if err == nil {
		t.Fatal("expected error for unknown MAC")
	}
}

func TestHostByName_Found(t *testing.T) {
	c := fakeBox(t, func(action, body string) string {
		switch action {
		case "GetHostNumberOfEntries":
			return soapEnvelope(action, map[string]string{"NewHostNumberOfEntries": "2"})
		case "GetGenericHostEntry":
			if strings.Contains(body, "<NewIndex>0</NewIndex>") {
				return soapEnvelope(action, map[string]string{
					"NewHostName": "macmini", "NewIPAddress": "192.168.188.65",
					"NewMACAddress": "aa:bb:cc:dd:ee:ff", "NewActive": "1",
					"NewInterfaceType": "Ethernet",
				})
			}
			return soapEnvelope(action, map[string]string{
				"NewHostName": "macbook", "NewIPAddress": "192.168.188.40",
				"NewMACAddress": "11:22:33:44:55:66", "NewActive": "0",
				"NewInterfaceType": "802.11",
			})
		}
		return soapEnvelope(action, nil)
	})

	h, err := c.HostByName(context.Background(), "macmini")
	if err != nil {
		t.Fatalf("HostByName: %v", err)
	}
	if h.Name != "macmini" || h.IP != "192.168.188.65" {
		t.Errorf("host = %+v", h)
	}
}

func TestHostByName_CaseInsensitive(t *testing.T) {
	c := fakeBox(t, func(action, body string) string {
		switch action {
		case "GetHostNumberOfEntries":
			return soapEnvelope(action, map[string]string{"NewHostNumberOfEntries": "1"})
		case "GetGenericHostEntry":
			return soapEnvelope(action, map[string]string{
				"NewHostName": "MacMini", "NewIPAddress": "10.0.0.1",
				"NewMACAddress": "aa:bb:cc:dd:ee:ff", "NewActive": "1",
			})
		}
		return soapEnvelope(action, nil)
	})

	h, err := c.HostByName(context.Background(), "MACMINI")
	if err != nil {
		t.Fatalf("HostByName case-insensitive: %v", err)
	}
	if h.Name != "MacMini" {
		t.Errorf("Name = %q, want MacMini", h.Name)
	}
}

func TestHostByName_NotFound(t *testing.T) {
	c := fakeBox(t, func(action, body string) string {
		switch action {
		case "GetHostNumberOfEntries":
			return soapEnvelope(action, map[string]string{"NewHostNumberOfEntries": "1"})
		case "GetGenericHostEntry":
			return soapEnvelope(action, map[string]string{"NewHostName": "other"})
		}
		return soapEnvelope(action, nil)
	})

	_, err := c.HostByName(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for unknown host name")
	}
	if !strings.Contains(err.Error(), "no host named") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestHostByName_Duplicate(t *testing.T) {
	c := fakeBox(t, func(action, body string) string {
		switch action {
		case "GetHostNumberOfEntries":
			return soapEnvelope(action, map[string]string{"NewHostNumberOfEntries": "2"})
		case "GetGenericHostEntry":
			return soapEnvelope(action, map[string]string{
				"NewHostName": "duplicate", "NewIPAddress": "10.0.0.1",
				"NewMACAddress": "aa:bb:cc:dd:ee:ff", "NewActive": "1",
			})
		}
		return soapEnvelope(action, nil)
	})

	_, err := c.HostByName(context.Background(), "duplicate")
	if err == nil {
		t.Fatal("expected error for duplicate host name")
	}
	if !strings.Contains(err.Error(), "2 hosts named") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestWakeOnLAN_Success(t *testing.T) {
	var gotMAC string
	c := fakeBox(t, func(action, body string) string {
		if action == "X_AVM-DE_WakeOnLANByMACAddress" {
			if i := strings.Index(body, "<NewMACAddress>"); i >= 0 {
				seg := body[i+len("<NewMACAddress>"):]
				if j := strings.Index(seg, "</"); j >= 0 {
					gotMAC = seg[:j]
				}
			}
			return soapEnvelope(action, nil)
		}
		return soapEnvelope(action, nil)
	})

	err := c.WakeOnLAN(context.Background(), "f0:18:98:f3:64:b5")
	if err != nil {
		t.Fatalf("WakeOnLAN: %v", err)
	}
	if gotMAC != "F0:18:98:F3:64:B5" {
		t.Errorf("sent MAC = %q, want upper-cased", gotMAC)
	}
}

func TestHosts_BulkPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/devicehostlist.lua" {
			w.Header().Set("Content-Type", "text/xml; charset=utf-8")
			_, _ = io.WriteString(w, `<?xml version="1.0" encoding="utf-8"?>
<List>
	<Item>
		<Index>1</Index>
		<IPAddress>192.168.188.65</IPAddress>
		<MACAddress>f0:18:98:f3:64:b5</MACAddress>
		<Active>1</Active>
		<HostName>macmini</HostName>
		<InterfaceType>Ethernet</InterfaceType>
		<AddressSource>DHCP</AddressSource>
		<LeaseTimeRemaining>3600</LeaseTimeRemaining>
	</Item>
	<Item>
		<Index>2</Index>
		<IPAddress>192.168.188.40</IPAddress>
		<MACAddress>aa:bb:cc:dd:ee:ff</MACAddress>
		<Active>0</Active>
		<HostName>macbook</HostName>
		<InterfaceType>802.11</InterfaceType>
		<AddressSource>DHCP</AddressSource>
		<LeaseTimeRemaining>0</LeaseTimeRemaining>
	</Item>
</List>`)
			return
		}

		action := r.Header.Get("SoapAction")
		if strings.Contains(action, "X_AVM-DE_GetHostListPath") {
			w.Header().Set("Content-Type", "text/xml; charset=utf-8")
			_, _ = io.WriteString(w, soapEnvelope("X_AVM-DE_GetHostListPath", map[string]string{
				"NewX_AVM-DE_HostListPath": "/devicehostlist.lua",
			}))
			return
		}

		http.Error(w, "unexpected request", http.StatusBadRequest)
	}))
	t.Cleanup(srv.Close)

	c := New("fritz.box")
	c.tr064BaseURL = srv.URL
	c.httpBaseURL = srv.URL

	hosts, err := c.Hosts(context.Background())
	if err != nil {
		t.Fatalf("Hosts bulk: %v", err)
	}
	if len(hosts) != 2 {
		t.Fatalf("want 2 hosts, got %d", len(hosts))
	}
	if hosts[0].Name != "macmini" || hosts[0].IP != "192.168.188.65" || hosts[0].MAC != "F0:18:98:F3:64:B5" {
		t.Errorf("host0 = %+v", hosts[0])
	}
	if !hosts[0].Active || hosts[0].Link() != "LAN" || hosts[0].LeaseTimeRemaining != 3600 {
		t.Errorf("host0 fields wrong: %+v", hosts[0])
	}
	if hosts[1].Name != "macbook" || hosts[1].IP != "192.168.188.40" || hosts[1].MAC != "AA:BB:CC:DD:EE:FF" {
		t.Errorf("host1 = %+v", hosts[1])
	}
	if hosts[1].Active || hosts[1].Link() != "WLAN" {
		t.Errorf("host1 fields wrong: %+v", hosts[1])
	}
}

func TestHosts_UnsupportedFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		action := r.Header.Get("SoapAction")
		body, _ := io.ReadAll(r.Body)

		if strings.Contains(action, "X_AVM-DE_GetHostListPath") {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, `<s:Fault><faultcode>s:Client</faultcode><faultstring>UPnPError 401</faultstring></s:Fault>`)
			return
		}

		w.Header().Set("Content-Type", "text/xml; charset=utf-8")
		if strings.Contains(action, "GetHostNumberOfEntries") {
			_, _ = io.WriteString(w, soapEnvelope("GetHostNumberOfEntries", map[string]string{"NewHostNumberOfEntries": "1"}))
			return
		}
		if strings.Contains(action, "GetGenericHostEntry") && strings.Contains(string(body), "<NewIndex>0</NewIndex>") {
			_, _ = io.WriteString(w, soapEnvelope("GetGenericHostEntry", map[string]string{
				"NewHostName": "fallback-box", "NewIPAddress": "192.168.188.99",
				"NewMACAddress": "11:22:33:44:55:66", "NewActive": "1",
				"NewInterfaceType": "Ethernet", "NewAddressSource": "DHCP",
				"NewLeaseTimeRemaining": "1800",
			}))
			return
		}

		http.Error(w, "unexpected", http.StatusBadRequest)
	}))
	t.Cleanup(srv.Close)

	c := New("fritz.box")
	c.tr064BaseURL = srv.URL
	c.httpBaseURL = srv.URL

	hosts, err := c.Hosts(context.Background())
	if err != nil {
		t.Fatalf("Hosts fallback: %v", err)
	}
	if len(hosts) != 1 {
		t.Fatalf("want 1 host from fallback, got %d", len(hosts))
	}
	if hosts[0].Name != "fallback-box" || hosts[0].IP != "192.168.188.99" || hosts[0].MAC != "11:22:33:44:55:66" {
		t.Errorf("host0 = %+v", hosts[0])
	}
	if !hosts[0].Active || hosts[0].Link() != "LAN" || hosts[0].LeaseTimeRemaining != 1800 {
		t.Errorf("host0 fields = %+v", hosts[0])
	}
}

func TestHosts_MalformedBulkDocument(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/devicehostlist.lua" {
			w.Header().Set("Content-Type", "text/xml; charset=utf-8")
			_, _ = io.WriteString(w, `<?xml version="1.0"?><List><Item><unclosed-xml>`)
			return
		}

		action := r.Header.Get("SoapAction")
		body, _ := io.ReadAll(r.Body)

		if strings.Contains(action, "X_AVM-DE_GetHostListPath") {
			w.Header().Set("Content-Type", "text/xml; charset=utf-8")
			_, _ = io.WriteString(w, soapEnvelope("X_AVM-DE_GetHostListPath", map[string]string{
				"NewX_AVM-DE_HostListPath": "/devicehostlist.lua",
			}))
			return
		}

		w.Header().Set("Content-Type", "text/xml; charset=utf-8")
		if strings.Contains(action, "GetHostNumberOfEntries") {
			_, _ = io.WriteString(w, soapEnvelope("GetHostNumberOfEntries", map[string]string{"NewHostNumberOfEntries": "1"}))
			return
		}
		if strings.Contains(action, "GetGenericHostEntry") && strings.Contains(string(body), "<NewIndex>0</NewIndex>") {
			_, _ = io.WriteString(w, soapEnvelope("GetGenericHostEntry", map[string]string{
				"NewHostName": "recovered-box", "NewIPAddress": "192.168.188.100",
				"NewMACAddress": "22:33:44:55:66:77", "NewActive": "1",
				"NewInterfaceType": "802.11", "NewAddressSource": "Static",
				"NewLeaseTimeRemaining": "0",
			}))
			return
		}

		http.Error(w, "unexpected", http.StatusBadRequest)
	}))
	t.Cleanup(srv.Close)

	c := New("fritz.box")
	c.tr064BaseURL = srv.URL
	c.httpBaseURL = srv.URL

	hosts, err := c.Hosts(context.Background())
	if err != nil {
		t.Fatalf("Hosts malformed fallback: %v", err)
	}
	if len(hosts) != 1 {
		t.Fatalf("want 1 host from fallback after malformed XML, got %d", len(hosts))
	}
	if hosts[0].Name != "recovered-box" || hosts[0].IP != "192.168.188.100" || hosts[0].MAC != "22:33:44:55:66:77" {
		t.Errorf("host0 = %+v", hosts[0])
	}
	if !hosts[0].Active || hosts[0].Link() != "WLAN" {
		t.Errorf("host0 fields = %+v", hosts[0])
	}
}

func TestHosts_FieldParity(t *testing.T) {
	// 1. Bulk server
	bulkSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/devicehostlist.lua" {
			w.Header().Set("Content-Type", "text/xml; charset=utf-8")
			_, _ = io.WriteString(w, `<?xml version="1.0" encoding="utf-8"?>
<List>
	<Item>
		<IPAddress>192.168.188.20</IPAddress>
		<MACAddress>aa:bb:cc:11:22:33</MACAddress>
		<Active>1</Active>
		<HostName>my-printer</HostName>
		<InterfaceType>Ethernet</InterfaceType>
		<AddressSource>DHCP</AddressSource>
		<LeaseTimeRemaining>7200</LeaseTimeRemaining>
	</Item>
</List>`)
			return
		}
		action := r.Header.Get("SoapAction")
		if strings.Contains(action, "X_AVM-DE_GetHostListPath") {
			w.Header().Set("Content-Type", "text/xml; charset=utf-8")
			_, _ = io.WriteString(w, soapEnvelope("X_AVM-DE_GetHostListPath", map[string]string{
				"NewX_AVM-DE_HostListPath": "/devicehostlist.lua",
			}))
			return
		}
		http.Error(w, "unexpected", http.StatusBadRequest)
	}))
	t.Cleanup(bulkSrv.Close)

	// 2. Index server
	indexSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		action := r.Header.Get("SoapAction")
		w.Header().Set("Content-Type", "text/xml; charset=utf-8")
		if strings.Contains(action, "GetHostNumberOfEntries") {
			_, _ = io.WriteString(w, soapEnvelope("GetHostNumberOfEntries", map[string]string{"NewHostNumberOfEntries": "1"}))
			return
		}
		if strings.Contains(action, "GetGenericHostEntry") {
			_, _ = io.WriteString(w, soapEnvelope("GetGenericHostEntry", map[string]string{
				"NewHostName": "my-printer", "NewIPAddress": "192.168.188.20",
				"NewMACAddress": "aa:bb:cc:11:22:33", "NewActive": "1",
				"NewInterfaceType": "Ethernet", "NewAddressSource": "DHCP",
				"NewLeaseTimeRemaining": "7200",
			}))
			return
		}
		http.Error(w, "unexpected", http.StatusBadRequest)
	}))
	t.Cleanup(indexSrv.Close)

	bulkClient := New("fritz.box")
	bulkClient.tr064BaseURL = bulkSrv.URL
	bulkClient.httpBaseURL = bulkSrv.URL

	indexClient := New("fritz.box")
	indexClient.tr064BaseURL = indexSrv.URL
	indexClient.httpBaseURL = indexSrv.URL

	bulkHostsList, err := bulkClient.bulkHosts(context.Background())
	if err != nil {
		t.Fatalf("bulkHosts: %v", err)
	}

	indexHostsList, err := indexClient.hostsFromIndex(context.Background())
	if err != nil {
		t.Fatalf("hostsFromIndex: %v", err)
	}

	if len(bulkHostsList) != len(indexHostsList) {
		t.Fatalf("length mismatch: bulk=%d, index=%d", len(bulkHostsList), len(indexHostsList))
	}

	bh := bulkHostsList[0]
	ih := indexHostsList[0]

	if bh.Name != ih.Name {
		t.Errorf("Name parity mismatch: bulk=%q, index=%q", bh.Name, ih.Name)
	}
	if bh.IP != ih.IP {
		t.Errorf("IP parity mismatch: bulk=%q, index=%q", bh.IP, ih.IP)
	}
	if bh.MAC != ih.MAC {
		t.Errorf("MAC parity mismatch: bulk=%q, index=%q", bh.MAC, ih.MAC)
	}
	if bh.Active != ih.Active {
		t.Errorf("Active parity mismatch: bulk=%v, index=%v", bh.Active, ih.Active)
	}
	if bh.InterfaceType != ih.InterfaceType {
		t.Errorf("InterfaceType parity mismatch: bulk=%q, index=%q", bh.InterfaceType, ih.InterfaceType)
	}
	if bh.AddressSource != ih.AddressSource {
		t.Errorf("AddressSource parity mismatch: bulk=%q, index=%q", bh.AddressSource, ih.AddressSource)
	}
	if bh.LeaseTimeRemaining != ih.LeaseTimeRemaining {
		t.Errorf("LeaseTimeRemaining parity mismatch: bulk=%d, index=%d", bh.LeaseTimeRemaining, ih.LeaseTimeRemaining)
	}
	if bh.Link() != ih.Link() {
		t.Errorf("Link() parity mismatch: bulk=%q, index=%q", bh.Link(), ih.Link())
	}
}
