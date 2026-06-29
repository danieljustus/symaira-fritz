package fritz

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRadios_ReturnsMultiple(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		sa := r.Header.Get("SoapAction")
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", `text/xml; charset="utf-8"`)

		if !strings.Contains(sa, "GetInfo") {
			_, _ = io.WriteString(w, soapEnvelope("GetInfo", nil))
			return
		}
		if strings.Contains(string(body), "WLANConfiguration:1") || strings.Contains(sa, "WLANConfiguration:1") {
			_, _ = io.WriteString(w, soapEnvelope("GetInfo", map[string]string{
				"NewSSID": "MyNet", "NewEnable": "1",
				"NewChannel": "6", "NewStandard": "802.11ac",
				"NewBSSID": "aa:bb:cc:dd:ee:01", "NewStatus": "Up",
			}))
			return
		}
		if strings.Contains(string(body), "WLANConfiguration:2") || strings.Contains(sa, "WLANConfiguration:2") {
			_, _ = io.WriteString(w, soapEnvelope("GetInfo", map[string]string{
				"NewSSID": "MyNet-5G", "NewEnable": "1",
				"NewChannel": "36", "NewStandard": "802.11ax",
				"NewBSSID": "aa:bb:cc:dd:ee:02", "NewStatus": "Up",
			}))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	c := New("fritz.box")
	c.tr064BaseURL = srv.URL

	radios, err := c.Radios(context.Background(), 3)
	if err != nil {
		t.Fatalf("Radios: %v", err)
	}
	if len(radios) != 2 {
		t.Fatalf("want 2 radios, got %d", len(radios))
	}
	if radios[0].SSID != "MyNet" || radios[0].Channel != "6" {
		t.Errorf("radio0 = %+v", radios[0])
	}
	if radios[0].Standard != "802.11ac" {
		t.Errorf("radio0 Standard = %q", radios[0].Standard)
	}
	if !radios[0].Enabled {
		t.Error("radio0 should be enabled")
	}
	if radios[1].SSID != "MyNet-5G" {
		t.Errorf("radio1 SSID = %q", radios[1].SSID)
	}
}

func TestRadios_NoRadios(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	c := New("fritz.box")
	c.tr064BaseURL = srv.URL

	_, err := c.Radios(context.Background(), 2)
	if err == nil {
		t.Fatal("expected error when no radios respond")
	}
}

func TestRadios_DefaultMaxN(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sa := r.Header.Get("SoapAction")
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", `text/xml; charset="utf-8"`)

		if strings.Contains(sa, "GetInfo") && (strings.Contains(string(body), "WLANConfiguration:1") || strings.Contains(sa, "WLANConfiguration:1")) {
			_, _ = io.WriteString(w, soapEnvelope("GetInfo", map[string]string{
				"NewSSID": "Only24G", "NewEnable": "0",
				"NewChannel": "11", "NewStandard": "802.11n",
				"NewBSSID": "aa:bb:cc:dd:ee:01", "NewStatus": "Down",
			}))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	c := New("fritz.box")
	c.tr064BaseURL = srv.URL

	radios, err := c.Radios(context.Background(), 0)
	if err != nil {
		t.Fatalf("Radios: %v", err)
	}
	if len(radios) != 1 {
		t.Fatalf("want 1 radio, got %d", len(radios))
	}
	if radios[0].SSID != "Only24G" {
		t.Errorf("radio SSID = %q", radios[0].SSID)
	}
}

func TestWLANClients_ReturnsClients(t *testing.T) {
	c := fakeBox(t, func(action, body string) string {
		switch action {
		case "GetTotalAssociations":
			return soapEnvelope(action, map[string]string{"NewTotalAssociations": "2"})
		case "GetGenericAssociatedDeviceInfo":
			if strings.Contains(body, "<NewAssociatedDeviceIndex>0</NewAssociatedDeviceIndex>") {
				return soapEnvelope(action, map[string]string{
					"NewAssociatedDeviceMACAddress": "aa:bb:cc:dd:ee:01",
					"NewAssociatedDeviceIPAddress":  "192.168.188.10",
					"NewX_AVM-DE_SignalStrength":    "80",
					"NewX_AVM-DE_Speed":             "300",
					"NewAssociatedDeviceAuthState":  "1",
				})
			}
			return soapEnvelope(action, map[string]string{
				"NewAssociatedDeviceMACAddress": "aa:bb:cc:dd:ee:02",
				"NewAssociatedDeviceIPAddress":  "192.168.188.11",
				"NewX_AVM-DE_SignalStrength":    "65",
				"NewX_AVM-DE_Speed":             "150",
				"NewAssociatedDeviceAuthState":  "0",
			})
		}
		return soapEnvelope(action, nil)
	})

	clients, err := c.WLANClients(context.Background(), 1)
	if err != nil {
		t.Fatalf("WLANClients: %v", err)
	}
	if len(clients) != 2 {
		t.Fatalf("want 2 clients, got %d", len(clients))
	}
	if clients[0].MAC != "aa:bb:cc:dd:ee:01" || clients[0].Signal != "80" {
		t.Errorf("client0 = %+v", clients[0])
	}
	if !clients[0].Authorized {
		t.Error("client0 should be authorized")
	}
	if clients[1].Authorized {
		t.Error("client1 should not be authorized")
	}
	if clients[0].RadioIndex != 1 {
		t.Errorf("client0 RadioIndex = %d", clients[0].RadioIndex)
	}
}

func TestWLANClients_ZeroAssociations(t *testing.T) {
	c := fakeBox(t, func(action, body string) string {
		if action == "GetTotalAssociations" {
			return soapEnvelope(action, map[string]string{"NewTotalAssociations": "0"})
		}
		return soapEnvelope(action, nil)
	})

	clients, err := c.WLANClients(context.Background(), 1)
	if err != nil {
		t.Fatalf("WLANClients: %v", err)
	}
	if len(clients) != 0 {
		t.Errorf("want 0 clients, got %d", len(clients))
	}
}

func TestAllWLANClients_Aggregates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		sa := r.Header.Get("SoapAction")
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", `text/xml; charset="utf-8"`)

		if strings.Contains(sa, "GetInfo") && (strings.Contains(string(body), "WLANConfiguration:1") || strings.Contains(sa, "WLANConfiguration:1")) {
			_, _ = io.WriteString(w, soapEnvelope("GetInfo", map[string]string{
				"NewSSID": "Net1", "NewEnable": "1", "NewChannel": "6",
				"NewStandard": "802.11ac", "NewBSSID": "aa:bb:cc:dd:ee:01", "NewStatus": "Up",
			}))
			return
		}
		if strings.Contains(sa, "GetTotalAssociations") {
			_, _ = io.WriteString(w, soapEnvelope("GetTotalAssociations", map[string]string{"NewTotalAssociations": "1"}))
			return
		}
		if strings.Contains(sa, "GetGenericAssociatedDeviceInfo") {
			_, _ = io.WriteString(w, soapEnvelope("GetGenericAssociatedDeviceInfo", map[string]string{
				"NewAssociatedDeviceMACAddress": "ff:ff:ff:ff:ff:01",
				"NewAssociatedDeviceIPAddress":  "10.0.0.2",
				"NewAssociatedDeviceAuthState":  "1",
			}))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	c := New("fritz.box")
	c.tr064BaseURL = srv.URL

	all, err := c.AllWLANClients(context.Background(), 2)
	if err != nil {
		t.Fatalf("AllWLANClients: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("want 1 client, got %d", len(all))
	}
	if all[0].MAC != "ff:ff:ff:ff:ff:01" {
		t.Errorf("MAC = %q", all[0].MAC)
	}
}

func TestGuestWLANStatus_Enabled(t *testing.T) {
	c := fakeBox(t, func(action, body string) string {
		if action == "GetInfo" {
			return soapEnvelope(action, map[string]string{
				"NewSSID": "GuestNet", "NewEnable": "1",
				"NewChannel": "11", "NewStandard": "802.11n",
				"NewStatus": "Up",
			})
		}
		return soapEnvelope(action, nil)
	})

	radio, err := c.GuestWLANStatus(context.Background(), 3)
	if err != nil {
		t.Fatalf("GuestWLANStatus: %v", err)
	}
	if radio.SSID != "GuestNet" {
		t.Errorf("SSID = %q", radio.SSID)
	}
	if !radio.Enabled {
		t.Error("expected enabled")
	}
	if radio.Index != 3 {
		t.Errorf("Index = %d, want 3", radio.Index)
	}
}

func TestGuestWLANStatus_Disabled(t *testing.T) {
	c := fakeBox(t, func(action, body string) string {
		if action == "GetInfo" {
			return soapEnvelope(action, map[string]string{
				"NewSSID": "GuestNet", "NewEnable": "0",
				"NewChannel": "0", "NewStandard": "",
				"NewStatus": "Down",
			})
		}
		return soapEnvelope(action, nil)
	})

	radio, err := c.GuestWLANStatus(context.Background(), 3)
	if err != nil {
		t.Fatalf("GuestWLANStatus: %v", err)
	}
	if radio.Enabled {
		t.Error("expected disabled")
	}
}

func TestSetGuestWLAN_Enable(t *testing.T) {
	var gotValue string
	c := fakeBox(t, func(action, body string) string {
		if action == "SetEnable" {
			if i := strings.Index(body, "<NewEnable>"); i >= 0 {
				seg := body[i+len("<NewEnable>"):]
				if j := strings.Index(seg, "</"); j >= 0 {
					gotValue = seg[:j]
				}
			}
			return soapEnvelope(action, nil)
		}
		return soapEnvelope(action, nil)
	})

	err := c.SetGuestWLAN(context.Background(), 3, true)
	if err != nil {
		t.Fatalf("SetGuestWLAN: %v", err)
	}
	if gotValue != "1" {
		t.Errorf("sent NewEnable = %q, want 1", gotValue)
	}
}

func TestSetGuestWLAN_Disable(t *testing.T) {
	var gotValue string
	c := fakeBox(t, func(action, body string) string {
		if action == "SetEnable" {
			if i := strings.Index(body, "<NewEnable>"); i >= 0 {
				seg := body[i+len("<NewEnable>"):]
				if j := strings.Index(seg, "</"); j >= 0 {
					gotValue = seg[:j]
				}
			}
			return soapEnvelope(action, nil)
		}
		return soapEnvelope(action, nil)
	})

	err := c.SetGuestWLAN(context.Background(), 3, false)
	if err != nil {
		t.Fatalf("SetGuestWLAN: %v", err)
	}
	if gotValue != "0" {
		t.Errorf("sent NewEnable = %q, want 0", gotValue)
	}
}
