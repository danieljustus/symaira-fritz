package fritz

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

// TestHome_RefreshesSIDOn403 verifies the AHA layer re-logs in once on a 403
// and retries, instead of surfacing a spurious "session expired" error.
func TestHome_RefreshesSIDOn403(t *testing.T) {
	var sidServes, ahaCalls int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/login_sid.lua"):
			// Any login attempt returns a valid SID immediately.
			n := atomic.AddInt32(&sidServes, 1)
			_, _ = w.Write([]byte(`<?xml version="1.0"?><SessionInfo><SID>sid` +
				string(rune('0'+n)) + `000000000000</SID><Challenge>x</Challenge><BlockTime>0</BlockTime></SessionInfo>`))
		case strings.HasPrefix(r.URL.Path, "/webservices/homeautoswitch.lua"):
			// First AHA call 403s; the retry (with a refreshed SID) succeeds.
			if atomic.AddInt32(&ahaCalls, 1) == 1 {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			_, _ = w.Write([]byte("OK\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c := New("fritz.box")
	c.httpBaseURL = srv.URL
	// Seed a cached SID so the first request uses it (and then gets a 403).
	c.sid = "staleSID00000000"

	out, err := c.Home(context.Background(), "getswitchlist", nil)
	if err != nil {
		t.Fatalf("Home returned error despite retry path: %v", err)
	}
	if out != "OK" {
		t.Errorf("output = %q, want OK", out)
	}
	if atomic.LoadInt32(&ahaCalls) != 2 {
		t.Errorf("expected 2 AHA calls (403 then retry), got %d", ahaCalls)
	}
	if atomic.LoadInt32(&sidServes) == 0 {
		t.Error("expected a re-login after the 403")
	}
}

func fakeAHA(t *testing.T, handler func(cmd string, params url.Values) (string, int)) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/login_sid.lua"):
			_, _ = w.Write([]byte(`<?xml version="1.0"?><SessionInfo><SID>ahatestsid000000</SID><Challenge>x</Challenge><BlockTime>0</BlockTime></SessionInfo>`))
		case strings.HasPrefix(r.URL.Path, "/webservices/homeautoswitch.lua"):
			cmd := r.URL.Query().Get("switchcmd")
			body, status := handler(cmd, r.URL.Query())
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	c := New("fritz.box")
	c.httpBaseURL = srv.URL
	return c
}

func TestDevices_ParsesXML(t *testing.T) {
	xmlResp := `<?xml version="1.0"?>
<devicelist version="1">
  <device identifier="123456789" id="0">
    <name>FRITZ!DECT 200</name>
    <present>1</present>
    <switch><state>1</state></switch>
    <temperature><celsius>235</celsius></temperature>
    <hkr><tist>44</tist><tsoll>42</tsoll></hkr>
  </device>
  <device identifier="987654321" id="1">
    <name>FRITZ!DECT 301</name>
    <present>1</present>
    <switch><state>0</state></switch>
    <temperature><celsius>210</celsius></temperature>
    <hkr><tist>42</tist><tsoll>28</tsoll></hkr>
  </device>
</devicelist>`

	c := fakeAHA(t, func(cmd string, params url.Values) (string, int) {
		if cmd == "getdevicelistinfos" {
			return xmlResp, http.StatusOK
		}
		return "", http.StatusBadRequest
	})

	devices, err := c.Devices(context.Background())
	if err != nil {
		t.Fatalf("Devices: %v", err)
	}
	if len(devices) != 2 {
		t.Fatalf("want 2 devices, got %d", len(devices))
	}
	if devices[0].Identifier != "123456789" {
		t.Errorf("device0 Identifier = %q", devices[0].Identifier)
	}
	if devices[0].Name != "FRITZ!DECT 200" {
		t.Errorf("device0 Name = %q", devices[0].Name)
	}
	if devices[0].Present != 1 {
		t.Errorf("device0 Present = %d", devices[0].Present)
	}
	if devices[0].Switch.State != "1" {
		t.Errorf("device0 Switch.State = %q", devices[0].Switch.State)
	}
	if devices[0].Temperature.Celsius != "235" {
		t.Errorf("device0 Temperature.Celsius = %q", devices[0].Temperature.Celsius)
	}
	if devices[0].Hkr.Tist != "44" {
		t.Errorf("device0 Hkr.Tist = %q", devices[0].Hkr.Tist)
	}
	if devices[0].Hkr.Tsoll != "42" {
		t.Errorf("device0 Hkr.Tsoll = %q", devices[0].Hkr.Tsoll)
	}
	if devices[1].Name != "FRITZ!DECT 301" {
		t.Errorf("device1 Name = %q", devices[1].Name)
	}
	if devices[1].Switch.State != "0" {
		t.Errorf("device1 Switch.State = %q", devices[1].Switch.State)
	}
}

func TestDevices_EmptyList(t *testing.T) {
	c := fakeAHA(t, func(cmd string, params url.Values) (string, int) {
		if cmd == "getdevicelistinfos" {
			return `<?xml version="1.0"?><devicelist version="1"></devicelist>`, http.StatusOK
		}
		return "", http.StatusBadRequest
	})

	devices, err := c.Devices(context.Background())
	if err != nil {
		t.Fatalf("Devices: %v", err)
	}
	if len(devices) != 0 {
		t.Errorf("want 0 devices, got %d", len(devices))
	}
}

func TestDevices_InvalidXML(t *testing.T) {
	c := fakeAHA(t, func(cmd string, params url.Values) (string, int) {
		if cmd == "getdevicelistinfos" {
			return `{not xml`, http.StatusOK
		}
		return "", http.StatusBadRequest
	})

	_, err := c.Devices(context.Background())
	if err == nil {
		t.Fatal("expected error for invalid XML")
	}
	if !strings.Contains(err.Error(), "parsing device list") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSwitchOn_SendsCorrectCommand(t *testing.T) {
	var gotCmd string
	var gotAIN string
	c := fakeAHA(t, func(cmd string, params url.Values) (string, int) {
		gotCmd = cmd
		gotAIN = params.Get("ain")
		if cmd == "setswitchon" {
			return "OK", http.StatusOK
		}
		return "", http.StatusBadRequest
	})

	err := c.SwitchOn(context.Background(), "123456789")
	if err != nil {
		t.Fatalf("SwitchOn: %v", err)
	}
	if gotCmd != "setswitchon" {
		t.Errorf("cmd = %q, want setswitchon", gotCmd)
	}
	if gotAIN != "123456789" {
		t.Errorf("ain = %q, want 123456789", gotAIN)
	}
}

func TestSwitchOff_SendsCorrectCommand(t *testing.T) {
	var gotCmd string
	var gotAIN string
	c := fakeAHA(t, func(cmd string, params url.Values) (string, int) {
		gotCmd = cmd
		gotAIN = params.Get("ain")
		if cmd == "setswitchoff" {
			return "OK", http.StatusOK
		}
		return "", http.StatusBadRequest
	})

	err := c.SwitchOff(context.Background(), "987654321")
	if err != nil {
		t.Fatalf("SwitchOff: %v", err)
	}
	if gotCmd != "setswitchoff" {
		t.Errorf("cmd = %q, want setswitchoff", gotCmd)
	}
	if gotAIN != "987654321" {
		t.Errorf("ain = %q, want 987654321", gotAIN)
	}
}

func TestSetHkrTemp_NormalTemperature(t *testing.T) {
	var gotCmd string
	var gotParams url.Values
	c := fakeAHA(t, func(cmd string, params url.Values) (string, int) {
		gotCmd = cmd
		gotParams = params
		if cmd == "sethkrtsoll" {
			return "OK", http.StatusOK
		}
		return "", http.StatusBadRequest
	})

	err := c.SetHkrTemp(context.Background(), "AIN123", 20.5)
	if err != nil {
		t.Fatalf("SetHkrTemp: %v", err)
	}
	if gotCmd != "sethkrtsoll" {
		t.Errorf("cmd = %q, want sethkrtsoll", gotCmd)
	}
	if gotParams.Get("ain") != "AIN123" {
		t.Errorf("ain = %q", gotParams.Get("ain"))
	}
	if gotParams.Get("param") != "41" {
		t.Errorf("param = %q, want 41 (20.5*2)", gotParams.Get("param"))
	}
}

func TestSetHkrTemp_SpecialOn(t *testing.T) {
	var gotParam string
	c := fakeAHA(t, func(cmd string, params url.Values) (string, int) {
		if cmd == "sethkrtsoll" {
			gotParam = params.Get("param")
			return "OK", http.StatusOK
		}
		return "", http.StatusBadRequest
	})

	err := c.SetHkrTemp(context.Background(), "AIN123", 254)
	if err != nil {
		t.Fatalf("SetHkrTemp: %v", err)
	}
	if gotParam != "254" {
		t.Errorf("param = %q, want 254 (ON)", gotParam)
	}
}

func TestSetHkrTemp_SpecialOff(t *testing.T) {
	var gotParam string
	c := fakeAHA(t, func(cmd string, params url.Values) (string, int) {
		if cmd == "sethkrtsoll" {
			gotParam = params.Get("param")
			return "OK", http.StatusOK
		}
		return "", http.StatusBadRequest
	})

	err := c.SetHkrTemp(context.Background(), "AIN123", 253)
	if err != nil {
		t.Fatalf("SetHkrTemp: %v", err)
	}
	if gotParam != "253" {
		t.Errorf("param = %q, want 253 (OFF)", gotParam)
	}
}

func TestSetHkrTemp_RoundTemperature(t *testing.T) {
	var gotParam string
	c := fakeAHA(t, func(cmd string, params url.Values) (string, int) {
		if cmd == "sethkrtsoll" {
			gotParam = params.Get("param")
			return "OK", http.StatusOK
		}
		return "", http.StatusBadRequest
	})

	err := c.SetHkrTemp(context.Background(), "AIN123", 22.0)
	if err != nil {
		t.Fatalf("SetHkrTemp: %v", err)
	}
	if gotParam != "44" {
		t.Errorf("param = %q, want 44 (22.0*2)", gotParam)
	}
}
