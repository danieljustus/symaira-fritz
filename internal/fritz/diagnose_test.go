package fritz

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestDiagnose_PortProbes(t *testing.T) {
	// Open a listener so one probe succeeds.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	openPort := ln.Addr().(*net.TCPAddr).Port

	// Point the client's TR-064 base at an address that refuses instantly so the
	// host-table lookup fails fast (we only care about the port probes here).
	c := New("fritz.box", WithTimeout(500*time.Millisecond))
	c.tr064BaseURL = "http://127.0.0.1:1"

	d := c.Diagnose(context.Background(), "127.0.0.1", DiagnoseOptions{
		Ports: []PortProbe{
			{Port: openPort, Label: "open"},
			{Port: 1, Label: "closed"},
		},
		DialTimeout: 500 * time.Millisecond,
	})

	if d.Target != "127.0.0.1" {
		t.Errorf("target = %q, want 127.0.0.1", d.Target)
	}

	var open, closed *Check
	for i := range d.Checks {
		switch d.Checks[i].Name {
		case "TCP " + itoa(openPort) + " (open)":
			open = &d.Checks[i]
		case "TCP 1 (closed)":
			closed = &d.Checks[i]
		}
	}
	if open == nil || open.Status != StatusOK {
		t.Errorf("open port check = %+v", open)
	}
	if closed == nil || closed.Status != StatusFail {
		t.Errorf("closed port check = %+v", closed)
	}
	// A failing check must flip OK to false.
	if d.OK {
		t.Error("diagnosis OK should be false when a port is closed")
	}
}

func TestDialTCP_OpenAndClosed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	if !dialTCP(context.Background(), "127.0.0.1", port, time.Second) {
		t.Error("expected open port to dial")
	}
	if dialTCP(context.Background(), "127.0.0.1", 1, 500*time.Millisecond) {
		t.Error("expected closed port to fail")
	}
}

// itoa avoids importing strconv just for the test labels.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [12]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
