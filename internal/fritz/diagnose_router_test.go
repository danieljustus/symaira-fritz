package fritz

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestProbePort_OptionalFailureIsWarning(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}

	result := probePort(context.Background(), "127.0.0.1", PortProbe{
		Port:     port,
		Label:    "optional",
		Optional: true,
	}, time.Second)
	if result.status != StatusWarn {
		t.Errorf("optional probe status = %q, want %q", result.status, StatusWarn)
	}
	if result.detail != "closed or filtered" {
		t.Errorf("optional probe detail = %q, want closed or filtered", result.detail)
	}
}
