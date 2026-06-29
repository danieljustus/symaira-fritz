package mcp

import (
	"context"
	"testing"

	"github.com/danieljustus/symaira-fritz/internal/fritz"
)

func TestStartServer_RequiresStdin(t *testing.T) {
	c := fritz.New("fritz.box")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately so ServeStdio fails

	err := StartServer(ctx, c)
	if err == nil {
		t.Error("expected error when context is cancelled, got nil")
	}
}
