package main

import "testing"

func TestNewAuthCmd(t *testing.T) {
	cmd := newAuthCmd()

	if cmd.Use != "auth" {
		t.Errorf("Use = %q, want %q", cmd.Use, "auth")
	}
	if cmd.Short == "" {
		t.Error("Short should not be empty")
	}

	subNames := make(map[string]bool)
	for _, sub := range cmd.Commands() {
		subNames[sub.Use] = true
	}

	for _, want := range []string{"test", "login", "store"} {
		if !subNames[want] {
			t.Errorf("missing subcommand %q, got: %v", want, cmd.Commands())
		}
	}

	if len(cmd.Commands()) != 3 {
		t.Errorf("expected 3 subcommands, got %d", len(cmd.Commands()))
	}
}
