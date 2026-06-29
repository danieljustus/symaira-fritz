package main

import "testing"

func TestNewDiagnoseCmd(t *testing.T) {
	cmd := newDiagnoseCmd()

	if cmd.Use != "diagnose <host>" {
		t.Errorf("Use = %q, want %q", cmd.Use, "diagnose <host>")
	}
	if cmd.Short == "" {
		t.Error("Short should not be empty")
	}
	if cmd.Aliases == nil || len(cmd.Aliases) == 0 || cmd.Aliases[0] != "doctor" {
		t.Errorf("expected alias 'doctor', got %v", cmd.Aliases)
	}

	// Check that Args validation exists (ExactArgs(1))
	if cmd.Args == nil {
		t.Fatal("Args should not be nil")
	}
	err := cmd.Args(cmd, []string{})
	if err == nil {
		t.Error("Expected error for no args")
	}
	err = cmd.Args(cmd, []string{"a", "b"})
	if err == nil {
		t.Error("Expected error for too many args")
	}
	err = cmd.Args(cmd, []string{"host"})
	if err != nil {
		t.Errorf("Expected no error for 1 arg, got: %v", err)
	}

	// Check flags
	jsonFlag := cmd.Flags().Lookup("json")
	if jsonFlag == nil {
		t.Error("missing --json flag")
	}
	portFlag := cmd.Flags().Lookup("port")
	if portFlag == nil {
		t.Error("missing --port flag")
	}
}
