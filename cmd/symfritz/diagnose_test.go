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
	if len(cmd.Aliases) == 0 || cmd.Aliases[0] != "doctor" {
		t.Errorf("expected alias 'doctor', got %v", cmd.Aliases)
	}

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

	jsonFlag := cmd.Flags().Lookup("json")
	if jsonFlag == nil {
		t.Error("missing --json flag")
	}
	portFlag := cmd.Flags().Lookup("port")
	if portFlag == nil {
		t.Error("missing --port flag")
	}
}

func TestNewDiagnoseRouterCmd(t *testing.T) {
	cmd := newDiagnoseCmd()
	routerCmd, _, err := cmd.Find([]string{"router"})
	if err != nil {
		t.Fatalf("router subcommand not found: %v", err)
	}

	if routerCmd.Use != "router" {
		t.Errorf("Use = %q, want %q", routerCmd.Use, "router")
	}
	if routerCmd.Short == "" {
		t.Error("Short should not be empty")
	}
	if routerCmd.Long == "" {
		t.Error("Long should not be empty")
	}

	jsonFlag := routerCmd.Flags().Lookup("json")
	if jsonFlag == nil {
		t.Error("router: missing --json flag")
	}
	portFlag := routerCmd.Flags().Lookup("port")
	if portFlag == nil {
		t.Error("router: missing --port flag")
	}
}
