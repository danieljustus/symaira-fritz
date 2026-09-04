package main

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/danieljustus/symaira-fritz/internal/config"
	"github.com/danieljustus/symaira-fritz/internal/fritz"
)

// runWithClient resolves the fritz.Client once, propagates the command's
// context (which carries signal-based cancellation from main), and funnels
// the returned error through wrapFritzError for consistent exit codes.
//
// This eliminates the 25-site preamble pattern documented in Issue #125:
//
//	c, _, err := newClient()
//	if err != nil { return err }
//	ctx := context.Background()
//	... err != nil { return err }  // hand-picked wrapper
//
// Commands that do not build a client (config init, version, gendocs) are
// intentionally excluded.
func runWithClient(cmd *cobra.Command, msg string, fn func(ctx context.Context, c *fritz.Client) error) error {
	return runWithClientAndConfig(cmd, msg, func(ctx context.Context, c *fritz.Client, _ *config.Config) error {
		return fn(ctx, c)
	})
}

// runWithClientAndConfig is like runWithClient but provides both the fritz.Client
// and the loaded config.Config to commands requiring both.
func runWithClientAndConfig(cmd *cobra.Command, msg string, fn func(ctx context.Context, c *fritz.Client, cfg *config.Config) error) error {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	c, cfg, err := newClient(ctx)
	if err != nil {
		return err
	}
	if err := fn(ctx, c, cfg); err != nil {
		return wrapFritzError(err, msg)
	}
	return nil
}

// ExitCanceled is the distinct exit code for a user-interrupted (Ctrl-C/SIGTERM)
// run. It is separate from ExitGeneric so callers can distinguish a clean abort
// from a real failure.
const ExitCanceled = 130
