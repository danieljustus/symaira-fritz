package main

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/danieljustus/symaira-corekit/updatecheck"
	"github.com/danieljustus/symaira-corekit/versionkit"
)

func newVersionCmd() *cobra.Command {
	var check bool
	var flagJSON bool
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print version",
		RunE: func(cmd *cobra.Command, _ []string) error {
			info := versionkit.New("symfritz", version, 1)
			if flagJSON {
				return info.Write(cmd.OutOrStdout())
			}
			fmt.Fprintln(cmd.OutOrStdout(), info.String())
			if check {
				checker := updatecheck.NewChecker("danieljustus", "symaira-fritz")
				release, err := checker.Check(context.Background(), version)
				if err != nil {
					fmt.Fprintf(os.Stderr, "update check failed: %v\n", err)
					return nil
				}
				if release != nil {
					fmt.Printf("Update available: %s\nDownload: %s\n", release.TagName, release.HTMLURL)
				} else {
					fmt.Println("Already up to date.")
				}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&check, "check", false, "Check for updates on GitHub")
	cmd.Flags().BoolVar(&flagJSON, "json", false, "Emit version as machine-readable JSON")
	return cmd
}
