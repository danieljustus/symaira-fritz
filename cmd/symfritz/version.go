package main

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/danieljustus/symaira-corekit/updatecheck"
)

func newVersionCmd() *cobra.Command {
	var check bool
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print version",
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Println("symfritz", version)
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
	return cmd
}
