package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/danieljustus/symaira-corekit/exitcodes"
	"github.com/danieljustus/symaira-fritz/internal/fritz"
)

func newCallsCmd() *cobra.Command {
	var (
		asJSON  bool
		typeStr string
		days    int
		limit   int
	)
	cmd := &cobra.Command{
		Use:   "calls",
		Short: "Show FRITZ!Box call list",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, _, err := newClient()
			if err != nil {
				return err
			}
			ct, err := parseCallType(typeStr)
			if err != nil {
				return exitcodes.Wrap(err, exitcodes.ExitConfig, exitcodes.KindValidation, "invalid call type")
			}
			calls, err := c.Calls(context.Background(), ct, limit, days)
			if err != nil {
				return exitcodes.Wrap(err, exitcodes.ExitGeneric, exitcodes.KindUnavailable, "calls failed")
			}
			if asJSON {
				return printJSON(calls)
			}
			if len(calls) == 0 {
				fmt.Println("No calls found.")
				return nil
			}

			fmt.Printf("%-18s  %-8s  %-24s  %-16s  %s\n", "DATE", "TYPE", "NAME", "NUMBER", "DURATION")
			for _, call := range calls {
				durStr := "—"
				if call.Duration > 0 {
					durStr = call.Duration.Round(time.Second).String()
				}
				numStr := call.CallerNumber
				if numStr == "" {
					numStr = call.CalledNumber
				}
				fmt.Printf("%-18s  %-8s  %-24s  %-16s  %s\n",
					call.Date.Format("02.01.06 15:04"),
					callTypeStr(call.Type),
					truncate(call.Caller, 24),
					numStr,
					durStr,
				)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "Output as JSON")
	cmd.Flags().StringVar(&typeStr, "type", "all", "Filter by type (incoming, missed, outgoing, rejected, all)")
	cmd.Flags().IntVar(&days, "days", 0, "Limit to calls in the last N days")
	cmd.Flags().IntVar(&limit, "limit", 0, "Limit the number of returned calls")
	return cmd
}

func newDialCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dial <nummer>",
		Short: "Instruct the FRITZ!Box to dial a phone number",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, _, err := newClient()
			if err != nil {
				return err
			}
			if err := c.Dial(context.Background(), args[0]); err != nil {
				return exitcodes.Wrap(err, exitcodes.ExitGeneric, exitcodes.KindUnavailable, "dial failed")
			}
			fmt.Printf("Dialing %s...\n", args[0])
			return nil
		},
	}
	return cmd
}

func newHangupCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "hangup",
		Short: "Hang up any active call initiated by dial",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, _, err := newClient()
			if err != nil {
				return err
			}
			if err := c.Hangup(context.Background()); err != nil {
				return exitcodes.Wrap(err, exitcodes.ExitGeneric, exitcodes.KindUnavailable, "hangup failed")
			}
			fmt.Println("Hanging up...")
			return nil
		},
	}
	return cmd
}

func parseCallType(s string) (fritz.CallType, error) {
	switch strings.ToLower(s) {
	case "incoming":
		return fritz.CallIncoming, nil
	case "missed":
		return fritz.CallMissed, nil
	case "outgoing":
		return fritz.CallOutgoing, nil
	case "rejected":
		return fritz.CallRejected, nil
	case "all":
		return fritz.CallAll, nil
	default:
		return 0, fmt.Errorf("unknown call type: %s", s)
	}
}

func callTypeStr(ct fritz.CallType) string {
	switch ct {
	case fritz.CallIncoming:
		return "incoming"
	case fritz.CallMissed:
		return "missed"
	case fritz.CallOutgoing:
		return "outgoing"
	case fritz.CallRejected:
		return "rejected"
	default:
		return "unknown"
	}
}
