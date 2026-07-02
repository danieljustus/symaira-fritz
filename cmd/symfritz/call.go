package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/danieljustus/symaira-corekit/exitcodes"
	"github.com/danieljustus/symaira-fritz/internal/fritz"
)

// newCallCmd is the power-user escape hatch: raw TR-064 action invocation.
func newCallCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "call <service> <action> [Key=Value ...]",
		Short: "Invoke a raw TR-064 action (power user)",
		Long: `Invoke any TR-064 action by service shortcut and action name.

Known shortcuts: deviceinfo, wanip, wanppp, wancommon, hosts, wlan1. Any other service
name is resolved via tr64desc.xml discovery (e.g. "WLANConfiguration:2").
Arguments are passed as Key=Value pairs (TR-064 input arguments).

Examples:
  symfritz call deviceinfo GetInfo
  symfritz call wanip GetExternalIPAddress
  symfritz call hosts GetGenericHostEntry NewIndex=0`,
		Args: cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			action := args[1]
			in := map[string]string{}
			for _, kv := range args[2:] {
				k, v, found := strings.Cut(kv, "=")
				if !found {
					return exitcodes.Wrap(fmt.Errorf("argument %q is not Key=Value", kv),
						exitcodes.ExitConfig, exitcodes.KindValidation, "bad argument")
				}
				in[k] = v
			}
			c, _, err := newClient()
			if err != nil {
				return err
			}
			ctx := context.Background()
			svc, ok := serviceByShortcut(args[0])
			if !ok {
				// Fall back to tr64desc.xml discovery for any advertised service.
				svc, err = c.ServiceByName(ctx, args[0])
				if err != nil {
					return exitcodes.Wrap(
						fmt.Errorf("unknown service %q: %w (known shortcuts: deviceinfo, wanip, wancommon, hosts, wlan1)", args[0], err),
						exitcodes.ExitConfig, exitcodes.KindValidation, "bad service")
				}
			}
			out, err := c.Call(ctx, svc, action, in)
			if err != nil {
				return exitcodes.Wrap(err, exitcodes.ExitGeneric, exitcodes.KindUnavailable, "tr064 call failed")
			}
			return printJSON(out)
		},
	}
	return cmd
}

func serviceByShortcut(name string) (fritz.Service, bool) {
	switch strings.ToLower(name) {
	case "deviceinfo":
		return fritz.ServiceDeviceInfo, true
	case "wanip":
		return fritz.ServiceWANIPConnection, true
	case "wanppp":
		return fritz.ServiceWANPPPConnection, true
	case "wancommon":
		return fritz.ServiceWANCommonIFC, true
	case "hosts":
		return fritz.ServiceHosts, true
	case "wlan1":
		return fritz.ServiceWLANConfig1, true
	default:
		return fritz.Service{}, false
	}
}
