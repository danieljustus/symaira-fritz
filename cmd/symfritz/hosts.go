package main

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/danieljustus/symaira-corekit/exitcodes"
	"github.com/danieljustus/symaira-fritz/internal/fritz"
)

func newHostsCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "hosts",
		Short: "FRITZ!Box host table (LAN/WLAN devices)",
	}

	printHosts := func(hosts []fritz.Host) error {
		if asJSON {
			return printJSON(hosts)
		}
		if len(hosts) == 0 {
			fmt.Println("No hosts found.")
			return nil
		}
		fmt.Printf("%-24s %-15s %-17s %-6s %-5s %s\n", "NAME", "IP", "MAC", "STATE", "LINK", "SOURCE")
		for _, h := range hosts {
			state := "down"
			if h.Active {
				state = "up"
			}
			fmt.Printf("%-24s %-15s %-17s %-6s %-5s %s\n",
				truncate(h.Name, 24), h.IP, h.MAC, state, h.Link(), h.AddressSource)
		}
		return nil
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List all known hosts",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, _, err := newClient()
			if err != nil {
				return err
			}
			hosts, err := c.Hosts(context.Background())
			if err != nil {
				return exitcodes.Wrap(err, exitcodes.ExitGeneric, exitcodes.KindUnavailable, "hosts failed")
			}
			return printHosts(hosts)
		},
	}

	activeCmd := &cobra.Command{
		Use:   "active",
		Short: "List only currently active hosts",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, _, err := newClient()
			if err != nil {
				return err
			}
			hosts, err := c.ActiveHosts(context.Background())
			if err != nil {
				return exitcodes.Wrap(err, exitcodes.ExitGeneric, exitcodes.KindUnavailable, "hosts failed")
			}
			return printHosts(hosts)
		},
	}

	var byMAC, byIP string
	getCmd := &cobra.Command{
		Use:   "get [name]",
		Short: "Show one host by name, --mac, or --ip",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, _, err := newClient()
			if err != nil {
				return err
			}
			ctx := context.Background()
			var host *fritz.Host
			switch {
			case byMAC != "":
				host, err = c.HostByMAC(ctx, byMAC)
			case byIP != "":
				host, err = c.HostByIP(ctx, byIP)
			case len(args) == 1:
				host, err = c.ResolveHost(ctx, args[0])
			default:
				return exitcodes.Wrap(fmt.Errorf("provide a name argument or --mac/--ip"),
					exitcodes.ExitConfig, exitcodes.KindValidation, "missing host reference")
			}
			if err != nil {
				return exitcodes.Wrap(err, exitcodes.ExitNotFound, exitcodes.KindNotFound, "host lookup failed")
			}
			if asJSON {
				return printJSON(host)
			}
			fmt.Printf("Name:    %s\n", orDash(host.Name))
			fmt.Printf("IP:      %s\n", orDash(host.IP))
			fmt.Printf("MAC:     %s\n", orDash(host.MAC))
			fmt.Printf("Active:  %v\n", host.Active)
			fmt.Printf("Link:    %s\n", host.Link())
			fmt.Printf("Source:  %s\n", orDash(host.AddressSource))
			fmt.Printf("Lease:   %ds\n", host.LeaseTimeRemaining)
			return nil
		},
	}
	getCmd.Flags().StringVar(&byMAC, "mac", "", "Look up by MAC address")
	getCmd.Flags().StringVar(&byIP, "ip", "", "Look up by IP address")

	cmd.PersistentFlags().BoolVar(&asJSON, "json", false, "Output as JSON")
	cmd.AddCommand(listCmd, activeCmd, getCmd)
	return cmd
}
