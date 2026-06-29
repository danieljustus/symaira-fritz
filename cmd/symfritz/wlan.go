package main

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/danieljustus/symaira-corekit/exitcodes"
)

func newWLANCmd() *cobra.Command {
	var (
		asJSON   bool
		guestIdx int
	)
	cmd := &cobra.Command{Use: "wlan", Short: "WLAN radios, clients, and guest network"}

	radiosCmd := &cobra.Command{
		Use:   "radios",
		Short: "List WLAN radios (SSID, band, channel, state)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, _, err := newClient()
			if err != nil {
				return err
			}
			radios, err := c.Radios(context.Background(), 3)
			if err != nil {
				return exitcodes.Wrap(err, exitcodes.ExitGeneric, exitcodes.KindUnavailable, "wlan failed")
			}
			if asJSON {
				return printJSON(radios)
			}
			fmt.Printf("%-3s %-24s %-8s %-8s %s\n", "IDX", "SSID", "ENABLED", "CHANNEL", "STANDARD")
			for _, r := range radios {
				fmt.Printf("%-3d %-24s %-8v %-8s %s\n", r.Index, truncate(r.SSID, 24), r.Enabled, r.Channel, r.Standard)
			}
			return nil
		},
	}

	clientsCmd := &cobra.Command{
		Use:   "clients",
		Short: "List devices associated with the WLAN radios",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, _, err := newClient()
			if err != nil {
				return err
			}
			clients, err := c.AllWLANClients(context.Background(), 3)
			if err != nil {
				return exitcodes.Wrap(err, exitcodes.ExitGeneric, exitcodes.KindUnavailable, "wlan clients failed")
			}
			if asJSON {
				return printJSON(clients)
			}
			fmt.Printf("%-3s %-17s %-15s %-7s %s\n", "RAD", "MAC", "IP", "SIGNAL", "SPEED")
			for _, cl := range clients {
				fmt.Printf("%-3d %-17s %-15s %-7s %s\n", cl.RadioIndex, cl.MAC, cl.IP, dashIf(cl.Signal), dashIf(cl.Speed))
			}
			return nil
		},
	}

	guestCmd := &cobra.Command{Use: "guest", Short: "Guest WLAN status/enable/disable"}
	guestStatus := &cobra.Command{
		Use:   "status",
		Short: "Show guest WLAN state",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, _, err := newClient()
			if err != nil {
				return err
			}
			r, err := c.GuestWLANStatus(context.Background(), guestIdx)
			if err != nil {
				return exitcodes.Wrap(err, exitcodes.ExitGeneric, exitcodes.KindUnavailable, "guest status failed")
			}
			if asJSON {
				return printJSON(r)
			}
			fmt.Printf("Guest WLAN (index %d): SSID=%q enabled=%v\n", r.Index, r.SSID, r.Enabled)
			return nil
		},
	}
	guestOn := &cobra.Command{
		Use: "on", Short: "Enable guest WLAN",
		RunE: func(cmd *cobra.Command, _ []string) error { return setGuest(guestIdx, true) },
	}
	guestOff := &cobra.Command{
		Use: "off", Short: "Disable guest WLAN",
		RunE: func(cmd *cobra.Command, _ []string) error { return setGuest(guestIdx, false) },
	}
	guestCmd.AddCommand(guestStatus, guestOn, guestOff)

	cmd.PersistentFlags().BoolVar(&asJSON, "json", false, "Output as JSON")
	cmd.PersistentFlags().IntVar(&guestIdx, "guest-index", 3, "WLANConfiguration index of the guest radio")
	cmd.AddCommand(radiosCmd, clientsCmd, guestCmd)
	return cmd
}

func setGuest(idx int, enable bool) error {
	c, _, err := newClient()
	if err != nil {
		return err
	}
	if err := c.SetGuestWLAN(context.Background(), idx, enable); err != nil {
		return exitcodes.Wrap(err, exitcodes.ExitGeneric, exitcodes.KindUnavailable, "guest toggle failed")
	}
	state := "disabled"
	if enable {
		state = "enabled"
	}
	fmt.Printf("Guest WLAN (index %d) %s.\n", idx, state)
	return nil
}
