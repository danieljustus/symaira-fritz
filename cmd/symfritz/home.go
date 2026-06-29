package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/danieljustus/symaira-corekit/exitcodes"
)

func newHomeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "home",
		Short: "DECT smart-home actors (switches, thermostats)",
	}

	var listJSON bool
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List DECT actors with AIN, name, and state",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, _, err := newClient()
			if err != nil {
				return err
			}
			devs, err := c.Devices(context.Background())
			if err != nil {
				return exitcodes.Wrap(err, exitcodes.ExitGeneric, exitcodes.KindUnavailable, "device list failed")
			}
			if listJSON {
				return printJSON(devs)
			}
			if len(devs) == 0 {
				fmt.Println("No DECT smart-home actors found.")
				return nil
			}
			for _, d := range devs {
				state := "n/a"
				if d.Switch.State == "1" {
					state = "on"
				} else if d.Switch.State == "0" {
					state = "off"
				}
				present := "offline"
				if d.Present == 1 {
					present = "online"
				}
				fmt.Printf("%-16s  %-20s  %-8s  %s\n", d.Identifier, d.Name, state, present)
			}
			return nil
		},
	}

	switchCmd := &cobra.Command{
		Use:   "switch <ain> <on|off>",
		Short: "Turn a switch actor on or off",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, _, err := newClient()
			if err != nil {
				return err
			}
			ctx := context.Background()
			switch strings.ToLower(args[1]) {
			case "on":
				err = c.SwitchOn(ctx, args[0])
			case "off":
				err = c.SwitchOff(ctx, args[0])
			default:
				return exitcodes.Wrap(fmt.Errorf("state must be on or off"),
					exitcodes.ExitConfig, exitcodes.KindValidation, "bad state")
			}
			if err != nil {
				return exitcodes.Wrap(err, exitcodes.ExitGeneric, exitcodes.KindUnavailable, "switch failed")
			}
			fmt.Printf("OK: %s -> %s\n", args[0], strings.ToLower(args[1]))
			return nil
		},
	}

	tempCmd := &cobra.Command{
		Use:   "temp <ain> <celsius|on|off>",
		Short: "Set the target temperature for a thermostat",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, _, err := newClient()
			if err != nil {
				return err
			}
			ctx := context.Background()
			var temp float64
			switch strings.ToLower(args[1]) {
			case "on":
				temp = 254
			case "off":
				temp = 253
			default:
				var parseErr error
				temp, parseErr = strconv.ParseFloat(args[1], 64)
				if parseErr != nil {
					return exitcodes.Wrap(fmt.Errorf("temperature must be 'on', 'off', or a number (e.g. 20.5)"),
						exitcodes.ExitConfig, exitcodes.KindValidation, "bad temperature")
				}
			}
			if err := c.SetHkrTemp(ctx, args[0], temp); err != nil {
				return exitcodes.Wrap(err, exitcodes.ExitGeneric, exitcodes.KindUnavailable, "set temp failed")
			}
			fmt.Printf("OK: %s -> %s\n", args[0], args[1])
			return nil
		},
	}

	listCmd.Flags().BoolVar(&listJSON, "json", false, "Output as JSON")
	cmd.AddCommand(listCmd, switchCmd, tempCmd)
	return cmd
}
