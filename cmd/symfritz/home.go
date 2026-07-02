package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/danieljustus/symaira-corekit/exitcodes"
	"github.com/danieljustus/symaira-fritz/internal/fritz"
)

func newHomeCmd() *cobra.Command {
	var (
		useTR064 bool
	)

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
			ctx := context.Background()

			if useTR064 {
				devs, err := c.HomeautoDevices(ctx)
				if err != nil {
					return wrapFritzError(err, "device list failed")
				}
				if listJSON {
					return printJSON(devs)
				}
				if len(devs) == 0 {
					fmt.Println("No TR-064 smart-home devices found.")
					return nil
				}
				fmt.Printf("%-16s  %-24s  %-16s  %s\n", "AIN", "PRODUCT NAME", "MANUFACTURER", "VERSION")
				for _, d := range devs {
					fmt.Printf("%-16s  %-24s  %-16s  %s\n", d.AIN, truncate(d.ProductName, 24), truncate(d.Manufacturer, 16), d.FirmwareVersion)
				}
				return nil
			}

			devs, err := c.Devices(ctx)
			if err != nil {
				return wrapFritzError(err, "device list failed")
			}
			groups, err := c.Groups(ctx)
			if err != nil {
				groups = nil
			}

			if listJSON {
				type Combined struct {
					Devices []fritz.Device `json:"devices"`
					Groups  []fritz.Group  `json:"groups"`
				}
				return printJSON(Combined{Devices: devs, Groups: groups})
			}

			if len(devs) == 0 && len(groups) == 0 {
				fmt.Println("No DECT smart-home actors found.")
				return nil
			}

			if len(devs) > 0 {
				fmt.Println("Devices:")
				fmt.Printf("%-16s  %-20s  %-8s  %-8s  %s\n", "AIN", "NAME", "STATE", "PRESENT", "INFO")
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

					var extra []string
					if d.Hkr.Tsoll != "" {
						tsollVal := parseHkrTemp(d.Hkr.Tsoll)
						tistVal := parseHkrTemp(d.Hkr.Tist)
						extra = append(extra, fmt.Sprintf("temp: %s°C (soll %s°C)", tistVal, tsollVal))
						if d.Hkr.BatteryCharge != "" {
							extra = append(extra, fmt.Sprintf("bat: %s%%", d.Hkr.BatteryCharge))
						}
						if d.Hkr.WindowOpen == "1" {
							extra = append(extra, "window: open")
						}
						if d.Hkr.ErrorCode != "0" && d.Hkr.ErrorCode != "" {
							desc := fritz.HkrErrorDescriptions[d.Hkr.ErrorCode]
							if desc == "" {
								desc = "Fehler " + d.Hkr.ErrorCode
							}
							extra = append(extra, desc)
						}
					}
					if d.PowerMeter.Power != "" {
						powerW := float64(parseInt(d.PowerMeter.Power)) / 1000.0
						energyWh := float64(parseInt(d.PowerMeter.Energy))
						extra = append(extra, fmt.Sprintf("power: %.2fW (total %.1fWh)", powerW, energyWh))
					}

					extraStr := ""
					if len(extra) > 0 {
						extraStr = "(" + strings.Join(extra, ", ") + ")"
					}

					fmt.Printf("%-16s  %-20s  %-8s  %-8s  %s\n", d.Identifier, truncate(d.Name, 20), state, present, extraStr)
				}
			}

			if len(groups) > 0 {
				fmt.Println("\nGroups:")
				fmt.Printf("%-16s  %-20s  %s\n", "AIN", "NAME", "MEMBERS")
				for _, g := range groups {
					fmt.Printf("%-16s  %-20s  %s\n", g.Identifier, truncate(g.Name, 20), strings.Join(g.Members, ", "))
				}
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
			var on bool
			switch strings.ToLower(args[1]) {
			case "on":
				on = true
			case "off":
				on = false
			default:
				return exitcodes.Wrap(fmt.Errorf("state must be on or off"),
					exitcodes.ExitConfig, exitcodes.KindValidation, "bad state")
			}

			if useTR064 {
				err = c.HomeautoSwitch(ctx, args[0], on)
			} else {
				if on {
					err = c.SwitchOn(ctx, args[0])
				} else {
					err = c.SwitchOff(ctx, args[0])
				}
			}

			if err != nil {
				return wrapFritzError(err, "switch failed")
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
				return wrapFritzError(err, "set temp failed")
			}
			fmt.Printf("OK: %s -> %s\n", args[0], args[1])
			return nil
		},
	}

	listCmd.Flags().BoolVar(&listJSON, "json", false, "Output as JSON")
	listCmd.Flags().BoolVar(&useTR064, "tr064", false, "Use TR-064 Homeauto API")
	switchCmd.Flags().BoolVar(&useTR064, "tr064", false, "Use TR-064 Homeauto API")

	cmd.AddCommand(listCmd, switchCmd, tempCmd)
	return cmd
}

func parseHkrTemp(s string) string {
	val, err := strconv.Atoi(s)
	if err != nil {
		return "—"
	}
	if val == 254 {
		return "ON"
	}
	if val == 253 {
		return "OFF"
	}
	return fmt.Sprintf("%.1f", float64(val)/2.0)
}

func parseInt(s string) int {
	v, _ := strconv.Atoi(s)
	return v
}
