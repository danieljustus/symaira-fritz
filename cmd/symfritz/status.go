package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/danieljustus/symaira-corekit/exitcodes"
)

func newStatusCmd() *cobra.Command {
	var (
		asJSON  bool
		showCPU bool
	)
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show a box overview (model, firmware, connection, external IP, CPU temperature)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, _, err := newClient()
			if err != nil {
				return err
			}
			ctx := context.Background()
			st, err := c.Status(ctx)
			if err != nil {
				return exitcodes.Wrap(err, exitcodes.ExitGeneric, exitcodes.KindUnavailable, "status failed")
			}

			var cpuTemps []int
			if showCPU {
				cpuTemps, _ = c.CPUTemperatures(ctx)
			}

			if asJSON {
				type JSONStatus struct {
					ModelName       string `json:"model_name"`
					FirmwareVersion string `json:"firmware_version"`
					ExternalIP      string `json:"external_ip"`
					ConnectionState string `json:"connection_state"`
					Uptime          string `json:"uptime"`
					UpdateAvailable string `json:"update_available,omitempty"`
					CPUTemperatures []int  `json:"cpu_temperatures,omitempty"`
				}
				return printJSON(JSONStatus{
					ModelName:       st.ModelName,
					FirmwareVersion: st.FirmwareVersion,
					ExternalIP:      st.ExternalIP,
					ConnectionState: st.ConnectionState,
					Uptime:          st.Uptime,
					UpdateAvailable: st.UpdateAvailable,
					CPUTemperatures: cpuTemps,
				})
			}

			fmt.Printf("Model:       %s\n", orDash(st.ModelName))
			firmwareStr := orDash(st.FirmwareVersion)
			if st.UpdateAvailable != "" {
				firmwareStr += fmt.Sprintf(" (Update available: %s)", st.UpdateAvailable)
			}
			fmt.Printf("Firmware:    %s\n", firmwareStr)
			fmt.Printf("Connection:  %s\n", orDash(st.ConnectionState))
			fmt.Printf("External IP: %s\n", orDash(st.ExternalIP))
			fmt.Printf("Uptime (s):  %s\n", orDash(st.Uptime))

			if showCPU {
				if len(cpuTemps) > 0 {
					var strTemps []string
					for _, temp := range cpuTemps {
						strTemps = append(strTemps, strconv.Itoa(temp))
					}
					fmt.Printf("CPU Temp:    %s °C\n", strings.Join(strTemps, ", "))
				} else {
					fmt.Println("CPU Temp:    —")
				}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "Output as JSON")
	cmd.Flags().BoolVar(&showCPU, "cpu", false, "Show CPU temperatures (experimental)")
	return cmd
}
