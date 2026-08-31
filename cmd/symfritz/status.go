package main

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/danieljustus/symaira-fritz/internal/fritz"
)

type statusErrorPayload struct {
	Service string `json:"service" yaml:"service"`
	Action  string `json:"action" yaml:"action"`
	Message string `json:"message" yaml:"message"`
	Kind    string `json:"kind,omitempty" yaml:"kind,omitempty"`
	Error   string `json:"error,omitempty" yaml:"error,omitempty"`
}

type statusPayloadDTO struct {
	ModelName       string               `json:"model_name" yaml:"model_name"`
	FirmwareVersion string               `json:"firmware_version" yaml:"firmware_version"`
	ExternalIP      string               `json:"external_ip" yaml:"external_ip"`
	ConnectionState string               `json:"connection_state" yaml:"connection_state"`
	Uptime          string               `json:"uptime" yaml:"uptime"`
	UpdateAvailable string               `json:"update_available,omitempty" yaml:"update_available,omitempty"`
	CPUTemperatures []int                `json:"cpu_temperatures,omitempty" yaml:"cpu_temperatures,omitempty"`
	Partial         bool                 `json:"partial" yaml:"partial"`
	Errors          []statusErrorPayload `json:"errors,omitempty" yaml:"errors,omitempty"`
}

func statusPayload(st *fritz.Status, cpuTemps []int) statusPayloadDTO {
	if st == nil {
		return statusPayloadDTO{CPUTemperatures: cpuTemps}
	}
	var errs []statusErrorPayload
	for _, e := range st.Errors {
		errMsg := e.Message
		if errMsg == "" && e.Err != nil {
			errMsg = e.Err.Error()
		}
		errs = append(errs, statusErrorPayload{
			Service: e.Service,
			Action:  e.Action,
			Message: e.Message,
			Kind:    string(e.Kind),
			Error:   errMsg,
		})
	}
	return statusPayloadDTO{
		ModelName:       st.ModelName,
		FirmwareVersion: st.FirmwareVersion,
		ExternalIP:      st.ExternalIP,
		ConnectionState: st.ConnectionState,
		Uptime:          st.Uptime,
		UpdateAvailable: st.UpdateAvailable,
		CPUTemperatures: cpuTemps,
		Partial:         st.Partial,
		Errors:          errs,
	}
}

func newStatusCmd() *cobra.Command {
	var (
		asJSON  bool
		showCPU bool
	)
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show a box overview (model, firmware, connection, external IP, CPU temperature)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			format, err := resolveOutputFormat(cmd, asJSON)
			if err != nil {
				return err
			}
			return runWithClient(cmd, "status failed", func(ctx context.Context, c *fritz.Client) error {
				st, err := c.Status(ctx)

				isEmpty := st == nil || (st.ModelName == "" && st.FirmwareVersion == "" && st.ExternalIP == "" && st.ConnectionState == "" && st.Uptime == "")

				var finalErr error
				if err != nil {
					finalErr = err
				} else if isEmpty {
					finalErr = errors.New("all status sub-queries failed; check connection and credentials")
				}

				var cpuTemps []int
				if showCPU && finalErr == nil {
					cpuTemps, _ = c.CPUTemperatures(ctx)
				}
				if format != outputText {
					payload := statusPayload(st, cpuTemps)
					printErr := printOutput(payload, format)
					if printErr != nil {
						return printErr
					}
					if finalErr != nil {
						return finalErr
					}
					return nil
				}

				if finalErr != nil {
					return finalErr
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

				if st.Partial {
					fmt.Fprintf(cmd.OutOrStderr(), "\nWarning: %d sub-queries failed:\n", len(st.Errors))
					for _, e := range st.Errors {
						fmt.Fprintf(cmd.OutOrStderr(), "  • %s/%s: %s\n", e.Service, e.Action, e.Message)
					}
				}

				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "Output as JSON")
	cmd.Flags().BoolVar(&showCPU, "cpu", false, "Show CPU temperatures (experimental)")
	return cmd
}
