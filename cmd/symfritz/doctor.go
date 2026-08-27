package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/danieljustus/symaira-corekit/exitcodes"
	"github.com/danieljustus/symaira-fritz/internal/config"
	"github.com/danieljustus/symaira-fritz/internal/fritz"
	"github.com/danieljustus/symaira-fritz/internal/secret"
)

type doctorCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

type doctorReport struct {
	ConfigPath string        `json:"config_path"`
	Host       string        `json:"host"`
	Checks     []doctorCheck `json:"checks"`
	Healthy    bool          `json:"healthy"`
}

func newDoctorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Check symfritz configuration, credentials, and box connectivity",
		Long: `Check the local symfritz setup and its FRITZ!Box connection.

The command verifies the global config file, credential resolution, TR-064
service discovery, and session login. Smart-home availability is probed when
the authenticated AHA endpoint reports actors.`,
		RunE: runDoctor,
	}
}

func runDoctor(cmd *cobra.Command, _ []string) error {
	format, err := resolveOutputFormat(cmd, false)
	if err != nil {
		return err
	}

	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	report := doctorReport{
		ConfigPath: config.DefaultPath(),
		Healthy:    true,
	}
	addCheck := func(name, status, detail string) {
		report.Checks = append(report.Checks, doctorCheck{Name: name, Status: status, Detail: detail})
		if status == "fail" {
			report.Healthy = false
		}
	}

	fileOK := true
	info, statErr := os.Stat(report.ConfigPath)
	switch {
	case errors.Is(statErr, os.ErrNotExist):
		fileOK = false
		addCheck("config file", "fail", "not found; run 'symfritz config init'")
	case statErr != nil:
		fileOK = false
		addCheck("config file", "fail", "cannot inspect configuration file")
	case info.IsDir():
		fileOK = false
		addCheck("config file", "fail", "path is a directory")
	default:
		addCheck("config file", "ok", report.ConfigPath)
	}

	cfg, configErr := config.Reload()
	if configErr != nil {
		addCheck("config parse", "fail", "configuration is not parseable")
		cfg = config.Defaults()
	} else if fileOK {
		addCheck("config parse", "ok", "configuration is valid")
	} else {
		addCheck("config parse", "skip", "not checked because the config file is missing")
	}

	box := cfg.Box
	if env := os.Getenv("SYMFRITZ_HOST"); env != "" {
		box.Host = env
	}
	if env := os.Getenv("SYMFRITZ_USER"); env != "" {
		box.User = env
	}
	report.Host = box.Host

	credential, credentialErr := secret.Resolve(ctx, secretOptions(box))
	credentialOK := credentialErr == nil && credential.Source != secret.SourceNone && credential.Password != ""
	switch {
	case credentialErr != nil:
		addCheck("credentials", "fail", "credential resolution failed")
	case !credentialOK:
		addCheck("credentials", "fail", "no credential resolved; run 'symfritz auth login'")
	default:
		addCheck("credentials", "ok", fmt.Sprintf("resolved from %s", credential.Source))
	}

	var client *fritz.Client
	if credentialOK {
		client = newClientFor(box, credential.Password)
	}

	discoveryOK := false
	sessionOK := false
	if client == nil {
		addCheck("box reachable", "skip", "requires resolved credentials")
		addCheck("TR-064 enabled", "skip", "requires a reachable box")
		addCheck("session login", "skip", "requires resolved credentials")
	} else {
		services, discoverErr := client.Discover(ctx)
		if discoverErr != nil {
			addCheck("box reachable", "fail", "TR-064 discovery request failed")
			addCheck("TR-064 enabled", "fail", "service description unavailable")
		} else {
			discoveryOK = true
			addCheck("box reachable", "ok", "TR-064 service description responded")
			if len(services) == 0 {
				addCheck("TR-064 enabled", "fail", "no services advertised")
			} else {
				addCheck("TR-064 enabled", "ok", fmt.Sprintf("%d service(s) advertised", len(services)))
			}
		}

		if _, sessionErr := client.SID(ctx); sessionErr != nil {
			addCheck("session login", "fail", "FRITZ!Box session login failed")
		} else {
			sessionOK = true
			addCheck("session login", "ok", "session established")
		}
	}

	if discoveryOK && sessionOK {
		devices, ahaErr := client.Devices(ctx)
		switch {
		case ahaErr != nil:
			addCheck("AHA endpoint", "skip", "no smart-home actors configured or endpoint unavailable")
		case len(devices) == 0:
			addCheck("AHA endpoint", "skip", "no smart-home actors reported")
		default:
			addCheck("AHA endpoint", "ok", fmt.Sprintf("%d actor(s) reachable", len(devices)))
		}
	} else {
		addCheck("AHA endpoint", "skip", "requires a reachable box and successful session login")
	}

	if format == outputText {
		if err := writeDoctorText(cmd.OutOrStdout(), report); err != nil {
			return err
		}
	} else if err := writeOutput(cmd.OutOrStdout(), report, format); err != nil {
		return err
	}

	if !report.Healthy {
		return exitcodes.Wrap(errors.New("one or more checks failed"), exitcodes.ExitGeneric, exitcodes.KindUnavailable, "doctor found failing checks")
	}
	return nil
}

func writeDoctorText(w interface{ Write([]byte) (int, error) }, report doctorReport) error {
	if _, err := fmt.Fprintf(w, "symfritz doctor (%s)\n", report.Host); err != nil {
		return err
	}
	for _, check := range report.Checks {
		glyph := "·"
		switch check.Status {
		case "ok":
			glyph = "✓"
		case "fail":
			glyph = "✗"
		}
		if _, err := fmt.Fprintf(w, "  %s %-18s %s\n", glyph, check.Name, check.Detail); err != nil {
			return err
		}
	}
	result := "healthy"
	if !report.Healthy {
		result = "problems detected"
	}
	_, err := fmt.Fprintf(w, "\nResult: %s\n", result)
	return err
}
