package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/danieljustus/symaira-corekit/exitcodes"
	"github.com/danieljustus/symaira-fritz/internal/config"
)

func newConfigCmd() *cobra.Command {
	cfg := &cobra.Command{Use: "config", Short: "Manage symfritz configuration"}

	initCmd := &cobra.Command{
		Use:          "init",
		Short:        "Write default config to ~/.config/symfritz/config.toml",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			home, err := os.UserHomeDir()
			if err != nil {
				return exitcodes.Wrap(err, exitcodes.ExitConfig, exitcodes.KindConfig, "cannot determine home directory")
			}
			dir := home + "/.config/symfritz"
			if err := os.MkdirAll(dir, 0755); err != nil {
				return exitcodes.Wrap(err, exitcodes.ExitConfig, exitcodes.KindConfig, "cannot create config directory")
			}
			path := dir + "/config.toml"
			force, _ := cmd.Flags().GetBool("force")
			if _, err := os.Stat(path); err == nil && !force {
				fmt.Fprintf(os.Stderr, "config already exists at %s (use --force to overwrite)\n", path)
				return nil
			}
			if err := os.WriteFile(path, []byte(config.DefaultConfigTOML()), 0600); err != nil {
				return exitcodes.Wrap(err, exitcodes.ExitConfig, exitcodes.KindConfig, "cannot write config file")
			}
			fmt.Printf("Config written to %s\n", path)
			return nil
		},
	}
	initCmd.Flags().Bool("force", false, "overwrite existing config file")
	cfg.AddCommand(initCmd, newDetectCmd())
	return cfg
}
