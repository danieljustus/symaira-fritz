package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/danieljustus/symaira-corekit/exitcodes"
	"github.com/spf13/cobra"
)

type outputFormat string

const (
	outputText outputFormat = "text"
	outputJSON outputFormat = "json"
	outputYAML outputFormat = "yaml"
)

// resolveOutputFormat combines the root output flags with a command's legacy
// local --json flag. Local and global --json remain compatible, while a
// conflicting --output value is rejected instead of silently choosing one.
func resolveOutputFormat(cmd *cobra.Command, localJSON bool) (outputFormat, error) {
	format := outputText
	globalJSON := false
	if root := cmd.Root(); root != nil {
		if flag := root.PersistentFlags().Lookup("output"); flag != nil {
			format = outputFormat(strings.ToLower(strings.TrimSpace(flag.Value.String())))
		}
		if flag := root.PersistentFlags().Lookup("json"); flag != nil {
			globalJSON, _ = root.PersistentFlags().GetBool("json")
		}
	}

	switch format {
	case "", outputText:
		format = outputText
	case outputJSON, outputYAML:
	default:
		return "", exitcodes.Wrap(
			fmt.Errorf("unsupported output format %q (want text, json, or yaml)", format),
			exitcodes.ExitConfig,
			exitcodes.KindValidation,
			"invalid output format",
		)
	}

	if globalJSON || localJSON {
		if format != outputText && format != outputJSON {
			return "", exitcodes.Wrap(
				fmt.Errorf("conflicting output formats %q and %q", format, outputJSON),
				exitcodes.ExitConfig,
				exitcodes.KindValidation,
				"conflicting output formats",
			)
		}
		return outputJSON, nil
	}
	return format, nil
}

func printJSON(v any) error {
	return writeOutput(os.Stdout, v, outputJSON)
}

func printOutput(v any, format outputFormat) error {
	return writeOutput(os.Stdout, v, format)
}

func writeOutput(w io.Writer, v any, format outputFormat) error {
	switch format {
	case outputJSON:
		b, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(w, string(b))
		return err
	case outputYAML:
		// Marshal through JSON first so YAML uses the same snake_case field names
		// and omitempty behavior as the existing JSON output.
		jsonBytes, err := json.Marshal(v)
		if err != nil {
			return err
		}
		var normalized any
		if err := json.Unmarshal(jsonBytes, &normalized); err != nil {
			return err
		}
		yamlBytes, err := yaml.Marshal(normalized)
		if err != nil {
			return err
		}
		_, err = w.Write(yamlBytes)
		return err
	default:
		return fmt.Errorf("cannot render structured output as %q", format)
	}
}
