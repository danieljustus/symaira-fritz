package config

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/danieljustus/symaira-corekit/configkit"
)

const updatePortFixturesEnv = "SYMFRITZ_UPDATE_PORT_FIXTURES"

type portConfigFixture struct {
	SchemaVersion   int                  `json:"schema_version"`
	Oracle          string               `json:"oracle"`
	Defaults        portBoxConfig        `json:"defaults"`
	PathSuffix      string               `json:"path_suffix"`
	ProjectFileName string               `json:"project_file_name"`
	TemplateTOML    string               `json:"template_toml"`
	TimeoutCases    []portTimeoutCase    `json:"timeout_cases"`
	PrecedenceCases []portPrecedenceCase `json:"precedence_cases"`
}

type portBoxConfig struct {
	Host            string `json:"host"`
	User            string `json:"user"`
	Password        string `json:"password"`
	PasswordRef     string `json:"password_ref"`
	Keychain        bool   `json:"keychain"`
	KeychainAccount string `json:"keychain_account"`
	UseTLS          bool   `json:"use_tls"`
	InsecureTLS     bool   `json:"insecure_tls"`
	TimeoutSeconds  int    `json:"timeout_seconds"`
}

type portTimeoutCase struct {
	InputSeconds    int `json:"input_seconds"`
	ExpectedSeconds int `json:"expected_seconds"`
}

type portPrecedenceCase struct {
	ID                 string            `json:"id"`
	GlobalTOML         string            `json:"global_toml,omitempty"`
	ProjectTOML        string            `json:"project_toml,omitempty"`
	Env                map[string]string `json:"env,omitempty"`
	Expected           *portBoxConfig    `json:"expected,omitempty"`
	ExpectedTimeoutSec int               `json:"expected_timeout_sec,omitempty"`
	Error              bool              `json:"error,omitempty"`
}

func TestPortConfigFixture(t *testing.T) {
	fixture := buildPortConfigFixture(t)
	got, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	path := portConfigFixturePath(t)
	if os.Getenv(updatePortFixturesEnv) == "1" {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config fixture: %v (regenerate with make port-fixtures)", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("config fixture drifted; regenerate deliberately with make port-fixtures")
	}
}

func buildPortConfigFixture(t *testing.T) portConfigFixture {
	t.Helper()
	defaults := Defaults()
	timeoutInputs := []int{0, -1, -10, 1, 15, 30, 300}
	timeouts := make([]portTimeoutCase, 0, len(timeoutInputs))
	for _, input := range timeoutInputs {
		timeouts = append(timeouts, portTimeoutCase{
			InputSeconds:    input,
			ExpectedSeconds: int((Box{TimeoutSeconds: input}).Timeout() / time.Second),
		})
	}

	inputs := []portPrecedenceCase{
		{ID: "defaults-only"},
		{ID: "global-file", GlobalTOML: "[box]\nhost=\"global.box\"\nuser=\"global-user\"\ntimeout_seconds=45\n"},
		{ID: "all-fields", GlobalTOML: "[box]\nhost=\"router.home\"\nuser=\"alice\"\npassword=\"plain-value\"\npassword_ref=\"vault.box\"\nkeychain=true\nkeychain_account=\"router-admin\"\nuse_tls=true\ninsecure_tls=true\ntimeout_seconds=20\n"},
		{ID: "project-over-global", GlobalTOML: "[box]\nhost=\"global.box\"\nuser=\"global-user\"\npassword_ref=\"global.ref\"\n", ProjectTOML: "[box]\nhost=\"project.box\"\ntimeout_seconds=30\n"},
		{ID: "file-zero-values-do-not-override", GlobalTOML: "[box]\nuse_tls=false\nkeychain=false\ntimeout_seconds=0\nhost=\"\"\n"},
		{ID: "nested-env", GlobalTOML: "[box]\nhost=\"global.box\"\n", Env: map[string]string{"SYMFRITZ_BOX_HOST": "env.box", "SYMFRITZ_BOX_USER": "env-user", "SYMFRITZ_BOX_USE_TLS": "false", "SYMFRITZ_BOX_INSECURE_TLS": "true", "SYMFRITZ_BOX_TIMEOUT_SECONDS": "90"}},
		{ID: "shorthand-env-last", GlobalTOML: "[box]\nhost=\"global.box\"\nuser=\"global-user\"\n", Env: map[string]string{"SYMFRITZ_BOX_HOST": "nested.box", "SYMFRITZ_BOX_USER": "nested-user", "SYMFRITZ_HOST": "short.box", "SYMFRITZ_USER": "short-user"}},
		{ID: "empty-env-ignored", GlobalTOML: "[box]\nhost=\"global.box\"\n", Env: map[string]string{"SYMFRITZ_BOX_HOST": "", "SYMFRITZ_HOST": ""}},
		{ID: "invalid-env-bool", Env: map[string]string{"SYMFRITZ_BOX_USE_TLS": "nope"}},
		{ID: "invalid-env-int", Env: map[string]string{"SYMFRITZ_BOX_TIMEOUT_SECONDS": "nope"}},
		{ID: "malformed-toml", GlobalTOML: "[box\nhost=\"broken\"\n"},
	}
	cases := make([]portPrecedenceCase, 0, len(inputs))
	for _, input := range inputs {
		box, timeout, err := evaluateConfigCase(t, input.GlobalTOML, input.ProjectTOML, input.Env)
		input.Error = err != nil
		if err == nil {
			converted := toPortBoxConfig(box)
			input.Expected = &converted
			input.ExpectedTimeoutSec = timeout
		}
		cases = append(cases, input)
	}
	return portConfigFixture{
		SchemaVersion:   1,
		Oracle:          "Go internal/config and configkit production functions",
		Defaults:        toPortBoxConfig(defaults.Box),
		PathSuffix:      filepath.Join(".config", "symfritz", "config.toml"),
		ProjectFileName: ".symfritz.toml",
		TemplateTOML:    DefaultConfigTOML(),
		TimeoutCases:    timeouts,
		PrecedenceCases: cases,
	}
}

func evaluateConfigCase(t *testing.T, globalTOML, projectTOML string, env map[string]string) (Box, int, error) {
	t.Helper()
	home, cwd := t.TempDir(), t.TempDir()
	if globalTOML != "" {
		path := filepath.Join(home, ".config", "symfritz", "config.toml")
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(globalTOML), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if projectTOML != "" {
		if err := os.WriteFile(filepath.Join(cwd, ".symfritz.toml"), []byte(projectTOML), 0644); err != nil {
			t.Fatal(err)
		}
	}
	original, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(cwd); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(original) }()
	t.Setenv("HOME", home)
	for _, key := range configEnvKeys() {
		t.Setenv(key, "")
	}
	for key, value := range env {
		t.Setenv(key, value)
	}
	loader := configkit.NewLoader[Config](configkit.Options{AppName: "symfritz", EnvPrefix: "SYMFRITZ"}, Defaults)
	cfg, err := loader.Load()
	if err != nil {
		return Box{}, 0, err
	}
	box := cfg.Box
	if value := os.Getenv("SYMFRITZ_HOST"); value != "" {
		box.Host = value
	}
	if value := os.Getenv("SYMFRITZ_USER"); value != "" {
		box.User = value
	}
	return box, int(box.Timeout() / time.Second), nil
}

func configEnvKeys() []string {
	return []string{"SYMFRITZ_HOST", "SYMFRITZ_USER", "SYMFRITZ_PASSWORD", "SYMFRITZ_BOX_HOST", "SYMFRITZ_BOX_USER", "SYMFRITZ_BOX_PASSWORD", "SYMFRITZ_BOX_PASSWORD_REF", "SYMFRITZ_BOX_KEYCHAIN", "SYMFRITZ_BOX_KEYCHAIN_ACCOUNT", "SYMFRITZ_BOX_USE_TLS", "SYMFRITZ_BOX_INSECURE_TLS", "SYMFRITZ_BOX_TIMEOUT_SECONDS"}
}

func toPortBoxConfig(box Box) portBoxConfig {
	return portBoxConfig(box)
}

func portConfigFixturePath(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve fixture source path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", "..", "testdata", "port", "config", "config-vectors.json"))
}
