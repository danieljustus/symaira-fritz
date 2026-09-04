package secret

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

const updatePortFixturesEnv = "SYMFRITZ_UPDATE_PORT_FIXTURES"

type portSecretFixture struct {
	SchemaVersion       int                      `json:"schema_version"`
	Oracle              string                   `json:"oracle"`
	CredentialCases     []portCredentialCase     `json:"credential_cases"`
	SubprocessContracts []portSubprocessContract `json:"subprocess_contracts"`
}

type portCredentialCase struct {
	ID               string `json:"id"`
	Description      string `json:"description"`
	EnvPassword      string `json:"env_password,omitempty"`
	Ref              string `json:"ref,omitempty"`
	Keychain         bool   `json:"keychain"`
	KeychainAccount  string `json:"keychain_account,omitempty"`
	Plaintext        string `json:"plaintext,omitempty"`
	MockVaultPass    string `json:"mock_vault_pass,omitempty"`
	MockVaultErr     string `json:"mock_vault_err,omitempty"`
	MockKeychainPass string `json:"mock_keychain_pass,omitempty"`
	MockKeychainErr  string `json:"mock_keychain_err,omitempty"`
	ExpectedPass     string `json:"expected_pass"`
	ExpectedSource   string `json:"expected_source"`
	ExpectedError    string `json:"expected_error,omitempty"`
}

type portSubprocessContract struct {
	ID                  string   `json:"id"`
	Description         string   `json:"description"`
	Executable          string   `json:"executable"`
	Args                []string `json:"args"`
	StdinPayload        string   `json:"stdin_payload"`
	ExposesSecretInArgv bool     `json:"exposes_secret_in_argv"`
}

func TestPortSecretFixture(t *testing.T) {
	fixture := buildPortSecretFixture(t)
	got, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')

	path := portSecretFixturePath(t)
	if os.Getenv(updatePortFixturesEnv) == "1" {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0644); err != nil {
			t.Fatal(err)
		}
		t.Logf("updated %s", path)
		return
	}

	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read secret fixture: %v (regenerate with make port-fixtures)", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("secret fixture drifted; regenerate deliberately with make port-fixtures")
	}
}

func buildPortSecretFixture(t *testing.T) portSecretFixture {
	t.Helper()

	cases := []struct {
		id              string
		desc            string
		envPass         string
		ref             string
		keychain        bool
		keychainAccount string
		plaintext       string
		mockVaultPass   string
		mockVaultErr    string
		mockKCPass      string
		mockKCErr       string
	}{
		{
			id:              "env-wins-over-all",
			desc:            "SYMFRITZ_PASSWORD environment variable takes precedence over symvault, keychain, and config",
			envPass:         "from-env-secret",
			ref:             "fritz.password",
			keychain:        true,
			keychainAccount: "fritz.box",
			plaintext:       "from-plaintext",
			mockVaultPass:   "from-vault",
			mockKCPass:      "from-keychain",
		},
		{
			id:              "symvault-wins-over-keychain-and-plaintext",
			desc:            "password_ref takes precedence over keychain and plaintext",
			ref:             "fritz.password",
			keychain:        true,
			keychainAccount: "fritz.box",
			plaintext:       "from-plaintext",
			mockVaultPass:   "from-vault",
			mockKCPass:      "from-keychain",
		},
		{
			id:              "symvault-error-stops-without-fallback",
			desc:            "symvault failure must return error immediately and fail closed without falling through",
			ref:             "fritz.password",
			keychain:        true,
			keychainAccount: "fritz.box",
			plaintext:       "should-never-be-used",
			mockVaultErr:    "vault is locked",
			mockKCPass:      "from-keychain",
		},
		{
			id:              "keychain-wins-over-plaintext",
			desc:            "keychain takes precedence over plaintext fallback",
			keychain:        true,
			keychainAccount: "fritz.box",
			plaintext:       "from-plaintext",
			mockKCPass:      "from-keychain",
		},
		{
			id:              "keychain-error-stops-without-fallback",
			desc:            "keychain lookup failure must return error immediately and fail closed without falling through",
			keychain:        true,
			keychainAccount: "fritz.box",
			plaintext:       "should-never-be-used",
			mockKCErr:       "security: item not found",
		},
		{
			id:        "plaintext-fallback",
			desc:      "plaintext config password is used when env, symvault and keychain are not configured",
			plaintext: "plain-config-password",
		},
		{
			id:   "nothing-configured",
			desc: "returns empty password with none source when no credentials are configured",
		},
	}

	credentialCases := make([]portCredentialCase, 0, len(cases))
	ctx := context.Background()

	for _, c := range cases {
		t.Setenv("SYMFRITZ_PASSWORD", c.envPass)

		withStubs(t,
			func(_ context.Context, ref string) (string, error) {
				if c.mockVaultErr != "" {
					return "", errors.New(c.mockVaultErr)
				}
				return c.mockVaultPass, nil
			},
			func(_ context.Context, _, _ string) (string, error) {
				if c.mockKCErr != "" {
					return "", errors.New(c.mockKCErr)
				}
				return c.mockKCPass, nil
			},
		)

		res, err := Resolve(ctx, Options{
			EnvVar:          "SYMFRITZ_PASSWORD",
			Ref:             c.ref,
			Keychain:        c.keychain,
			KeychainAccount: c.keychainAccount,
			Plaintext:       c.plaintext,
		})

		cc := portCredentialCase{
			ID:               c.id,
			Description:      c.desc,
			EnvPassword:      c.envPass,
			Ref:              c.ref,
			Keychain:         c.keychain,
			KeychainAccount:  c.keychainAccount,
			Plaintext:        c.plaintext,
			MockVaultPass:    c.mockVaultPass,
			MockVaultErr:     c.mockVaultErr,
			MockKeychainPass: c.mockKCPass,
			MockKeychainErr:  c.mockKCErr,
			ExpectedPass:     res.Password,
			ExpectedSource:   string(res.Source),
		}
		if err != nil {
			cc.ExpectedError = err.Error()
		}
		credentialCases = append(credentialCases, cc)
	}

	subprocessContracts := []portSubprocessContract{
		{
			ID:                  "symvault-get",
			Description:         "symvault get reads secret from stdout, never passing secret in argv",
			Executable:          "symvault",
			Args:                symvaultGetArgs("{ref}"),
			StdinPayload:        "",
			ExposesSecretInArgv: false,
		},
		{
			ID:                  "symvault-set",
			Description:         "symvault set receives secret over stdin with trailing newline, never in argv",
			Executable:          "symvault",
			Args:                symvaultSetArgs("{ref}"),
			StdinPayload:        symvaultSetPayload("{value}"),
			ExposesSecretInArgv: false,
		},
		{
			ID:                  "keychain-get-with-account",
			Description:         "security find-generic-password with service and account",
			Executable:          "security",
			Args:                keychainGetArgs(KeychainService, "{account}"),
			StdinPayload:        "",
			ExposesSecretInArgv: false,
		},
		{
			ID:                  "keychain-get-without-account",
			Description:         "security find-generic-password with service only",
			Executable:          "security",
			Args:                keychainGetArgs(KeychainService, ""),
			StdinPayload:        "",
			ExposesSecretInArgv: false,
		},
		{
			ID:                  "keychain-set-with-account",
			Description:         "security interactive mode receives a hex-encoded add-generic-password command over stdin, never in argv",
			Executable:          "security",
			Args:                keychainSetArgs(),
			StdinPayload:        keychainSetPayload(KeychainService, "{account}", "{value}"),
			ExposesSecretInArgv: false,
		},
		{
			ID:                  "keychain-set-without-account",
			Description:         "security interactive mode stores a hex-encoded password without an account",
			Executable:          "security",
			Args:                keychainSetArgs(),
			StdinPayload:        keychainSetPayload(KeychainService, "", "{value}"),
			ExposesSecretInArgv: false,
		},
	}

	return portSecretFixture{
		SchemaVersion:       1,
		Oracle:              "Go internal/secret production functions",
		CredentialCases:     credentialCases,
		SubprocessContracts: subprocessContracts,
	}
}

func portSecretFixturePath(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve fixture source path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", "..", "testdata", "port", "config", "secret-vectors.json"))
}
