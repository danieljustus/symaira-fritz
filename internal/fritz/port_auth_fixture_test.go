package fritz

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

const updatePortFixturesEnv = "SYMFRITZ_UPDATE_PORT_FIXTURES"

type portAuthFixture struct {
	SchemaVersion int                  `json:"schema_version"`
	Oracle        string               `json:"oracle"`
	Session       []sessionVector      `json:"session"`
	DigestParse   []digestParseVector  `json:"digest_parse"`
	DigestHeader  []digestHeaderVector `json:"digest_header"`
}

type sessionVector struct {
	ID        string `json:"id"`
	Challenge string `json:"challenge"`
	Password  string `json:"password"`
	Response  string `json:"response,omitempty"`
	Error     string `json:"error,omitempty"`
}

type digestChallengeVector struct {
	Realm     string `json:"realm"`
	Nonce     string `json:"nonce"`
	QOP       string `json:"qop"`
	Algorithm string `json:"algorithm"`
	Opaque    string `json:"opaque"`
}

type digestParseVector struct {
	ID        string                `json:"id"`
	Header    string                `json:"header"`
	Parsed    bool                  `json:"parsed"`
	Challenge digestChallengeVector `json:"challenge"`
}

type digestHeaderVector struct {
	ID        string                `json:"id"`
	Challenge digestChallengeVector `json:"challenge"`
	User      string                `json:"user"`
	Password  string                `json:"password"`
	Method    string                `json:"method"`
	URI       string                `json:"uri"`
	NC        int                   `json:"nc"`
	Cnonce    string                `json:"cnonce"`
	Header    string                `json:"header"`
}

func TestPortAuthFixture(t *testing.T) {
	fixture := buildPortAuthFixture(t)
	got, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')

	path := portAuthFixturePath(t)
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
		t.Fatalf("read auth fixture: %v (regenerate with make port-fixtures)", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("auth fixture drifted; regenerate deliberately with make port-fixtures")
	}
}

func buildPortAuthFixture(t *testing.T) portAuthFixture {
	t.Helper()

	sessionInputs := []sessionVector{
		{ID: "legacy-avm", Challenge: "1234567z", Password: "äbc"},
		{ID: "legacy-surrogate-pair", Challenge: "emoji", Password: "🔐"},
		{ID: "legacy-prefix-two", Challenge: "2legacy", Password: "x"},
		{ID: "pbkdf2-standard", Challenge: "2$10000$5A1B$2000$5A1C", Password: "geheim"},
		{ID: "pbkdf2-lowercase-salts", Challenge: "2$2$0a0b$3$0c0d", Password: "päss🔐"},
		{ID: "pbkdf2-empty-second-salt", Challenge: "2$2$0a0b$3$", Password: "x"},
		{ID: "error-empty", Challenge: "", Password: "x"},
		{ID: "error-part-count", Challenge: "2$10000$5A1B$2000", Password: "x"},
		{ID: "error-iteration", Challenge: "2$x$5A1B$2000$5A1C", Password: "x"},
		{ID: "pbkdf2-zero-iteration", Challenge: "2$0$5A1B$2000$5A1C", Password: "x"},
		{ID: "pbkdf2-negative-iteration", Challenge: "2$-1$5A1B$2000$5A1C", Password: "x"},
		{ID: "error-salt", Challenge: "2$10000$zz$2000$5A1C", Password: "x"},
	}
	for i := range sessionInputs {
		response, err := computeChallengeResponse(sessionInputs[i].Challenge, sessionInputs[i].Password)
		if err != nil {
			sessionInputs[i].Error = err.Error()
		} else {
			sessionInputs[i].Response = response
		}
	}

	parseInputs := []struct {
		id     string
		header string
	}{
		{"standard", `Digest realm="F!Box", nonce="abc123", qop="auth", algorithm=MD5`},
		{"quoted-comma", `Digest realm="Fritz, Box", nonce="n-1", qop="auth,auth-int", opaque="opaque-value"`},
		{"embedded-prefix", `Negotiate token, Digest realm="F!Box", nonce="n-2"`},
		{"lowercase-prefix", `digest realm="F!Box", nonce="n-3"`},
		{"basic", `Basic realm="F!Box"`},
		{"missing-nonce", `Digest realm="F!Box", qop="auth"`},
	}
	parseVectors := make([]digestParseVector, 0, len(parseInputs))
	for _, input := range parseInputs {
		dc, ok := parseDigestChallenge(input.header)
		parseVectors = append(parseVectors, digestParseVector{
			ID:        input.id,
			Header:    input.header,
			Parsed:    ok,
			Challenge: challengeVector(dc),
		})
	}

	headerInputs := []digestHeaderVector{
		{
			ID:        "qop-auth",
			Challenge: digestChallengeVector{Realm: "F!Box", Nonce: "abc123", QOP: "auth", Algorithm: "MD5"},
			User:      "user",
			Password:  "pass",
			Method:    "POST",
			URI:       "/upnp/control/deviceinfo",
			NC:        1,
			Cnonce:    "0011223344556677",
		},
		{
			ID:        "qop-list-opaque",
			Challenge: digestChallengeVector{Realm: "Fritz, Box", Nonce: "n-2", QOP: "auth-int, auth", Opaque: "opaque-value"},
			User:      "alice",
			Password:  "päss",
			Method:    "GET",
			URI:       "/mesh.xml?x=1",
			NC:        255,
			Cnonce:    "8899aabbccddeeff",
		},
		{
			ID:        "legacy-no-qop",
			Challenge: digestChallengeVector{Realm: "F!Box", Nonce: "legacy-nonce"},
			User:      "user",
			Password:  "pass",
			Method:    "POST",
			URI:       "/ctrl",
			NC:        1,
			Cnonce:    "ignored-without-qop",
		},
		{
			ID:        "auth-int-only-falls-back",
			Challenge: digestChallengeVector{Realm: "F!Box", Nonce: "auth-int-nonce", QOP: "auth-int"},
			User:      "user",
			Password:  "pass",
			Method:    "POST",
			URI:       "/ctrl",
			NC:        2,
			Cnonce:    "ignored-without-auth",
		},
	}
	for i := range headerInputs {
		dc := fixtureChallenge(headerInputs[i].Challenge)
		headerInputs[i].Header = digestAuthHeaderWithCnonce(
			dc,
			headerInputs[i].User,
			headerInputs[i].Password,
			headerInputs[i].Method,
			headerInputs[i].URI,
			headerInputs[i].NC,
			headerInputs[i].Cnonce,
		)
	}

	return portAuthFixture{
		SchemaVersion: 1,
		Oracle:        "Go internal/fritz production authentication functions",
		Session:       sessionInputs,
		DigestParse:   parseVectors,
		DigestHeader:  headerInputs,
	}
}

func challengeVector(dc digestChallenge) digestChallengeVector {
	return digestChallengeVector{
		Realm:     dc.realm,
		Nonce:     dc.nonce,
		QOP:       dc.qop,
		Algorithm: dc.algorithm,
		Opaque:    dc.opaque,
	}
}

func fixtureChallenge(dc digestChallengeVector) digestChallenge {
	return digestChallenge{
		realm:     dc.Realm,
		nonce:     dc.Nonce,
		qop:       dc.QOP,
		algorithm: dc.Algorithm,
		opaque:    dc.Opaque,
	}
}

func portAuthFixturePath(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve fixture source path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", "..", "testdata", "port", "auth", "auth-vectors.json"))
}
