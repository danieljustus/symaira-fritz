package fritz

import (
	"errors"
	"strings"
	"testing"
)

func TestParseDigestChallenge(t *testing.T) {
	header := `Digest realm="F!Box", nonce="abc123", qop="auth", algorithm=MD5`
	dc, ok := parseDigestChallenge(header)
	if !ok {
		t.Fatal("expected challenge to parse")
	}
	if dc.realm != "F!Box" {
		t.Errorf("realm = %q", dc.realm)
	}
	if dc.nonce != "abc123" {
		t.Errorf("nonce = %q", dc.nonce)
	}
	if dc.qop != "auth" {
		t.Errorf("qop = %q", dc.qop)
	}
}

func TestParseDigestChallenge_NotDigest(t *testing.T) {
	if _, ok := parseDigestChallenge(`Basic realm="x"`); ok {
		t.Error("expected Basic auth to fail digest parse")
	}
}

func TestDigestAuthHeader_Auth(t *testing.T) {
	dc := digestChallenge{realm: "F!Box", nonce: "abc123", qop: "auth"}
	got, err := digestAuthHeader(dc, "user", "pass", "POST", "/upnp/control/deviceinfo", 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`username="user"`, `realm="F!Box"`, `nonce="abc123"`,
		`uri="/upnp/control/deviceinfo"`, `qop=auth`, `nc=00000001`, `response="`,
	} {
		if !contains(got, want) {
			t.Errorf("auth header missing %q\nfull: %s", want, got)
		}
	}
}

func TestDigestAuthHeader_QopList(t *testing.T) {
	// Servers may advertise "auth,auth-int" — we must still select auth.
	dc := digestChallenge{realm: "F!Box", nonce: "n", qop: "auth,auth-int"}
	got, err := digestAuthHeader(dc, "u", "p", "POST", "/ctrl", 1)
	if err != nil {
		t.Fatal(err)
	}
	if !contains(got, "qop=auth") || !contains(got, "nc=00000001") {
		t.Errorf("qop list not handled: %s", got)
	}
}

func TestQopOffersAuth(t *testing.T) {
	cases := map[string]bool{
		"auth":            true,
		"auth,auth-int":   true,
		" auth-int, auth": true,
		"auth-int":        false,
		"":                false,
	}
	for in, want := range cases {
		if got := qopOffersAuth(in); got != want {
			t.Errorf("qopOffersAuth(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestSplitDigestFields_QuotedComma(t *testing.T) {
	fields := splitDigestFields(`realm="a,b", nonce="c"`)
	if len(fields) != 2 {
		t.Fatalf("expected 2 fields, got %d: %v", len(fields), fields)
	}
}

// TestGenerateCnonce_Uniqueness verifies Issue #121: the client nonce is
// freshly generated per request and two consecutive calls produce different
// values.
func TestGenerateCnonce_Uniqueness(t *testing.T) {
	c1, err := generateCnonce()
	if err != nil {
		t.Fatalf("generateCnonce() error: %v", err)
	}
	c2, err := generateCnonce()
	if err != nil {
		t.Fatalf("generateCnonce() error: %v", err)
	}
	if c1 == c2 {
		t.Errorf("consecutive cnonce values should differ: both %q", c1)
	}
	if len(c1) != 16 {
		t.Errorf("cnonce should be 16 hex chars (8 bytes), got %d: %q", len(c1), c1)
	}
}

// TestDigestAuthHeader_DifferentCnoncePerRequest verifies Issue #121: two
// consecutive calls to digestAuthHeader produce different cnonce values in
// the Authorization header.
func TestDigestAuthHeader_DifferentCnoncePerRequest(t *testing.T) {
	dc := digestChallenge{realm: "F!Box", nonce: "abc123", qop: "auth"}
	h1, err := digestAuthHeader(dc, "user", "pass", "POST", "/ctrl", 1)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := digestAuthHeader(dc, "user", "pass", "POST", "/ctrl", 1)
	if err != nil {
		t.Fatal(err)
	}
	if h1 == h2 {
		t.Errorf("two consecutive auth headers should differ (cnonce should be random)")
	}
}

// TestDigestAuthHeader_NcFormat verifies Issue #122: the nc value is
// formatted as an 8-digit hex string (RFC 7616).
func TestDigestAuthHeader_NcFormat(t *testing.T) {
	dc := digestChallenge{realm: "F!Box", nonce: "abc123", qop: "auth"}
	tests := []struct {
		name string
		nc   int
		want string
	}{
		{"nc=1", 1, "nc=00000001"},
		{"nc=2", 2, "nc=00000002"},
		{"nc=255", 255, "nc=000000ff"},
		{"nc=65535", 65535, "nc=0000ffff"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := digestAuthHeader(dc, "user", "pass", "POST", "/ctrl", tt.nc)
			if err != nil {
				t.Fatal(err)
			}
			if !contains(got, tt.want) {
				t.Errorf("nc=%d: expected %q in header, got: %s", tt.nc, tt.want, got)
			}
		})
	}
}

// TestGenerateCnonce_ErrorPath verifies Issue #121 acceptance criterion:
// if the random source fails, generateCnonce returns an error.
func TestGenerateCnonce_ErrorPath(t *testing.T) {
	original := randRead
	randRead = func([]byte) (int, error) { return 0, errors.New("entropy unavailable") }
	t.Cleanup(func() { randRead = original })

	dc := digestChallenge{realm: "F!Box", nonce: "abc123", qop: "auth"}
	header, err := digestAuthHeader(dc, "user", "pass", "POST", "/ctrl", 1)
	if err == nil || !strings.Contains(err.Error(), "generating client nonce") {
		t.Fatalf("digestAuthHeader error = %v, want client nonce error", err)
	}
	if header != "" {
		t.Fatalf("digestAuthHeader returned header %q after entropy failure", header)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
