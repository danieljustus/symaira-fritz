package fritz

import "testing"

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
	got := digestAuthHeader(dc, "user", "pass", "POST", "/upnp/control/deviceinfo")
	for _, want := range []string{
		`username="user"`, `realm="F!Box"`, `nonce="abc123"`,
		`uri="/upnp/control/deviceinfo"`, `qop=auth`, `nc=00000001`, `response="`,
	} {
		if !contains(got, want) {
			t.Errorf("auth header missing %q\nfull: %s", want, got)
		}
	}
}

func TestSplitDigestFields_QuotedComma(t *testing.T) {
	fields := splitDigestFields(`realm="a,b", nonce="c"`)
	if len(fields) != 2 {
		t.Fatalf("expected 2 fields, got %d: %v", len(fields), fields)
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
