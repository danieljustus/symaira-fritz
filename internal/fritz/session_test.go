package fritz

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestMD5Response(t *testing.T) {
	// Reference vector from AVM's session-id documentation.
	// challenge "1234567z", password "äbc" → known response.
	got := md5Response("1234567z", "äbc")
	const want = "1234567z-9e224a41eeefa284df7bb0f26c2913e2"
	if got != want {
		t.Fatalf("md5Response = %q, want %q", got, want)
	}
}

func TestPBKDF2Response_Shape(t *testing.T) {
	// We don't have an official end-to-end vector here, but we can assert the
	// structural contract: response is "<salt2>$<64-hex>".
	challenge := "2$10000$5A1B$2000$5A1C"
	got, err := pbkdf2Response(challenge, "secret")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	salt2, hashHex, ok := strings.Cut(got, "$")
	if !ok {
		t.Fatalf("response %q missing '$' separator", got)
	}
	if salt2 != "5A1C" {
		t.Errorf("salt2 = %q, want 5A1C", salt2)
	}
	if len(hashHex) != 64 {
		t.Errorf("hash hex length = %d, want 64", len(hashHex))
	}
}

func TestPBKDF2Response_Malformed(t *testing.T) {
	for _, ch := range []string{"2$10000$5A1B$2000", "2$x$5A1B$2000$5A1C", "2$10000$zz$2000$5A1C"} {
		if _, err := pbkdf2Response(ch, "secret"); err == nil {
			t.Errorf("expected error for malformed challenge %q", ch)
		}
	}
}

func TestComputeChallengeResponse_Dispatch(t *testing.T) {
	// Legacy challenge (no "2$" prefix) must go through the MD5 path.
	got, err := computeChallengeResponse("1234567z", "äbc")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got, "1234567z-") {
		t.Errorf("legacy response = %q, want MD5 form", got)
	}
	if _, err := computeChallengeResponse("", "x"); err == nil {
		t.Error("expected error for empty challenge")
	}
}

func TestSID_NoPasswordDoesNotContactBox(t *testing.T) {
	var requests int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		t.Fatalf("SID contacted the box without a configured password: %s", r.URL.String())
	}))
	defer srv.Close()

	c := New("fritz.box")
	c.httpBaseURL = srv.URL

	_, err := c.SID(context.Background())
	if !errors.Is(err, ErrNoCredential) {
		t.Fatalf("SID error = %v, want ErrNoCredential", err)
	}
	if got := atomic.LoadInt32(&requests); got != 0 {
		t.Fatalf("requests = %d, want 0", got)
	}
}
