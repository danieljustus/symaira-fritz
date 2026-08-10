package fritz

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
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

// fakeSessionBox serves /login_sid.lua as a two-request challenge-response box:
// request 1 yields a challenge (or a ready SID), request 2 (username+response)
// yields the final SID, an invalid SID, or an error response. Requests are
// recorded for assertion.
type fakeSessionBox struct {
	readySID  string // when set, returned immediately on every request (no challenge flow)
	challenge string // challenge sent on the first request
	step2SID  string // SID sent once a response is supplied
	blockTime int
	status    int    // HTTP status for every response; 0 = 200
	body      string // raw body override (e.g. malformed XML)
	reqs      []url.Values
}

func (f *fakeSessionBox) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/login_sid.lua" {
		http.NotFound(w, r)
		return
	}
	q := r.URL.Query()
	f.reqs = append(f.reqs, q)
	if f.status != 0 {
		w.WriteHeader(f.status)
	}
	if f.body != "" {
		_, _ = w.Write([]byte(f.body))
		return
	}
	if f.readySID != "" {
		_, _ = w.Write([]byte(`<?xml version="1.0"?><SessionInfo><SID>` + f.readySID + `</SID><Challenge>x</Challenge><BlockTime>0</BlockTime></SessionInfo>`))
		return
	}
	if q.Get("response") == "" {
		_, _ = w.Write([]byte(`<?xml version="1.0"?><SessionInfo><SID>0000000000000000</SID><Challenge>` + f.challenge + `</Challenge><BlockTime>0</BlockTime></SessionInfo>`))
		return
	}
	_, _ = w.Write([]byte(`<?xml version="1.0"?><SessionInfo><SID>` + f.step2SID + `</SID><Challenge>x</Challenge><BlockTime>` + strconv.Itoa(f.blockTime) + `</BlockTime></SessionInfo>`))
}

// newSessionClient returns a client pointed at an httptest server backed by box.
func newSessionClient(t *testing.T, box http.Handler) *Client {
	t.Helper()
	srv := httptest.NewServer(box)
	t.Cleanup(srv.Close)
	c := New("fritz.box", WithUser("admin"), WithPassword("geheim"))
	c.httpBaseURL = srv.URL
	return c
}

// TestSID_LegacyChallengeFlow exercises the full two-request login exchange
// with the legacy MD5 challenge, asserting username/response forwarding and
// SID caching.
func TestSID_LegacyChallengeFlow(t *testing.T) {
	box := &fakeSessionBox{challenge: "1234567z", step2SID: "legacysid000000000000"}
	c := newSessionClient(t, box)
	c.Password = "äbc"

	sid, err := c.SID(context.Background())
	if err != nil {
		t.Fatalf("SID: %v", err)
	}
	if sid != "legacysid000000000000" {
		t.Fatalf("SID = %q, want legacysid000000000000", sid)
	}
	if len(box.reqs) != 2 {
		t.Fatalf("requests = %d, want 2 (challenge + response)", len(box.reqs))
	}
	if got := box.reqs[0].Get("username"); got != "" {
		t.Errorf("first request username = %q, want empty", got)
	}
	if got := box.reqs[0].Get("response"); got != "" {
		t.Errorf("first request response = %q, want empty", got)
	}
	if got := box.reqs[1].Get("username"); got != c.User {
		t.Errorf("second request username = %q, want %q", got, c.User)
	}
	wantResp := md5Response("1234567z", "äbc")
	if got := box.reqs[1].Get("response"); got != wantResp {
		t.Errorf("second request response = %q, want %q", got, wantResp)
	}

	// The SID is cached: a second call must not contact the box again.
	if _, err := c.SID(context.Background()); err != nil {
		t.Fatalf("cached SID call: %v", err)
	}
	if len(box.reqs) != 2 {
		t.Errorf("requests after cached call = %d, want 2", len(box.reqs))
	}
}

// TestSID_PBKDF2ChallengeFlow verifies the modern FRITZ!OS 7.24+ challenge.
func TestSID_PBKDF2ChallengeFlow(t *testing.T) {
	challenge := "2$10000$5A1B$2000$5A1C"
	box := &fakeSessionBox{challenge: challenge, step2SID: "pbkdf2sid000000000000"}
	c := newSessionClient(t, box)

	sid, err := c.SID(context.Background())
	if err != nil {
		t.Fatalf("SID: %v", err)
	}
	if sid != "pbkdf2sid000000000000" {
		t.Fatalf("SID = %q, want pbkdf2sid000000000000", sid)
	}
	if len(box.reqs) != 2 {
		t.Fatalf("requests = %d, want 2", len(box.reqs))
	}
	wantResp, err := pbkdf2Response(challenge, "geheim")
	if err != nil {
		t.Fatal(err)
	}
	if got := box.reqs[1].Get("response"); got != wantResp {
		t.Errorf("second request response = %q, want %q", got, wantResp)
	}
}

// TestSID_ReadySIDWithoutChallenge covers boxes that hand out a SID on the
// first request (no challenge needed).
func TestSID_ReadySIDWithoutChallenge(t *testing.T) {
	box := &fakeSessionBox{readySID: "directsid000000000000"}
	c := newSessionClient(t, box)

	sid, err := c.SID(context.Background())
	if err != nil {
		t.Fatalf("SID: %v", err)
	}
	if sid != "directsid000000000000" {
		t.Fatalf("SID = %q, want directsid000000000000", sid)
	}
	if len(box.reqs) != 1 {
		t.Errorf("requests = %d, want 1", len(box.reqs))
	}
}

// TestSID_RejectedCredentials verifies the invalid-SID error path.
func TestSID_RejectedCredentials(t *testing.T) {
	box := &fakeSessionBox{challenge: "1234567z", step2SID: invalidSID}
	c := newSessionClient(t, box)

	_, err := c.SID(context.Background())
	if err == nil {
		t.Fatal("expected error for rejected credentials")
	}
	if !strings.Contains(err.Error(), "invalid credentials") {
		t.Errorf("error = %q, want mention of invalid credentials", err)
	}
	if len(box.reqs) != 2 {
		t.Errorf("requests = %d, want 2", len(box.reqs))
	}
}

// TestSID_BlockTimeRateLimit verifies the rate-limiting error path.
func TestSID_BlockTimeRateLimit(t *testing.T) {
	box := &fakeSessionBox{challenge: "1234567z", step2SID: invalidSID, blockTime: 30}
	c := newSessionClient(t, box)

	_, err := c.SID(context.Background())
	if err == nil {
		t.Fatal("expected error for rate-limited box")
	}
	if !strings.Contains(err.Error(), "rate-limiting") || !strings.Contains(err.Error(), "30") {
		t.Errorf("error = %q, want rate-limiting mention with 30s", err)
	}
}

// TestSID_MalformedLoginXML verifies the XML parse error path.
func TestSID_MalformedLoginXML(t *testing.T) {
	box := &fakeSessionBox{body: `<SessionInfo><SID>oops`}
	c := newSessionClient(t, box)

	_, err := c.SID(context.Background())
	if err == nil {
		t.Fatal("expected error for malformed XML")
	}
	if !strings.Contains(err.Error(), "parsing login_sid.lua") {
		t.Errorf("error = %q, want mention of parsing login_sid.lua", err)
	}
}

// TestSID_TransportError verifies the connection-error path.
func TestSID_TransportError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	deadURL := srv.URL
	srv.Close()

	c := New("fritz.box", WithPassword("geheim"))
	c.httpBaseURL = deadURL

	_, err := c.SID(context.Background())
	if err == nil {
		t.Fatal("expected error for unreachable box")
	}
	if !strings.Contains(err.Error(), "contacting") {
		t.Errorf("error = %q, want mention of contacting", err)
	}
}

// TestSID_NonSuccessStatus verifies the non-200 status handling.
func TestSID_NonSuccessStatus(t *testing.T) {
	box := &fakeSessionBox{status: http.StatusInternalServerError}
	c := newSessionClient(t, box)

	_, err := c.SID(context.Background())
	if err == nil {
		t.Fatal("expected error for HTTP 500")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error = %q, want mention of HTTP 500", err)
	}
}
