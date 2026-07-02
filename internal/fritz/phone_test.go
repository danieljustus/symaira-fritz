package fritz

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCalls_ParsesRootWrappedCallList(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/calllist.lua" {
			w.Header().Set("Content-Type", `text/xml; charset="utf-8"`)
			_, _ = io.WriteString(w, `<root>
				<timestamp>123456</timestamp>
				<Call>
					<Id>1</Id>
					<Type>1</Type>
					<Caller>01712345</Caller>
					<Called>089123</Called>
					<Name>Alice</Name>
					<Date>29.06.26 14:15</Date>
					<Duration>0:15</Duration>
				</Call>
			</root>`)
			return
		}
		if r.Method == http.MethodPost && strings.Contains(r.Header.Get("SoapAction"), "GetCallList") {
			w.Header().Set("Content-Type", `text/xml; charset="utf-8"`)
			_, _ = io.WriteString(w, soapEnvelope("GetCallList", map[string]string{
				"NewCallListURL": srvURL(r) + "/calllist.lua?sid=from-soap",
			}))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	c := New("fritz.box", WithPassword("secret"))
	c.SetMockURLs(srv.URL)

	calls, err := c.Calls(context.Background(), CallAll, 0, 0)
	if err != nil {
		t.Fatalf("Calls: %v", err)
	}
	if len(calls) != 1 {
		t.Fatalf("len(calls) = %d, want 1", len(calls))
	}
	if calls[0].Caller != "Alice" || calls[0].CallerNumber != "01712345" {
		t.Fatalf("unexpected call: %+v", calls[0])
	}
}

func srvURL(r *http.Request) string {
	return "http://" + r.Host
}
