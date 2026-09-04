package fritz

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestScrapeDataLUAResponseValidation(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		body        string
		want        string
		wantErr     []string
	}{
		{
			name:        "valid JSON",
			contentType: "application/json; charset=utf-8",
			body:        `{"data":[]}`,
			want:        `{"data":[]}`,
		},
		{
			name:        "HTML login page",
			contentType: "text/html; charset=utf-8",
			body:        `<!DOCTYPE html><html><head><title>FRITZ!Box</title></head><body>Login</body></html>`,
			wantErr:     []string{"HTML login page", "symfritz auth test"},
		},
		{
			name:        "other non-JSON response",
			contentType: "text/plain",
			body:        "temporarily unavailable",
			wantErr:     []string{"non-JSON response", "text/plain"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/login_sid.lua":
					w.Header().Set("Content-Type", "text/xml")
					_, _ = io.WriteString(w, `<?xml version="1.0"?><SessionInfo><SID>0123456789abcdef</SID><Challenge>x</Challenge><BlockTime>0</BlockTime></SessionInfo>`)
				case "/data.lua":
					if err := r.ParseForm(); err != nil {
						t.Errorf("ParseForm: %v", err)
					}
					if got := r.Form.Get("sid"); got != "0123456789abcdef" {
						t.Errorf("sid = %q, want authenticated SID", got)
					}
					if got := r.Form.Get("page"); got != "overview" {
						t.Errorf("page = %q, want overview", got)
					}
					w.Header().Set("Content-Type", tt.contentType)
					_, _ = io.WriteString(w, tt.body)
				default:
					http.NotFound(w, r)
				}
			}))
			t.Cleanup(srv.Close)

			c := New("fritz.box", WithPassword("pw"))
			c.SetMockURLs(srv.URL)
			got, err := c.ScrapeDataLUA(context.Background(), "overview", url.Values{"foo": {"bar"}})
			if len(tt.wantErr) == 0 {
				if err != nil {
					t.Fatalf("ScrapeDataLUA: %v", err)
				}
				if got != tt.want {
					t.Errorf("ScrapeDataLUA = %q, want %q", got, tt.want)
				}
				return
			}
			if err == nil {
				t.Fatalf("ScrapeDataLUA returned %q without an error", got)
			}
			for _, want := range tt.wantErr {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error = %q, want %q", err, want)
				}
			}
		})
	}
}
