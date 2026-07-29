package fritz

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDSLLineStats_IGDFallback(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		soapAction := r.Header.Get("SoapAction")
		if soapAction == "urn:dslforum-org:service:WANDSLInterfaceConfig:1#GetInfo" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if soapAction == "urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1#GetCommonLinkProperties" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:GetCommonLinkPropertiesResponse xmlns:u="urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1"><NewLayer1DownstreamMaxBitRate>100000000</NewLayer1DownstreamMaxBitRate><NewLayer1UpstreamMaxBitRate>40000000</NewLayer1UpstreamMaxBitRate></u:GetCommonLinkPropertiesResponse></s:Body></s:Envelope>`))
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer ts.Close()

	client := New("127.0.0.1")
	client.SetMockURLs(ts.URL)

	stats, err := client.DSLLineStats(context.Background())
	if err != nil {
		t.Fatalf("expected successful DSL fallback, got %v", err)
	}

	if !stats.IsReducedDataset {
		t.Errorf("expected IsReducedDataset true, got false")
	}
	if stats.DownstreamMaxBitRate != 100000000 {
		t.Errorf("expected 100000000 max downstream, got %d", stats.DownstreamMaxBitRate)
	}
	if stats.UpstreamMaxBitRate != 40000000 {
		t.Errorf("expected 40000000 max upstream, got %d", stats.UpstreamMaxBitRate)
	}
}
