package fritz

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOnlineMonitor_IGDFallback(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		soapAction := r.Header.Get("SoapAction")
		if soapAction == "urn:dslforum-org:service:WANCommonInterfaceConfig:1#X_AVM-DE_GetOnlineMonitor" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if soapAction == "urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1#GetAddonInfos" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:GetAddonInfosResponse xmlns:u="urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1"><NewByteReceiveRate>125000</NewByteReceiveRate><NewByteSendRate>25000</NewByteSendRate></u:GetAddonInfosResponse></s:Body></s:Envelope>`))
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer ts.Close()

	client := New("127.0.0.1")
	client.SetMockURLs(ts.URL)

	traffic, err := client.OnlineMonitor(context.Background())
	if err != nil {
		t.Fatalf("expected successful fallback, got %v", err)
	}

	if !traffic.IsReducedDataset {
		t.Errorf("expected IsReducedDataset true, got false")
	}
	if len(traffic.DownstreamInternet) != 1 || traffic.DownstreamInternet[0] != 1000000 {
		t.Errorf("expected 1000000 bps downstream, got %v", traffic.DownstreamInternet)
	}
	if len(traffic.UpstreamDefaultPriority) != 1 || traffic.UpstreamDefaultPriority[0] != 200000 {
		t.Errorf("expected 200000 bps upstream, got %v", traffic.UpstreamDefaultPriority)
	}
}
