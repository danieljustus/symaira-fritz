package fritz

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

type portRemainingFixture struct {
	SchemaVersion int                      `json:"schema_version"`
	Oracle        string                   `json:"oracle"`
	Models        portRemainingModels      `json:"models"`
	Requests      []portRemainingRequest   `json:"requests"`
	Fallbacks     []portRemainingFallback  `json:"fallbacks"`
	Negative      []portCapabilityNegative `json:"negative"`
}

type portRemainingModels struct {
	DSL     DSLLineStatsFixture `json:"dsl"`
	Calls   []CallFixture       `json:"calls"`
	Traffic TrafficDataFixture  `json:"traffic"`
	Log     []LogEventFixture   `json:"log"`
}

type DSLLineStatsFixture struct {
	UpstreamNoiseMargin   int  `json:"upstream_noise_margin,omitempty"`
	DownstreamNoiseMargin int  `json:"downstream_noise_margin,omitempty"`
	UpstreamAttenuation   int  `json:"upstream_attenuation,omitempty"`
	DownstreamAttenuation int  `json:"downstream_attenuation,omitempty"`
	UpstreamMaxBitRate    int  `json:"upstream_max_bit_rate,omitempty"`
	DownstreamMaxBitRate  int  `json:"downstream_max_bit_rate,omitempty"`
	IsReducedDataset      bool `json:"is_reduced_dataset,omitempty"`
}

type CallFixture struct {
	Type         CallType      `json:"type"`
	Date         time.Time     `json:"date"`
	Caller       string        `json:"caller"`
	CallerNumber string        `json:"caller_number"`
	CalledNumber string        `json:"called_number"`
	Name         string        `json:"name"`
	Duration     time.Duration `json:"duration"`
}

type TrafficDataFixture struct {
	DownstreamInternet      []float64 `json:"downstream_internet,omitempty"`
	DownstreamMedia         []float64 `json:"downstream_media,omitempty"`
	DownstreamGuest         []float64 `json:"downstream_guest,omitempty"`
	UpstreamRealtime        []float64 `json:"upstream_realtime,omitempty"`
	UpstreamHighPriority    []float64 `json:"upstream_high_priority,omitempty"`
	UpstreamDefaultPriority []float64 `json:"upstream_default_priority,omitempty"`
	UpstreamLowPriority     []float64 `json:"upstream_low_priority,omitempty"`
	UpstreamGuest           []float64 `json:"upstream_guest,omitempty"`
	IsReducedDataset        bool      `json:"is_reduced_dataset,omitempty"`
}

type LogEventFixture struct {
	ID    string    `json:"id"`
	Group string    `json:"group"`
	Time  time.Time `json:"time"`
	Msg   string    `json:"msg"`
}

type portRemainingRequest struct {
	ID          string            `json:"id"`
	ServiceType string            `json:"service_type,omitempty"`
	ControlURL  string            `json:"control_url,omitempty"`
	Action      string            `json:"action,omitempty"`
	Args        map[string]string `json:"args,omitempty"`
	Method      string            `json:"method,omitempty"`
	URL         string            `json:"url,omitempty"`
	Body        string            `json:"body,omitempty"`
}

type portRemainingFallback struct {
	ID              string                 `json:"id"`
	Trigger         string                 `json:"trigger"`
	Reduced         bool                   `json:"reduced"`
	ExpectedRequest []portRemainingRequest `json:"expected_request"`
}

func TestPortRemainingCapabilitiesFixture(t *testing.T) {
	fixture := portRemainingFixture{
		SchemaVersion: 1,
		Oracle:        "Go internal/fritz/{status,dsl,phone,traffic,log} production models and request seams; reboot uses cmd/symfritz/reboot.go raw Call",
		Models: portRemainingModels{
			DSL:     DSLLineStatsFixture{UpstreamNoiseMargin: 60, DownstreamNoiseMargin: 80, UpstreamAttenuation: 150, DownstreamAttenuation: 180, UpstreamMaxBitRate: 40000000, DownstreamMaxBitRate: 100000000},
			Calls:   []CallFixture{{Type: CallIncoming, Date: time.Date(2026, 6, 29, 14, 15, 0, 0, time.UTC), Caller: "Alice", CallerNumber: "01712345", CalledNumber: "089123", Name: "Alice", Duration: 15 * time.Second}, {Type: CallOutgoing, Date: time.Date(2026, 6, 29, 14, 16, 0, 0, time.UTC), Caller: "089123", CallerNumber: "", CalledNumber: "01712345", Name: "", Duration: 90 * time.Second}},
			Traffic: TrafficDataFixture{DownstreamInternet: []float64{1000, 2000}, DownstreamMedia: []float64{100, 200}, DownstreamGuest: []float64{10, 20}, UpstreamRealtime: []float64{5, 5}, UpstreamHighPriority: []float64{2, 2}, UpstreamDefaultPriority: []float64{1, 1}, UpstreamLowPriority: []float64{0, 0}, UpstreamGuest: []float64{0, 0}},
			Log:     []LogEventFixture{{ID: "10", Group: "sys", Time: time.Date(2026, 6, 29, 14, 15, 0, 0, time.UTC), Msg: "System started"}, {ID: "11", Group: "net", Time: time.Date(2026, 6, 29, 14, 16, 0, 0, time.UTC), Msg: "Link up"}},
		},
		Requests: []portRemainingRequest{
			{ID: "dsl-info", ServiceType: ServiceWANDSLInterfaceConfig.Type, ControlURL: ServiceWANDSLInterfaceConfig.ControlURL, Action: "GetInfo"},
			{ID: "dsl-common", ServiceType: ServiceWANCommonIFC.Type, ControlURL: ServiceWANCommonIFC.ControlURL, Action: "GetCommonLinkProperties"},
			{ID: "dsl-igd-common", ServiceType: ServiceIGDWANCommonIFC.Type, ControlURL: ServiceIGDWANCommonIFC.ControlURL, Action: "GetCommonLinkProperties"},
			{ID: "traffic-monitor", ServiceType: ServiceWANCommonIFC.Type, ControlURL: ServiceWANCommonIFC.ControlURL, Action: "X_AVM-DE_GetOnlineMonitor", Args: map[string]string{"NewSyncGroupIndex": "0"}},
			{ID: "traffic-igd-addon", ServiceType: ServiceIGDWANCommonIFC.Type, ControlURL: ServiceIGDWANCommonIFC.ControlURL, Action: "GetAddonInfos"},
			{ID: "phone-list", ServiceType: ServiceOnTel.Type, ControlURL: ServiceOnTel.ControlURL, Action: "GetCallList"},
			{ID: "phone-dial", ServiceType: ServiceVoIP.Type, ControlURL: ServiceVoIP.ControlURL, Action: "X_AVM-DE_DialNumber", Args: map[string]string{"NewX_AVM-DE_PhoneNumber": "123"}},
			{ID: "phone-hangup", ServiceType: ServiceVoIP.Type, ControlURL: ServiceVoIP.ControlURL, Action: "X_AVM-DE_DialHangup"},
			{ID: "log-path", ServiceType: ServiceDeviceInfo.Type, ControlURL: ServiceDeviceInfo.ControlURL, Action: "X_AVM-DE_GetDeviceLogPath"},
			{ID: "reboot", ServiceType: "urn:dslforum-org:service:DeviceConfig:1", ControlURL: "/upnp/control/deviceconfig", Action: "Reboot"},
			{ID: "cpu-query", Method: "POST", URL: "/query.lua?sid=mock-sid", Body: `{"CPUTEMP":"cpu:status/StatTemperature"}`},
		},
		Fallbacks: []portRemainingFallback{
			{ID: "dsl-unauthorized-to-igd", Trigger: "unauthorized", Reduced: true, ExpectedRequest: []portRemainingRequest{{ID: "dsl-igd-common", ServiceType: ServiceIGDWANCommonIFC.Type, ControlURL: ServiceIGDWANCommonIFC.ControlURL, Action: "GetCommonLinkProperties"}}},
			{ID: "traffic-unauthorized-to-igd", Trigger: "unauthorized", Reduced: true, ExpectedRequest: []portRemainingRequest{{ID: "traffic-igd-addon", ServiceType: ServiceIGDWANCommonIFC.Type, ControlURL: ServiceIGDWANCommonIFC.ControlURL, Action: "GetAddonInfos"}}},
			{ID: "calls-filter-order", Trigger: "days=7,max=2,type=missed", Reduced: false, ExpectedRequest: []portRemainingRequest{{ID: "phone-list", ServiceType: ServiceOnTel.Type, ControlURL: ServiceOnTel.ControlURL, Action: "GetCallList"}}},
			{ID: "log-filter-all-omitted", Trigger: "filter=all", Reduced: false, ExpectedRequest: []portRemainingRequest{{ID: "log-path", ServiceType: ServiceDeviceInfo.Type, ControlURL: ServiceDeviceInfo.ControlURL, Action: "X_AVM-DE_GetDeviceLogPath"}}},
			{ID: "cpu-403-refresh-once", Trigger: "HTTP 403", Reduced: false, ExpectedRequest: []portRemainingRequest{{ID: "cpu-query", Method: "POST", URL: "/query.lua?sid=mock-sid", Body: `{"CPUTEMP":"cpu:status/StatTemperature"}`}, {ID: "cpu-query-refresh", Method: "POST", URL: "/query.lua?sid=fresh-sid", Body: `{"CPUTEMP":"cpu:status/StatTemperature"}`}}},
		},
		Negative: []portCapabilityNegative{
			{ID: "empty-call-list-url", Input: "", Message: "tr064: GetCallList returned empty NewCallListURL"},
			{ID: "empty-device-log-path", Input: "", Message: "tr064: GetDeviceLogPath returned empty path"},
			{ID: "cpu-missing-key", Input: `{}`, Message: "query.lua response missing CPUTEMP key"},
			{ID: "malformed-call-xml", Input: "<CallList>", Message: "XML parse error"},
		},
	}
	got, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	path := portRemainingFixturePath(t)
	if os.Getenv(updatePortFixturesEnv) == "1" {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read remaining capabilities fixture: %v (regenerate with make port-remaining-fixtures)", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("remaining capabilities fixture drifted; regenerate deliberately with make port-remaining-fixtures")
	}
}

func portRemainingFixturePath(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve remaining fixture path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", "..", "testdata", "port", "capabilities-remaining", "contracts.json"))
}
