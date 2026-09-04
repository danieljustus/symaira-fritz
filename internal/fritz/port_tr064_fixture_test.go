package fritz

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

type portTR064Fixture struct {
	SchemaVersion int                   `json:"schema_version"`
	Oracle        string                `json:"oracle"`
	SOAPRequests  []soapRequestVector   `json:"soap_requests"`
	SOAPResponses []soapResponseVector  `json:"soap_responses"`
	SOAPFaults    []soapFaultVector     `json:"soap_faults"`
	Discovery     []discoveryVector     `json:"discovery"`
	ServiceLookup []serviceLookupVector `json:"service_lookup"`
}

type portService struct {
	Type       string `json:"type"`
	ControlURL string `json:"control_url"`
}

type soapRequestVector struct {
	ID          string            `json:"id"`
	ServiceType string            `json:"service_type"`
	Action      string            `json:"action"`
	Args        map[string]string `json:"args"`
	Body        string            `json:"body"`
}

type soapResponseVector struct {
	ID     string            `json:"id"`
	Action string            `json:"action"`
	XML    string            `json:"xml"`
	Output map[string]string `json:"output,omitempty"`
	Error  bool              `json:"error,omitempty"`
}

type soapFaultVector struct {
	ID          string `json:"id"`
	XML         string `json:"xml"`
	Code        int    `json:"code"`
	Description string `json:"description"`
}

type discoveryVector struct {
	ID        string        `json:"id"`
	InputFile string        `json:"input_file,omitempty"`
	XML       string        `json:"xml,omitempty"`
	Services  []portService `json:"services,omitempty"`
	Error     bool          `json:"error,omitempty"`
}

type serviceLookupVector struct {
	ID      string       `json:"id"`
	Name    string       `json:"name"`
	Service *portService `json:"service,omitempty"`
	Error   string       `json:"error,omitempty"`
}

func TestPortTR064Fixture(t *testing.T) {
	fixture := buildPortTR064Fixture(t)
	got, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')

	path := portTR064FixturePath(t)
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
		t.Fatalf("read TR-064 fixture: %v (regenerate with make port-fixtures)", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("TR-064 fixture drifted; regenerate deliberately with make port-fixtures")
	}
}

func buildPortTR064Fixture(t *testing.T) portTR064Fixture {
	t.Helper()

	requests := []soapRequestVector{
		{
			ID:          "no-arguments",
			ServiceType: "urn:dslforum-org:service:DeviceInfo:1",
			Action:      "GetInfo",
			Args:        map[string]string{},
		},
		{
			ID:          "sorted-and-escaped-arguments",
			ServiceType: "urn:dslforum-org:service:Hosts:1",
			Action:      "X_Test",
			Args: map[string]string{
				"NewZulu":   "last",
				"NewAlpha":  `<tag attr="x">A&B's</tag>`,
				"NewMiddle": "Grüße",
			},
		},
	}
	for i := range requests {
		requests[i].Body = string(buildSOAPRequest(requests[i].ServiceType, requests[i].Action, requests[i].Args))
	}

	responses := []soapResponseVector{
		{
			ID:     "namespaced-values",
			Action: "GetInfo",
			XML:    `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:GetInfoResponse xmlns:u="urn:dslforum-org:service:DeviceInfo:1"><NewModelName>FRITZ!Box 7590 AX</NewModelName><NewSoftwareVersion>8.20</NewSoftwareVersion></u:GetInfoResponse></s:Body></s:Envelope>`,
		},
		{
			ID:     "empty-response",
			Action: "Reboot",
			XML:    `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:RebootResponse xmlns:u="urn:dslforum-org:service:DeviceConfig:1"></u:RebootResponse></s:Body></s:Envelope>`,
		},
		{
			ID:     "entities-and-cdata",
			Action: "GetInfo",
			XML:    `<GetInfoResponse><NewText>A&amp;B&#34;quoted&#34;</NewText><NewCDATA><![CDATA[<raw>]]></NewCDATA></GetInfoResponse>`,
		},
		{
			ID:     "nested-values-follow-go-state-machine",
			Action: "GetInfo",
			XML:    `<GetInfoResponse><Outer>before<Inner>inside</Inner>after</Outer></GetInfoResponse>`,
		},
		{
			ID:     "valid-without-action-response",
			Action: "GetInfo",
			XML:    `<Envelope><Body></Body></Envelope>`,
		},
		{ID: "malformed", Action: "GetInfo", XML: `<s:Envelope><GetInfoResponse>`, Error: true},
	}
	for i := range responses {
		output, err := parseSOAPResponse([]byte(responses[i].XML), responses[i].Action)
		if err != nil {
			responses[i].Error = true
			continue
		}
		responses[i].Output = output
	}

	faults := []soapFaultVector{
		{
			ID:  "upnp-invalid-args",
			XML: `<s:Fault><detail><UPnPError><errorCode>402</errorCode><errorDescription>Invalid Args</errorDescription></UPnPError></detail></s:Fault>`,
		},
		{
			ID:  "unauthorized-localized",
			XML: `<s:Fault><detail><UPnPError><errorCode>606</errorCode><errorDescription>Aktion nicht autorisiert</errorDescription></UPnPError></detail></s:Fault>`,
		},
		{
			ID:  "raw-fallback",
			XML: `<s:Fault><faultstring>No such entry</faultstring></s:Fault>`,
		},
	}
	for i := range faults {
		faults[i].Code, faults[i].Description = parseSOAPFault([]byte(faults[i].XML))
	}

	realDescriptionPath := filepath.Join(filepath.Dir(portTR064FixturePath(t)), "..", "..", "..", "internal", "fritz", "testdata", "tr64desc.xml")
	realDescription, err := os.ReadFile(realDescriptionPath)
	if err != nil {
		t.Fatal(err)
	}
	const nestedDescription = `<?xml version="1.0"?><root xmlns="urn:dslforum-org:device-1-0"><device><serviceList><service><serviceType>urn:test:service:Zulu:1</serviceType><controlURL>/zulu</controlURL></service></serviceList><deviceList><device><serviceList><service><serviceType>urn:test:service:Alpha:1</serviceType><controlURL>/alpha</controlURL></service></serviceList></device></deviceList></device></root>`
	discovery := []discoveryVector{
		{ID: "redacted-router-description", InputFile: "internal/fritz/testdata/tr64desc.xml"},
		{ID: "nested-and-sorted", XML: nestedDescription},
		{ID: "malformed", XML: `<root><device>`, Error: true},
	}
	for i := range discovery {
		var input []byte
		if discovery[i].InputFile != "" {
			input = realDescription
		} else {
			input = []byte(discovery[i].XML)
		}
		services, err := parseDiscoveryDescription(input)
		if err != nil {
			discovery[i].Error = true
			continue
		}
		discovery[i].Services = portServices(services)
	}

	realServices, err := parseDiscoveryDescription(realDescription)
	if err != nil {
		t.Fatal(err)
	}
	lookupInputs := []struct {
		id   string
		name string
	}{
		{"device-info", "DeviceInfo"},
		{"case-insensitive", "deviceinfo"},
		{"specific-wlan", "WLANConfiguration:2"},
		{"ambiguous", "X_AVM-DE"},
		{"missing", "NoSuchService"},
	}
	lookups := make([]serviceLookupVector, 0, len(lookupInputs))
	for _, input := range lookupInputs {
		service, err := findServiceByName(realServices, input.name)
		vector := serviceLookupVector{ID: input.id, Name: input.name}
		if err != nil {
			vector.Error = err.Error()
		} else {
			converted := portService(service)
			vector.Service = &converted
		}
		lookups = append(lookups, vector)
	}

	return portTR064Fixture{
		SchemaVersion: 1,
		Oracle:        "Go internal/fritz production SOAP and discovery functions",
		SOAPRequests:  requests,
		SOAPResponses: responses,
		SOAPFaults:    faults,
		Discovery:     discovery,
		ServiceLookup: lookups,
	}
}

func portServices(services []Service) []portService {
	result := make([]portService, 0, len(services))
	for _, service := range services {
		result = append(result, portService(service))
	}
	return result
}

func portTR064FixturePath(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve fixture source path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", "..", "testdata", "port", "tr064", "contracts.json"))
}
