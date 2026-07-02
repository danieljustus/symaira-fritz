package fritz

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMeshTopology_ParsesNodesAndLinks(t *testing.T) {
	topo := MeshTopology{
		SchemaVersion: "1.0",
		Nodes: []MeshNode{
			{
				UID: "n1", DeviceName: "FRITZ!Box 7590", DeviceModel: "FB7590",
				IsMeshed: true, MeshRole: "master",
				Interfaces: []MeshInterface{
					{
						UID: "n1-lan", Name: "LAN Bridge", Type: "LAN",
						Links: []MeshLink{
							{State: "CONNECTED", Node1: "n1-lan", Node2: "n2-wlan",
								MaxDataRateRx: 1000, MaxDataRateTx: 1000,
								CurDataRateRx: 500, CurDataRateTx: 400},
						},
					},
				},
			},
			{
				UID: "n2", DeviceName: "FRITZ!Repeater 1200", DeviceModel: "FB1200",
				IsMeshed: true, MeshRole: "slave",
				Interfaces: []MeshInterface{
					{UID: "n2-wlan", Name: "WLAN", Type: "WLAN", Links: nil},
				},
			},
		},
	}
	jsonBody, err := json.Marshal(topo)
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost:
			// SOAP call for X_AVM-DE_GetMeshListPath
			action := r.Header.Get("SoapAction")
			if strings.Contains(action, "X_AVM-DE_GetMeshListPath") {
				w.Header().Set("Content-Type", `text/xml; charset="utf-8"`)
				_, _ = io.WriteString(w, soapEnvelope("X_AVM-DE_GetMeshListPath",
					map[string]string{"NewX_AVM-DE_MeshListPath": "/mesh.json"}))
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
		case r.URL.Path == "/login_sid.lua":
			_, _ = w.Write([]byte(`<?xml version="1.0"?><SessionInfo><SID>meshsid00000000</SID><Challenge>x</Challenge><BlockTime>0</BlockTime></SessionInfo>`))
		case r.URL.Path == "/mesh.json":
			w.Header().Set("Content-Type", "application/json")
			w.Write(jsonBody)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c := New("fritz.box", WithPassword("secret"))
	c.tr064BaseURL = srv.URL
	c.httpBaseURL = srv.URL

	result, err := c.MeshTopology(context.Background())
	if err != nil {
		t.Fatalf("MeshTopology: %v", err)
	}
	if result.SchemaVersion != "1.0" {
		t.Errorf("SchemaVersion = %q", result.SchemaVersion)
	}
	if len(result.Nodes) != 2 {
		t.Fatalf("want 2 nodes, got %d", len(result.Nodes))
	}
	if result.Nodes[0].DeviceName != "FRITZ!Box 7590" {
		t.Errorf("node0 = %q", result.Nodes[0].DeviceName)
	}
	if !result.Nodes[0].IsMeshed {
		t.Error("node0 should be meshed")
	}
	if result.Nodes[0].MeshRole != "master" {
		t.Errorf("node0 role = %q", result.Nodes[0].MeshRole)
	}
	if len(result.Nodes[0].Interfaces) != 1 {
		t.Fatalf("node0 interfaces = %d, want 1", len(result.Nodes[0].Interfaces))
	}
	if result.Nodes[0].Interfaces[0].Type != "LAN" {
		t.Errorf("interface type = %q", result.Nodes[0].Interfaces[0].Type)
	}
	if len(result.Nodes[0].Interfaces[0].Links) != 1 {
		t.Fatalf("node0 links = %d, want 1", len(result.Nodes[0].Interfaces[0].Links))
	}
	link := result.Nodes[0].Interfaces[0].Links[0]
	if link.State != "CONNECTED" {
		t.Errorf("link state = %q", link.State)
	}
	if link.CurDataRateRx != 500 {
		t.Errorf("link CurDataRateRx = %d", link.CurDataRateRx)
	}
}

func TestMeshTopology_FetchesRelativePathFromTR064Port(t *testing.T) {
	jsonBody := []byte(`{"schema_version":"7.8","nodes":[{"uid":"n-1","device_name":"FRITZ!Box 4060"}]}`)

	webSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer webSrv.Close()

	tr064Srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost:
			w.Header().Set("Content-Type", `text/xml; charset="utf-8"`)
			_, _ = io.WriteString(w, soapEnvelope("X_AVM-DE_GetMeshListPath",
				map[string]string{"NewX_AVM-DE_MeshListPath": "/meshlist.lua?sid=from-soap"}))
		case r.URL.Path == "/meshlist.lua":
			if r.URL.Query().Get("sid") != "from-soap" {
				t.Errorf("sid = %q, want from-soap", r.URL.Query().Get("sid"))
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(jsonBody)
		default:
			http.NotFound(w, r)
		}
	}))
	defer tr064Srv.Close()

	c := New("fritz.box", WithPassword("secret"))
	c.tr064BaseURL = tr064Srv.URL
	c.httpBaseURL = webSrv.URL

	result, err := c.MeshTopology(context.Background())
	if err != nil {
		t.Fatalf("MeshTopology: %v", err)
	}
	if len(result.Nodes) != 1 || result.Nodes[0].DeviceName != "FRITZ!Box 4060" {
		t.Fatalf("unexpected topology: %+v", result)
	}
}

func TestMeshTopology_EmptyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.Header().Set("Content-Type", `text/xml; charset="utf-8"`)
			_, _ = io.WriteString(w, soapEnvelope("X_AVM-DE_GetMeshListPath",
				map[string]string{"NewX_AVM-DE_MeshListPath": ""}))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	c := New("fritz.box", WithPassword("secret"))
	c.tr064BaseURL = srv.URL
	c.httpBaseURL = srv.URL

	_, err := c.MeshTopology(context.Background())
	if err == nil {
		t.Fatal("expected error for empty mesh path")
	}
	if !strings.Contains(err.Error(), "no mesh list path") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestMeshTopology_JSONFetchError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost:
			w.Header().Set("Content-Type", `text/xml; charset="utf-8"`)
			_, _ = io.WriteString(w, soapEnvelope("X_AVM-DE_GetMeshListPath",
				map[string]string{"NewX_AVM-DE_MeshListPath": "/mesh.json"}))
		case r.URL.Path == "/login_sid.lua":
			_, _ = w.Write([]byte(`<?xml version="1.0"?><SessionInfo><SID>meshsid00000000</SID><Challenge>x</Challenge><BlockTime>0</BlockTime></SessionInfo>`))
		case r.URL.Path == "/mesh.json":
			w.WriteHeader(http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c := New("fritz.box", WithPassword("secret"))
	c.tr064BaseURL = srv.URL
	c.httpBaseURL = srv.URL

	_, err := c.MeshTopology(context.Background())
	if err == nil {
		t.Fatal("expected error for HTTP 500 from mesh JSON endpoint")
	}
	if !strings.Contains(err.Error(), "HTTP 500") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestMeshTopology_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost:
			w.Header().Set("Content-Type", `text/xml; charset="utf-8"`)
			_, _ = io.WriteString(w, soapEnvelope("X_AVM-DE_GetMeshListPath",
				map[string]string{"NewX_AVM-DE_MeshListPath": "/mesh.json"}))
		case r.URL.Path == "/login_sid.lua":
			_, _ = w.Write([]byte(`<?xml version="1.0"?><SessionInfo><SID>meshsid00000000</SID><Challenge>x</Challenge><BlockTime>0</BlockTime></SessionInfo>`))
		case r.URL.Path == "/mesh.json":
			_, _ = w.Write([]byte(`{not valid json`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c := New("fritz.box", WithPassword("secret"))
	c.tr064BaseURL = srv.URL
	c.httpBaseURL = srv.URL

	_, err := c.MeshTopology(context.Background())
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	if !strings.Contains(err.Error(), "parsing mesh list JSON") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestNodeName_Found(t *testing.T) {
	topo := &MeshTopology{
		Nodes: []MeshNode{
			{UID: "n1", DeviceName: "Box"},
			{UID: "n2", DeviceName: "Repeater", Interfaces: []MeshInterface{
				{UID: "n2-if"},
			}},
		},
	}
	if name := topo.NodeName("n1"); name != "Box" {
		t.Errorf("NodeName(n1) = %q, want Box", name)
	}
	if name := topo.NodeName("n2-if"); name != "Repeater" {
		t.Errorf("NodeName(n2-if) = %q, want Repeater", name)
	}
}

func TestNodeName_NotFound(t *testing.T) {
	topo := &MeshTopology{Nodes: []MeshNode{{UID: "n1"}}}
	if name := topo.NodeName("unknown"); name != "unknown" {
		t.Errorf("NodeName(unknown) = %q, want uid passthrough", name)
	}
}
