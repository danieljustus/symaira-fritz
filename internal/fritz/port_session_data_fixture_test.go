package fritz

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

type portSessionDataFixture struct {
	SchemaVersion int                `json:"schema_version"`
	Oracle        string             `json:"oracle"`
	SessionXML    []sessionXMLVector `json:"session_xml"`
	DataForms     []dataFormVector   `json:"data_forms"`
}

type sessionXMLVector struct {
	ID        string `json:"id"`
	XML       string `json:"xml"`
	SID       string `json:"sid,omitempty"`
	Challenge string `json:"challenge,omitempty"`
	BlockTime int    `json:"block_time,omitempty"`
	Error     string `json:"error,omitempty"`
}

type dataFormVector struct {
	ID     string              `json:"id"`
	Page   string              `json:"page"`
	SID    string              `json:"sid"`
	Params map[string][]string `json:"params"`
	Body   string              `json:"body"`
}

func TestPortSessionDataFixture(t *testing.T) {
	fixture := buildPortSessionDataFixture(t)
	got, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')

	path := portSessionDataFixturePath(t)
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
		t.Fatalf("read session/data fixture: %v (regenerate with make port-fixtures)", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("session/data fixture drifted; regenerate deliberately with make port-fixtures")
	}
}

func buildPortSessionDataFixture(t *testing.T) portSessionDataFixture {
	t.Helper()
	xmlInputs := []sessionXMLVector{
		{
			ID:  "ready-sid",
			XML: `<?xml version="1.0"?><SessionInfo><SID>0123456789abcdef</SID><Challenge>ignored</Challenge><BlockTime>0</BlockTime></SessionInfo>`,
		},
		{
			ID:  "invalid-sid-with-block-time",
			XML: `<SessionInfo><SID>0000000000000000</SID><Challenge>1234567z</Challenge><BlockTime>30</BlockTime></SessionInfo>`,
		},
		{
			ID:  "missing-optional-block-time",
			XML: `<SessionInfo><SID>0000000000000000</SID><Challenge>legacy</Challenge></SessionInfo>`,
		},
		{
			ID:    "malformed-xml",
			XML:   `<SessionInfo><SID>oops`,
			Error: "malformed XML",
		},
		{
			ID:    "malformed-block-time",
			XML:   `<SessionInfo><SID>sid</SID><BlockTime>later</BlockTime></SessionInfo>`,
			Error: "invalid block time",
		},
	}
	for i := range xmlInputs {
		var info sessionInfo
		if err := xml.Unmarshal([]byte(xmlInputs[i].XML), &info); err != nil {
			xmlInputs[i].Error = "malformed XML"
			continue
		}
		xmlInputs[i].SID = info.SID
		xmlInputs[i].Challenge = info.Challenge
		xmlInputs[i].BlockTime = info.BlockTime
	}

	formInputs := []dataFormVector{
		{
			ID:     "overview-extra",
			Page:   "overview",
			SID:    "0123456789abcdef",
			Params: map[string][]string{"foo": {"bar"}},
		},
		{
			ID:     "repeated-and-escaped",
			Page:   "a page",
			SID:    "sid+value",
			Params: map[string][]string{"z": {"one", "two"}, "a": {"x&y"}},
		},
	}
	for i := range formInputs {
		values := url.Values{
			"sid":  {formInputs[i].SID},
			"page": {formInputs[i].Page},
		}
		for key, entries := range formInputs[i].Params {
			for _, entry := range entries {
				values.Add(key, entry)
			}
		}
		formInputs[i].Body = values.Encode()
	}

	return portSessionDataFixture{
		SchemaVersion: 1,
		Oracle:        "Go internal/fritz session and scrape contracts",
		SessionXML:    xmlInputs,
		DataForms:     formInputs,
	}
}

func portSessionDataFixturePath(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve fixture source path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", "..", "testdata", "port", "session-data", "contracts.json"))
}
