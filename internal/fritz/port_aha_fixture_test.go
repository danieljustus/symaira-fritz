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

type portAHAFixture struct {
	SchemaVersion int               `json:"schema_version"`
	Oracle        string            `json:"oracle"`
	DeviceXML     []ahaDeviceVector `json:"device_xml"`
	HomeQueries   []ahaQueryVector  `json:"home_queries"`
	HkrParams     []ahaHkrVector    `json:"hkr_params"`
}

type ahaDeviceVector struct {
	ID       string            `json:"id"`
	XML      string            `json:"xml"`
	Devices  []ahaDevice       `json:"devices"`
	Groups   []ahaGroup        `json:"groups"`
	NamesAIN map[string]string `json:"names_and_ains"`
}

type ahaDevice struct {
	Identifier string     `json:"identifier"`
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Present    int        `json:"present"`
	Switch     string     `json:"switch"`
	Celsius    string     `json:"celsius"`
	Tist       string     `json:"tist"`
	Tsoll      string     `json:"tsoll"`
	BatteryLow string     `json:"batterylow"`
	Battery    string     `json:"battery"`
	WindowOpen string     `json:"windowopenactiv"`
	ErrorCode  string     `json:"errorcode"`
	NextChange NextChange `json:"nextchange"`
	Power      string     `json:"power"`
	Energy     string     `json:"energy"`
}

type ahaGroup struct {
	Identifier string   `json:"identifier"`
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Members    []string `json:"members"`
	Master     string   `json:"master_device_id"`
}

type ahaQueryVector struct {
	ID        string              `json:"id"`
	SID       string              `json:"sid"`
	Switchcmd string              `json:"switchcmd"`
	Params    map[string][]string `json:"params"`
	URL       string              `json:"url"`
}

type ahaHkrVector struct {
	ID    string  `json:"id"`
	Temp  float64 `json:"temp_celsius"`
	Param string  `json:"param"`
}

func TestPortAHAFixture(t *testing.T) {
	fixture := buildPortAHAFixture(t)
	got, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	path := portAHAFixturePath(t)
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
		t.Fatalf("read AHA fixture: %v (regenerate with make port-aha-fixtures)", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("AHA fixture drifted; regenerate deliberately with make port-aha-fixtures")
	}
}

func buildPortAHAFixture(t *testing.T) portAHAFixture {
	t.Helper()
	xmlInput := `<?xml version="1.0"?><devicelist version="1"><device identifier="ain-1" id="0"><name>Plug</name><present>1</present><switch><state>1</state></switch><temperature><celsius>235</celsius></temperature><hkr><tist>44</tist><tsoll>42</tsoll><batterylow>0</batterylow><battery>90</battery><windowopenactiv>0</windowopenactiv><errorcode>0</errorcode><nextchange><end>1700000000</end><start>1699990000</start><tchange>60</tchange></nextchange></hkr><powermeter><power>12</power><energy>34</energy></powermeter></device><group identifier="group-1" id="g"><name>All</name><groupinfo><masterdeviceid>ain-1</masterdeviceid><members>ain-1,ain-2,</members></groupinfo></group></devicelist>`
	var list DeviceList
	if err := xml.Unmarshal([]byte(xmlInput), &list); err != nil {
		t.Fatal(err)
	}
	device := list.Devices[0]
	group := list.Groups[0]
	queries := []ahaQueryVector{
		{ID: "switch", SID: "sid+value", Switchcmd: "setswitchon", Params: map[string][]string{"ain": {"ain-1"}}},
		{ID: "repeated", SID: "sid", Switchcmd: "getdevicelistinfos", Params: map[string][]string{"foo": {"a b", "x&y"}}},
	}
	for i := range queries {
		queries[i].URL = buildAHAURL("http://fritz.box", queries[i].SID, queries[i].Switchcmd, url.Values(queries[i].Params))
	}
	return portAHAFixture{
		SchemaVersion: 1,
		Oracle:        "Go internal/fritz AHA Home and Homeauto contracts",
		DeviceXML: []ahaDeviceVector{{
			ID:       "device-list",
			XML:      xmlInput,
			Devices:  []ahaDevice{{Identifier: device.Identifier, ID: device.ID, Name: device.Name, Present: device.Present, Switch: device.Switch.State, Celsius: device.Temperature.Celsius, Tist: device.Hkr.Tist, Tsoll: device.Hkr.Tsoll, BatteryLow: device.Hkr.BatteryLow, Battery: device.Hkr.BatteryCharge, WindowOpen: device.Hkr.WindowOpen, ErrorCode: device.Hkr.ErrorCode, NextChange: device.Hkr.NextChange, Power: device.PowerMeter.Power, Energy: device.PowerMeter.Energy}},
			Groups:   []ahaGroup{{Identifier: group.Identifier, ID: group.ID, Name: group.Name, Members: group.Members, Master: group.GroupInfo.MasterDeviceID}},
			NamesAIN: list.NamesAndAins(),
		}},
		HomeQueries: queries,
		HkrParams:   []ahaHkrVector{{ID: "half-degree", Temp: 20.5, Param: hkrTempParam(20.5)}, {ID: "on", Temp: 254, Param: hkrTempParam(254)}, {ID: "off", Temp: 253, Param: hkrTempParam(253)}},
	}
}

func portAHAFixturePath(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve fixture source path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", "..", "testdata", "port", "aha", "contracts.json"))
}
