package fritz

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewFeatures(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/xml; charset=utf-8")

		// 1. query.lua (CPU temp POST)
		if strings.Contains(r.URL.Path, "query.lua") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"CPUTEMP": "41,42,43,44"}`)
			return
		}

		// 2. call list XML download
		if strings.Contains(r.URL.Path, "calls.xml") {
			_, _ = io.WriteString(w, `<CallList>
				<Call>
					<Type>1</Type>
					<Caller>01712345</Caller>
					<Called>089123</Called>
					<Name>Alice</Name>
					<Date>29.06.26 14:15</Date>
					<Duration>0:15</Duration>
				</Call>
			</CallList>`)
			return
		}

		// 3. log XML download
		if strings.Contains(r.URL.Path, "devicelog.lua") {
			_, _ = io.WriteString(w, `<DeviceLog>
				<Event>
					<id>10</id>
					<group>sys</group>
					<date>29.06.26</date>
					<time>14:15:00</time>
					<msg>System started</msg>
				</Event>
			</DeviceLog>`)
			return
		}

		// 4. AHA getdevicelistinfos
		if strings.Contains(r.URL.Path, "homeautoswitch.lua") {
			w.Header().Set("Content-Type", "text/xml")
			_, _ = io.WriteString(w, `<devicelist>
				<device identifier="111" present="1">
					<name>HKR 1</name>
					<temperature><celsius>210</celsius></temperature>
					<hkr>
						<tist>42</tist>
						<tsoll>40</tsoll>
						<batterylow>0</batterylow>
						<battery>90</battery>
						<windowopenactiv>1</windowopenactiv>
						<errorcode>3</errorcode>
						<nextchange>
							<end>1483228800</end>
							<start>1483232400</start>
							<tchange>38</tchange>
						</nextchange>
					</hkr>
					<powermeter>
						<power>1200</power>
						<energy>500</energy>
					</powermeter>
				</device>
				<group identifier="900" id="900">
					<name>MyGroup</name>
					<groupinfo>
						<masterdeviceid>111</masterdeviceid>
						<members>111,112</members>
					</groupinfo>
				</group>
			</devicelist>`)
			return
		}

		// 5. TR-064 Soap actions
		sa := r.Header.Get("SoapAction")
		bodyBytes, _ := io.ReadAll(r.Body)
		body := string(bodyBytes)

		// WANCommonInterfaceConfig: GetOnlineMonitor
		if strings.Contains(sa, "X_AVM-DE_GetOnlineMonitor") {
			_, _ = io.WriteString(w, soapEnvelope("X_AVM-DE_GetOnlineMonitor", map[string]string{
				"Newds_current_bps":    "1000,2000",
				"Newmc_current_bps":    "100,200",
				"Newds_guest_bps":      "10,20",
				"Newprio_realtime_bps": "5,5",
				"Newprio_high_bps":     "2,2",
				"Newprio_default_bps":  "1,1",
				"Newprio_low_bps":      "0,0",
				"Newus_guest_bps":      "0,0",
			}))
			return
		}

		// WANDSLInterfaceConfig: GetInfo
		if strings.Contains(sa, "WANDSLInterfaceConfig") && strings.Contains(sa, "GetInfo") {
			_, _ = io.WriteString(w, soapEnvelope("GetInfo", map[string]string{
				"NewUpstreamNoiseMargin":   "60",
				"NewDownstreamNoiseMargin": "80",
				"NewUpstreamAttenuation":   "150",
				"NewDownstreamAttenuation": "180",
			}))
			return
		}

		// WANCommonInterfaceConfig: GetCommonLinkProperties
		if strings.Contains(sa, "GetCommonLinkProperties") {
			_, _ = io.WriteString(w, soapEnvelope("GetCommonLinkProperties", map[string]string{
				"NewLayer1UpstreamMaxBitRate":   "40000000",
				"NewLayer1DownstreamMaxBitRate": "100000000",
			}))
			return
		}

		// Homeauto: GetGenericDeviceInfos (TR-064)
		if strings.Contains(sa, "GetGenericDeviceInfos") {
			if strings.Contains(body, "<NewIndex>0</NewIndex>") {
				_, _ = io.WriteString(w, soapEnvelope("GetGenericDeviceInfos", map[string]string{
					"NewAIN":             "12345",
					"NewFunctionBitMask": "32768", // 1 << 15 (Switch)
					"NewManufacturer":    "AVM",
					"NewProductName":     "FRITZ!DECT 200",
					"NewFirmwareVersion": "04.16",
				}))
			} else {
				// return SOAP fault to end the loop
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = io.WriteString(w, `<soap:Envelope><soap:Body><soap:Fault><faultcode>Client</faultcode><faultstring>Index out of bounds</faultstring></soap:Fault></soap:Body></soap:Envelope>`)
			}
			return
		}

		// Homeauto: SetSwitch
		if strings.Contains(sa, "SetSwitch") {
			_, _ = io.WriteString(w, soapEnvelope("SetSwitch", nil))
			return
		}

		// VoIP: DialNumber
		if strings.Contains(sa, "X_AVM-DE_DialNumber") {
			_, _ = io.WriteString(w, soapEnvelope("X_AVM-DE_DialNumber", nil))
			return
		}

		// VoIP: DialHangup
		if strings.Contains(sa, "X_AVM-DE_DialHangup") {
			_, _ = io.WriteString(w, soapEnvelope("X_AVM-DE_DialHangup", nil))
			return
		}

		// OnTel: GetCallList
		if strings.Contains(sa, "GetCallList") {
			_, _ = io.WriteString(w, soapEnvelope("GetCallList", map[string]string{
				"NewCallListURL": "http://" + r.Host + "/calls.xml",
			}))
			return
		}

		// DeviceInfo: GetDeviceLogPath
		if strings.Contains(sa, "X_AVM-DE_GetDeviceLogPath") {
			_, _ = io.WriteString(w, soapEnvelope("X_AVM-DE_GetDeviceLogPath", map[string]string{
				"NewDeviceLogPath": "/devicelog.lua",
			}))
			return
		}

		// UserInterface: GetInfo
		if strings.Contains(sa, "UserInterface") && strings.Contains(sa, "GetInfo") {
			_, _ = io.WriteString(w, soapEnvelope("GetInfo", map[string]string{
				"NewUpgradeAvailable": "1",
				"NewX_AVM-DE_Version": "7.58",
			}))
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	c := New("fritz.box")
	c.SetMockURLs(srv.URL)
	c.sid = "mock-sid"

	ctx := context.Background()

	// 1. OnlineMonitor
	traffic, err := c.OnlineMonitor(ctx)
	if err != nil {
		t.Fatalf("OnlineMonitor failed: %v", err)
	}
	if len(traffic.DownstreamInternet) != 2 || traffic.DownstreamInternet[0] != 1000 {
		t.Errorf("unexpected DownstreamInternet: %v", traffic.DownstreamInternet)
	}

	// 2. DSLLineStats
	dsl, err := c.DSLLineStats(ctx)
	if err != nil {
		t.Fatalf("DSLLineStats failed: %v", err)
	}
	if dsl.UpstreamNoiseMargin != 60 || dsl.DownstreamMaxBitRate != 100000000 {
		t.Errorf("unexpected dsl stats: %+v", dsl)
	}

	// 3. Homeauto (TR-064)
	homeDevs, err := c.HomeautoDevices(ctx)
	if err != nil {
		t.Fatalf("HomeautoDevices failed: %v", err)
	}
	if len(homeDevs) != 1 || homeDevs[0].AIN != "12345" || !homeDevs[0].IsSwitch() {
		t.Errorf("unexpected home devices: %+v", homeDevs)
	}
	if err := c.HomeautoSwitch(ctx, "12345", true); err != nil {
		t.Fatalf("HomeautoSwitch failed: %v", err)
	}

	// 4. Phone
	calls, err := c.Calls(ctx, CallAll, 0, 0)
	if err != nil {
		t.Fatalf("Calls failed: %v", err)
	}
	if len(calls) != 1 || calls[0].Caller != "Alice" {
		t.Errorf("unexpected calls: %+v", calls)
	}
	if err := c.Dial(ctx, "123"); err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	if err := c.Hangup(ctx); err != nil {
		t.Fatalf("Hangup failed: %v", err)
	}

	// 5. DeviceLog
	logs, err := c.DeviceLog(ctx, "sys")
	if err != nil {
		t.Fatalf("DeviceLog failed: %v", err)
	}
	if len(logs) != 1 || logs[0].Msg != "System started" {
		t.Errorf("unexpected logs: %+v", logs)
	}

	// 6. UpdateAvailable
	upd, err := c.UpdateAvailable(ctx)
	if err != nil {
		t.Fatalf("UpdateAvailable failed: %v", err)
	}
	if upd != "7.58" {
		t.Errorf("expected update to be 7.58, got %q", upd)
	}

	// 7. CPUTemperatures
	temps, err := c.CPUTemperatures(ctx)
	if err != nil {
		t.Fatalf("CPUTemperatures failed: %v", err)
	}
	if len(temps) != 4 || temps[0] != 41 {
		t.Errorf("unexpected cpu temps: %v", temps)
	}

	// 8. AHA Devices & Groups
	devices, err := c.Devices(ctx)
	if err != nil {
		t.Fatalf("AHA Devices failed: %v", err)
	}
	if len(devices) != 1 || devices[0].Hkr.WindowOpen != "1" || devices[0].PowerMeter.Power != "1200" {
		t.Errorf("unexpected AHA device: %+v", devices[0])
	}
	if devices[0].Hkr.ErrorCode != "3" {
		t.Errorf("expected error code 3, got %q", devices[0].Hkr.ErrorCode)
	}

	groups, err := c.Groups(ctx)
	if err != nil {
		t.Fatalf("AHA Groups failed: %v", err)
	}
	if len(groups) != 1 || groups[0].Name != "MyGroup" || len(groups[0].Members) != 2 {
		t.Errorf("unexpected AHA group: %+v", groups[0])
	}

	var list DeviceList
	list.Devices = devices
	list.Groups = groups
	m := list.NamesAndAins()
	if m["HKR 1"] != "111" || m["MyGroup"] != "900" {
		t.Errorf("unexpected NamesAndAins output: %v", m)
	}
}
