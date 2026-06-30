package fritz

import "testing"

func TestHomeautoDevice_TypeChecks(t *testing.T) {
	tests := []struct {
		name     string
		mask     int
		method   func(HomeautoDevice) bool
		wantTrue bool
	}{
		{"IsThermostat set", 1 << 6, func(d HomeautoDevice) bool { return d.IsThermostat() }, true},
		{"IsThermostat unset", 0, func(d HomeautoDevice) bool { return d.IsThermostat() }, false},
		{"IsBulb set", 1 << 2, func(d HomeautoDevice) bool { return d.IsBulb() }, true},
		{"IsBulb unset", 0, func(d HomeautoDevice) bool { return d.IsBulb() }, false},
		{"IsAlarmSensor set", 1 << 4, func(d HomeautoDevice) bool { return d.IsAlarmSensor() }, true},
		{"IsAlarmSensor unset", 0, func(d HomeautoDevice) bool { return d.IsAlarmSensor() }, false},
		{"IsButton set", 1 << 5, func(d HomeautoDevice) bool { return d.IsButton() }, true},
		{"IsButton unset", 0, func(d HomeautoDevice) bool { return d.IsButton() }, false},
		{"IsBlind set", 1 << 18, func(d HomeautoDevice) bool { return d.IsBlind() }, true},
		{"IsBlind unset", 0, func(d HomeautoDevice) bool { return d.IsBlind() }, false},
		{"IsEnergySensor set", 1 << 7, func(d HomeautoDevice) bool { return d.IsEnergySensor() }, true},
		{"IsEnergySensor unset", 0, func(d HomeautoDevice) bool { return d.IsEnergySensor() }, false},
		{"IsTemperatureSensor set", 1 << 8, func(d HomeautoDevice) bool { return d.IsTemperatureSensor() }, true},
		{"IsTemperatureSensor unset", 0, func(d HomeautoDevice) bool { return d.IsTemperatureSensor() }, false},
		{"IsSwitch set", 1 << 15, func(d HomeautoDevice) bool { return d.IsSwitch() }, true},
		{"IsSwitch unset", 0, func(d HomeautoDevice) bool { return d.IsSwitch() }, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := HomeautoDevice{FunctionBitMask: tt.mask}
			got := tt.method(d)
			if got != tt.wantTrue {
				t.Errorf("FunctionBitMask=%#x: got %v, want %v", tt.mask, got, tt.wantTrue)
			}
		})
	}
}

func TestHomeautoDevice_MultipleCapabilities(t *testing.T) {
	// Thermostat (bit 6) + TemperatureSensor (bit 8)
	d := HomeautoDevice{FunctionBitMask: (1 << 6) | (1 << 8)}
	if !d.IsThermostat() {
		t.Error("expected IsThermostat")
	}
	if !d.IsTemperatureSensor() {
		t.Error("expected IsTemperatureSensor")
	}
	if d.IsBulb() {
		t.Error("should not be IsBulb")
	}
	if d.IsSwitch() {
		t.Error("should not be IsSwitch")
	}
}
