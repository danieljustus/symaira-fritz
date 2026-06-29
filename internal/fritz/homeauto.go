package fritz

import (
	"context"
	"strconv"
)

// HomeautoDevice represents a smart home device queried via TR-064 Homeauto.
type HomeautoDevice struct {
	AIN             string
	FunctionBitMask int
	Manufacturer    string
	ProductName     string
	FirmwareVersion string
}

// Capabilities checks based on FunctionBitMask bit positions.
func (d HomeautoDevice) IsSwitch() bool {
	return (d.FunctionBitMask & (1 << 15)) != 0
}

func (d HomeautoDevice) IsThermostat() bool {
	return (d.FunctionBitMask & (1 << 6)) != 0
}

func (d HomeautoDevice) IsBulb() bool {
	return (d.FunctionBitMask & (1 << 2)) != 0
}

func (d HomeautoDevice) IsAlarmSensor() bool {
	return (d.FunctionBitMask & (1 << 4)) != 0
}

func (d HomeautoDevice) IsButton() bool {
	return (d.FunctionBitMask & (1 << 5)) != 0
}

func (d HomeautoDevice) IsBlind() bool {
	return (d.FunctionBitMask & (1 << 18)) != 0
}

func (d HomeautoDevice) IsEnergySensor() bool {
	return (d.FunctionBitMask & (1 << 7)) != 0
}

func (d HomeautoDevice) IsTemperatureSensor() bool {
	return (d.FunctionBitMask & (1 << 8)) != 0
}

// HomeautoDevices lists all smart-home devices via the TR-064 Homeauto API.
func (c *Client) HomeautoDevices(ctx context.Context) ([]HomeautoDevice, error) {
	var devices []HomeautoDevice
	for i := 0; ; i++ {
		res, err := c.Call(ctx, ServiceHomeauto, "GetGenericDeviceInfos", map[string]string{
			"NewIndex": strconv.Itoa(i),
		})
		if err != nil {
			// TR-064 returns error (e.g. ArrayIndexError) when index is out of bounds
			break
		}
		mask, _ := strconv.Atoi(res["NewFunctionBitMask"])
		devices = append(devices, HomeautoDevice{
			AIN:             res["NewAIN"],
			FunctionBitMask: mask,
			Manufacturer:    res["NewManufacturer"],
			ProductName:     res["NewProductName"],
			FirmwareVersion: res["NewFirmwareVersion"],
		})
	}
	return devices, nil
}

// HomeautoSwitch controls a smart-home switch actor via TR-064 Homeauto.
func (c *Client) HomeautoSwitch(ctx context.Context, ain string, on bool) error {
	state := "OFF"
	if on {
		state = "ON"
	}
	_, err := c.Call(ctx, ServiceHomeauto, "SetSwitch", map[string]string{
		"NewAIN":         ain,
		"NewSwitchState": state,
	})
	return err
}
