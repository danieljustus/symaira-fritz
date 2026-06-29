package fritz

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/url"
	"time"
)

// LogEvent represents a single event entry in the FRITZ!Box device log.
type LogEvent struct {
	ID    string
	Group string
	Time  time.Time
	Msg   string
}

// DeviceLog retrieves the system event log from the box.
func (c *Client) DeviceLog(ctx context.Context, filter string) ([]LogEvent, error) {
	resp, err := c.Call(ctx, ServiceDeviceInfo, "X_AVM-DE_GetDeviceLogPath", nil)
	if err != nil {
		return nil, err
	}
	path := resp["NewDeviceLogPath"]
	if path == "" {
		return nil, fmt.Errorf("tr064: GetDeviceLogPath returned empty path")
	}

	u, err := url.Parse(c.tr064Base() + path)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	if filter != "" && filter != "all" {
		q.Set("filter", filter)
	}
	u.RawQuery = q.Encode()

	xmlData, err := c.fetchAuthenticatedURL(ctx, u.String())
	if err != nil {
		return nil, err
	}

	type XmlEvent struct {
		ID    string `xml:"id"`
		Group string `xml:"group"`
		Date  string `xml:"date"`
		Time  string `xml:"time"`
		Msg   string `xml:"msg"`
	}
	type XmlDeviceLog struct {
		XMLName xml.Name   `xml:"DeviceLog"`
		Events  []XmlEvent `xml:"Event"`
	}

	var log XmlDeviceLog
	if err := xml.Unmarshal(xmlData, &log); err != nil {
		return nil, err
	}

	var result []LogEvent
	for _, xe := range log.Events {
		result = append(result, LogEvent{
			ID:    xe.ID,
			Group: xe.Group,
			Time:  parseLogTime(xe.Date, xe.Time),
			Msg:   xe.Msg,
		})
	}
	return result, nil
}

func parseLogTime(dStr, tStr string) time.Time {
	s := dStr + " " + tStr
	layouts := []string{
		"02.01.06 15:04:05",
		"02.01.2006 15:04:05",
		"02.01.06 15:04",
		"02.01.2006 15:04",
	}
	for _, layout := range layouts {
		if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
			return t
		}
	}
	return time.Time{}
}
