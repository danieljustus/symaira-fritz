package fritz

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// CallType represents the type of call (incoming, outgoing, missed, rejected).
type CallType int

const (
	CallAll      CallType = 0
	CallIncoming CallType = 1
	CallMissed   CallType = 2
	CallOutgoing CallType = 3
	CallRejected CallType = 10
)

// Call represents a call entry from the FRITZ!Box call list.
type Call struct {
	Type         CallType
	Date         time.Time
	Caller       string
	CallerNumber string
	CalledNumber string
	Name         string
	Duration     time.Duration
}

// Calls fetches the call list and filters by type, limit (max), and days.
func (c *Client) Calls(ctx context.Context, typ CallType, max int, days int) ([]Call, error) {
	resp, err := c.Call(ctx, ServiceOnTel, "GetCallList", nil)
	if err != nil {
		return nil, err
	}
	rawURL := resp["NewCallListURL"]
	if rawURL == "" {
		return nil, fmt.Errorf("tr064: GetCallList returned empty NewCallListURL")
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	if days > 0 {
		q.Set("days", strconv.Itoa(days))
	}
	if max > 0 {
		q.Set("max", strconv.Itoa(max))
	}
	u.RawQuery = q.Encode()

	xmlData, err := c.fetchAuthenticatedURL(ctx, u.String())
	if err != nil {
		return nil, err
	}

	type XmlCall struct {
		Type     int    `xml:"Type"`
		Caller   string `xml:"Caller"`
		Called   string `xml:"Called"`
		Name     string `xml:"Name"`
		Date     string `xml:"Date"`
		Duration string `xml:"Duration"`
	}
	type XmlCallList struct {
		XMLName xml.Name  `xml:"CallList"`
		Calls   []XmlCall `xml:"Call"`
	}

	var list XmlCallList
	if err := xml.Unmarshal(xmlData, &list); err != nil {
		return nil, err
	}

	var result []Call
	for _, xc := range list.Calls {
		ct := CallType(xc.Type)
		if typ != CallAll && ct != typ {
			continue
		}
		caller := xc.Name
		if caller == "" {
			caller = xc.Caller
		}
		result = append(result, Call{
			Type:         ct,
			Date:         parseDate(xc.Date),
			Caller:       caller,
			CallerNumber: xc.Caller,
			CalledNumber: xc.Called,
			Name:         xc.Name,
			Duration:     parseDuration(xc.Duration),
		})
	}
	return result, nil
}

// Dial instructs the FRITZ!Box to dial a number.
func (c *Client) Dial(ctx context.Context, number string) error {
	_, err := c.Call(ctx, ServiceVoIP, "X_AVM-DE_DialNumber", map[string]string{
		"NewX_AVM-DE_PhoneNumber": number,
	})
	return err
}

// Hangup hangs up any active call initiated by Dial.
func (c *Client) Hangup(ctx context.Context) error {
	_, err := c.Call(ctx, ServiceVoIP, "X_AVM-DE_DialHangup", nil)
	return err
}

func parseDate(s string) time.Time {
	layouts := []string{
		"02.01.06 15:04",
		"02.01.2006 15:04",
		"2006-01-02 15:04:05",
	}
	for _, layout := range layouts {
		if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
			return t
		}
	}
	return time.Time{}
}

func parseDuration(s string) time.Duration {
	if strings.Contains(s, ":") {
		parts := strings.Split(s, ":")
		if len(parts) == 2 {
			m, _ := strconv.Atoi(parts[0])
			sec, _ := strconv.Atoi(parts[1])
			return time.Duration(m)*time.Minute + time.Duration(sec)*time.Second
		} else if len(parts) == 3 {
			h, _ := strconv.Atoi(parts[0])
			m, _ := strconv.Atoi(parts[1])
			sec, _ := strconv.Atoi(parts[2])
			return time.Duration(h)*time.Hour + time.Duration(m)*time.Minute + time.Duration(sec)*time.Second
		}
	}
	if sec, err := strconv.Atoi(s); err == nil {
		return time.Duration(sec) * time.Second
	}
	return 0
}
