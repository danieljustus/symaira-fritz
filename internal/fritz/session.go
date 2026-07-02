package fritz

import (
	"context"
	"crypto/md5"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf16"
)

// sessionInfo mirrors the XML returned by /login_sid.lua.
type sessionInfo struct {
	XMLName   xml.Name `xml:"SessionInfo"`
	SID       string   `xml:"SID"`
	Challenge string   `xml:"Challenge"`
	BlockTime int      `xml:"BlockTime"`
}

const invalidSID = "0000000000000000"

// SID returns a valid session id, performing the login challenge-response if
// the cached SID is empty or expired. It supports both the modern PBKDF2
// challenge (FRITZ!OS 7.24+) and the legacy MD5 challenge.
//
// The returned SID is required for AHA-HTTP calls and web-UI (data.lua)
// scraping. TR-064 uses HTTP digest auth instead and does not need it.
func (c *Client) SID(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.sid != "" && c.sid != invalidSID {
		return c.sid, nil
	}
	if strings.TrimSpace(c.Password) == "" {
		return "", ErrNoCredential
	}

	// Step 1: fetch a challenge.
	info, err := c.fetchSession(ctx, nil)
	if err != nil {
		return "", err
	}
	if info.SID != "" && info.SID != invalidSID {
		c.sid = info.SID
		return c.sid, nil
	}

	// Step 2: compute the response for the challenge.
	response, err := computeChallengeResponse(info.Challenge, c.Password)
	if err != nil {
		return "", err
	}

	// Step 3: send username + response to obtain a SID.
	info, err = c.fetchSession(ctx, url.Values{
		"username": {c.User},
		"response": {response},
	})
	if err != nil {
		return "", err
	}
	if info.SID == "" || info.SID == invalidSID {
		if info.BlockTime > 0 {
			return "", fmt.Errorf("login failed; box is rate-limiting for %ds (wrong password?)", info.BlockTime)
		}
		return "", fmt.Errorf("login failed: invalid credentials")
	}

	c.sid = info.SID
	return c.sid, nil
}

// fetchSession GETs /login_sid.lua (optionally with auth params) and parses it.
func (c *Client) fetchSession(ctx context.Context, params url.Values) (*sessionInfo, error) {
	u := c.baseHTTP() + "/login_sid.lua?version=2"
	if params != nil {
		u += "&" + params.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("contacting %s: %w", c.Host, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil, err
	}
	var info sessionInfo
	if err := xml.Unmarshal(body, &info); err != nil {
		return nil, fmt.Errorf("parsing login_sid.lua response: %w", err)
	}
	return &info, nil
}

// computeChallengeResponse builds the response string for a login challenge.
// It auto-detects the PBKDF2 ("2$…") and legacy MD5 variants.
func computeChallengeResponse(challenge, password string) (string, error) {
	if challenge == "" {
		return "", fmt.Errorf("empty challenge from box")
	}
	if strings.HasPrefix(challenge, "2$") {
		return pbkdf2Response(challenge, password)
	}
	return md5Response(challenge, password), nil
}

// pbkdf2Response implements the FRITZ!OS 7.24+ PBKDF2 challenge.
//
// Challenge format: 2$<iter1>$<salt1>$<iter2>$<salt2>
//
//	hash1    = pbkdf2_hmac_sha256(password, salt1, iter1)
//	response = salt2 + "$" + hex(pbkdf2_hmac_sha256(hash1, salt2, iter2))
func pbkdf2Response(challenge, password string) (string, error) {
	parts := strings.Split(challenge, "$")
	if len(parts) != 5 {
		return "", fmt.Errorf("malformed PBKDF2 challenge")
	}
	iter1, err1 := strconv.Atoi(parts[1])
	iter2, err2 := strconv.Atoi(parts[3])
	if err1 != nil || err2 != nil {
		return "", fmt.Errorf("malformed PBKDF2 iteration count")
	}
	salt1, err1 := hex.DecodeString(parts[2])
	salt2, err2 := hex.DecodeString(parts[4])
	if err1 != nil || err2 != nil {
		return "", fmt.Errorf("malformed PBKDF2 salt")
	}

	hash1, err := pbkdf2.Key(sha256.New, password, salt1, iter1, 32)
	if err != nil {
		return "", err
	}
	hash2, err := pbkdf2.Key(sha256.New, string(hash1), salt2, iter2, 32)
	if err != nil {
		return "", err
	}
	return parts[4] + "$" + hex.EncodeToString(hash2), nil
}

// md5Response implements the legacy challenge:
//
//	response = challenge + "-" + md5_hex(utf16le(challenge + "-" + password))
func md5Response(challenge, password string) string {
	clear := challenge + "-" + password
	// FRITZ!OS hashes the UTF-16LE encoding of the string.
	u16 := utf16.Encode([]rune(clear))
	buf := make([]byte, 0, len(u16)*2)
	for _, r := range u16 {
		buf = append(buf, byte(r), byte(r>>8))
	}
	sum := md5.Sum(buf)
	return challenge + "-" + hex.EncodeToString(sum[:])
}
