package fritz

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"strings"
)

// digestChallenge holds the fields parsed from a WWW-Authenticate: Digest header.
type digestChallenge struct {
	realm     string
	nonce     string
	qop       string
	algorithm string
	opaque    string
}

// parseDigestChallenge parses a "Digest realm=…, nonce=…, …" header value.
func parseDigestChallenge(header string) (digestChallenge, bool) {
	const prefix = "Digest "
	idx := strings.Index(header, prefix)
	if idx < 0 {
		return digestChallenge{}, false
	}
	var dc digestChallenge
	for _, part := range splitDigestFields(header[idx+len(prefix):]) {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.Trim(strings.TrimSpace(v), `"`)
		switch k {
		case "realm":
			dc.realm = v
		case "nonce":
			dc.nonce = v
		case "qop":
			dc.qop = v
		case "algorithm":
			dc.algorithm = v
		case "opaque":
			dc.opaque = v
		}
	}
	return dc, dc.nonce != ""
}

// splitDigestFields splits on commas that are not inside quoted strings.
func splitDigestFields(s string) []string {
	var out []string
	var b strings.Builder
	inQuote := false
	for _, r := range s {
		switch {
		case r == '"':
			inQuote = !inQuote
			b.WriteRune(r)
		case r == ',' && !inQuote:
			out = append(out, b.String())
			b.Reset()
		default:
			b.WriteRune(r)
		}
	}
	if b.Len() > 0 {
		out = append(out, b.String())
	}
	return out
}

// digestAuthHeader builds an Authorization header value for HTTP Digest auth.
// FRITZ!Box TR-064 uses qop="auth" with MD5; a fixed client nonce is acceptable
// because each request fetches a fresh server nonce (nc is always 00000001).
func digestAuthHeader(dc digestChallenge, user, password, method, uri string) string {
	const cnonce = "0a4f113b"
	const nc = "00000001"

	ha1 := md5hex(user + ":" + dc.realm + ":" + password)
	ha2 := md5hex(method + ":" + uri)

	// qop may be a comma-separated list (e.g. "auth,auth-int"). We only support
	// and select "auth"; anything else falls back to the legacy (no-qop) form.
	useAuth := qopOffersAuth(dc.qop)

	var response string
	if useAuth {
		response = md5hex(strings.Join([]string{ha1, dc.nonce, nc, cnonce, "auth", ha2}, ":"))
	} else {
		response = md5hex(ha1 + ":" + dc.nonce + ":" + ha2)
	}

	parts := []string{
		fmt.Sprintf(`username="%s"`, user),
		fmt.Sprintf(`realm="%s"`, dc.realm),
		fmt.Sprintf(`nonce="%s"`, dc.nonce),
		fmt.Sprintf(`uri="%s"`, uri),
		fmt.Sprintf(`response="%s"`, response),
	}
	if useAuth {
		parts = append(parts,
			`qop=auth`,
			fmt.Sprintf("nc=%s", nc),
			fmt.Sprintf(`cnonce="%s"`, cnonce),
		)
	}
	if dc.opaque != "" {
		parts = append(parts, fmt.Sprintf(`opaque="%s"`, dc.opaque))
	}
	return "Digest " + strings.Join(parts, ", ")
}

// qopOffersAuth reports whether the qop directive includes the "auth" option.
func qopOffersAuth(qop string) bool {
	for _, opt := range strings.Split(qop, ",") {
		if strings.TrimSpace(opt) == "auth" {
			return true
		}
	}
	return false
}

func md5hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}
