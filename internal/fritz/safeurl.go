package fritz

import (
	"net/url"
)

// safeURLForError returns a URL string with sensitive query parameters
// (such as sid, response, password) and user credentials redacted. It is used
// when wrapping transport errors and logging HTTP requests so that a live
// session id, challenge response, or credentials never reach logs or stderr.
func safeURLForError(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	q := u.Query()
	modified := false
	for _, param := range []string{"sid", "response", "password", "pass"} {
		if q.Has(param) {
			q.Set(param, "REDACTED")
			modified = true
		}
	}
	if modified {
		u.RawQuery = q.Encode()
	}
	return u.Redacted()
}
