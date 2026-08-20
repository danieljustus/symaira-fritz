package fritz

import (
	"net/url"
)

// safeURLForError returns a URL string with the session id (sid) query
// parameter redacted. It is used when wrapping transport errors so that
// a live session id never reaches stderr or --json error output.
func safeURLForError(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	q := u.Query()
	if q.Has("sid") {
		q.Set("sid", "REDACTED")
		u.RawQuery = q.Encode()
	}
	return u.String()
}
