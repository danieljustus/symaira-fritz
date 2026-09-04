package fritz

// getCachedDigestAuth returns a cached Authorization header for the given
// method and URI, or empty string if no cached challenge exists. Entropy
// failures are returned before any authenticated request is sent.
// The nc counter is incremented under the mutex so concurrent callers
// each get a unique nc.
func (c *Client) getCachedDigestAuth(method, uri string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.digestCache == nil || c.digestCache.challenge.nonce == "" {
		return "", nil
	}
	c.digestCache.nc++
	dc := c.digestCache.challenge
	return digestAuthHeader(dc, c.User, c.Password, method, uri, c.digestCache.nc)
}

// setCachedDigestChallenge stores the challenge and resets the nc counter.
func (c *Client) setCachedDigestChallenge(dc digestChallenge) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.digestCache = &cachedDigest{challenge: dc, nc: 0}
}

// buildDigestAuth builds an Authorization header for the given challenge,
// incrementing the cached nc counter and propagating cnonce entropy failures.
func (c *Client) buildDigestAuth(dc digestChallenge, method, uri string) (string, error) {
	c.mu.Lock()
	c.digestCache = &cachedDigest{challenge: dc, nc: 0}
	nc := c.digestCache.nc + 1
	c.digestCache.nc = nc
	c.mu.Unlock()
	return digestAuthHeader(dc, c.User, c.Password, method, uri, nc)
}
