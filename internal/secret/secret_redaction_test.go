package secret

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestRedactSecretOutput(t *testing.T) {
	const secret = "sensitive-test-value"
	hexSecret := hex.EncodeToString([]byte(secret))
	got := redactSecretOutput("plain="+secret+" hex="+hexSecret+" upper="+strings.ToUpper(hexSecret), secret)
	if strings.Contains(got, secret) || strings.Contains(got, hexSecret) {
		t.Fatalf("redacted output still contains secret material")
	}
	if got != "plain=REDACTED hex=REDACTED upper=REDACTED" {
		t.Fatalf("redacted output = %q", got)
	}
}
