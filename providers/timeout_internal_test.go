package providers

import "testing"

// Regression test for M4 (see oauth2.TestDefaultClientHasTimeout).
func TestDefaultClientHasTimeout(t *testing.T) {
	if defaultHTTPClient.Timeout <= 0 {
		t.Fatal("providers default HTTP client has no timeout")
	}
}
