package oauth2

import "testing"

// Regression test for M4: provider calls made without an
// application-supplied client must be bounded by a timeout, or a hung
// identity provider pins goroutines indefinitely.
func TestDefaultClientHasTimeout(t *testing.T) {
	if defaultHTTPClient.Timeout <= 0 {
		t.Fatal("oauth2 default HTTP client has no timeout")
	}
	p := New(Spec{ProviderID: "x"})
	if p.client().Timeout <= 0 {
		t.Fatal("provider without HTTPClient falls back to an unbounded client")
	}
}
