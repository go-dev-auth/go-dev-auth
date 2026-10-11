package godevauth_test

import (
	"encoding/json"
	"net/http"
	"testing"
)

// Regression test for M13: a session listing omits the raw token, so
// revoking another device has to work by the session id the listing
// does expose.
func TestRevokeSessionByID(t *testing.T) {
	_, tc := newTestAuth(t, nil)
	tc.signUp("multi@example.com", "password123", "Multi")

	// A second device (client) for the same account.
	other := secondClient(t, tc)
	res, body := other.post("/sign-in/email", map[string]any{
		"email": "multi@example.com", "password": "password123",
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("second device sign-in: %d %v", res.StatusCode, body)
	}

	// The caller's own current session id, so the test revokes the OTHER
	// device and stays authenticated for the final assertion.
	_, self := tc.get("/get-session")
	selfSession, _ := self["session"].(map[string]any)
	ownID, _ := selfSession["id"].(string)
	if ownID == "" {
		t.Fatalf("get-session did not return the current session id: %v", self)
	}

	sessions := listSessions(t, tc)
	if len(sessions) < 2 {
		t.Fatalf("want at least 2 sessions, got %d", len(sessions))
	}
	var targetID string
	for _, s := range sessions {
		if _, hasToken := s["token"]; hasToken {
			t.Fatal("session listing leaked the raw token")
		}
		if id, _ := s["id"].(string); id != ownID {
			targetID = id
		}
	}
	if targetID == "" {
		t.Fatal("no other-device session id in listing")
	}

	// A stranger cannot revoke a session by id.
	stranger := secondClient(t, tc)
	stranger.signUp("stranger@example.com", "password123", "Stranger")
	res, _ = stranger.post("/revoke-session", map[string]any{"sessionId": targetID})
	if res.StatusCode == http.StatusOK {
		t.Fatal("a stranger revoked another user's session by id")
	}

	// The owner can.
	res, body = tc.post("/revoke-session", map[string]any{"sessionId": targetID})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("revoke by id: %d %v", res.StatusCode, body)
	}
	if after := listSessions(t, tc); len(after) != len(sessions)-1 {
		t.Fatalf("sessions after revoke = %d, want %d", len(after), len(sessions)-1)
	}
}

// listSessions decodes the /list-sessions array (the typed helpers
// decode a single object).
func listSessions(t *testing.T, tc *testClient) []map[string]any {
	t.Helper()
	res, err := tc.client.Get(tc.server.URL + "/api/auth/list-sessions")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var out []map[string]any
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}
