package godevauth_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Regression test for the sliding-refresh privilege escalation (H1): a
// session minted with a custom, shorter duration (admin impersonation
// is the canonical case) used to be treated as an overdue
// default-lifetime session on its first lookup and extended to the full
// Session.ExpiresIn.
func TestShortLivedSessionIsNotExtendedByRefresh(t *testing.T) {
	auth, tc := newTestAuth(t, nil)
	tc.signUp("short@example.com", "password123", "Short")
	user, err := auth.FindUserByEmail(t.Context(), "short@example.com")
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/test", nil)
	c := auth.NewCtx(rec, req)

	const lifetime = time.Hour
	sess, err := auth.CreateSessionWith(c, user, false, nil, lifetime)
	if err != nil {
		t.Fatal(err)
	}
	wantExpiry := time.Now().Add(lifetime)
	if sess.ExpiresAt.Sub(wantExpiry).Abs() > time.Minute {
		t.Fatalf("created session expiry = %v, want ~%v", sess.ExpiresAt, wantExpiry)
	}

	// The bug fired on the very first lookup: updateAt was computed as
	// ExpiresAt - config.ExpiresIn + UpdateAge, which for a 1h session
	// is far in the past.
	sd, err := auth.GetSessionFromToken(t.Context(), sess.Token)
	if err != nil {
		t.Fatal(err)
	}
	if sd.Session.ExpiresAt.Sub(wantExpiry).Abs() > time.Minute {
		t.Fatalf("after lookup, session expiry = %v (lifetime %v), want ~%v: short-lived session was extended by sliding refresh",
			sd.Session.ExpiresAt, time.Until(sd.Session.ExpiresAt).Round(time.Minute), wantExpiry)
	}
}

// Companion to the test above: a default-lifetime session past its
// UpdateAge still gets its expiry refreshed, so the H1 fix did not
// disable sliding expiration wholesale.
func TestDefaultSessionStillRefreshes(t *testing.T) {
	auth, tc := newTestAuth(t, nil)
	tc.signUp("slider@example.com", "password123", "Slider")
	user, err := auth.FindUserByEmail(t.Context(), "slider@example.com")
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/test", nil)
	c := auth.NewCtx(rec, req)
	sess, err := auth.CreateSessionWith(c, user, true, nil, 0) // default duration
	if err != nil {
		t.Fatal(err)
	}

	// Simulate a session created two days ago (default ExpiresIn 7d,
	// UpdateAge 1d): backdate createdAt and expiresAt together so the
	// session's own lifetime is still the default.
	expiresIn := auth.Config().Session.ExpiresIn
	created := time.Now().UTC().Add(-48 * time.Hour)
	if _, err := auth.UpdateSessionRecord(t.Context(), sess.Token, map[string]any{
		"createdAt": created,
		"expiresAt": created.Add(expiresIn),
	}); err != nil {
		t.Fatal(err)
	}

	sd, err := auth.GetSessionFromToken(t.Context(), sess.Token)
	if err != nil {
		t.Fatal(err)
	}
	wantExpiry := time.Now().Add(expiresIn)
	if sd.Session.ExpiresAt.Sub(wantExpiry).Abs() > time.Minute {
		t.Fatalf("after lookup, expiry = %v, want refreshed to ~%v", sd.Session.ExpiresAt, wantExpiry)
	}
}
