package godevauth_test

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"

	godevauth "github.com/go-dev-auth/go-dev-auth"
	"github.com/go-dev-auth/go-dev-auth/storage"
)

// recorder collects the audit trail for assertions.
type recorder struct {
	mu     sync.Mutex
	events []godevauth.Event
}

func (r *recorder) handler() func(context.Context, *godevauth.Event) {
	return func(_ context.Context, e *godevauth.Event) {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.events = append(r.events, *e)
	}
}

func (r *recorder) all() []godevauth.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]godevauth.Event(nil), r.events...)
}

// find returns the first event of a type, or fails.
func (r *recorder) find(t *testing.T, typ godevauth.EventType) godevauth.Event {
	t.Helper()
	for _, e := range r.all() {
		if e.Type == typ {
			return e
		}
	}
	t.Fatalf("no %s event; got %v", typ, r.types())
	return godevauth.Event{}
}

func (r *recorder) count(typ godevauth.EventType) int {
	n := 0
	for _, e := range r.all() {
		if e.Type == typ {
			n++
		}
	}
	return n
}

func (r *recorder) types() []godevauth.EventType {
	var out []godevauth.EventType
	for _, e := range r.all() {
		out = append(out, e.Type)
	}
	return out
}

// newRecordingAuth wires an instance to a recorder, with the default
// slog output off so test logs stay readable.
func newRecordingAuth(t *testing.T, mutate func(*godevauth.Config)) (*recorder, *testClient) {
	t.Helper()
	rec := &recorder{}
	_, tc := newTestAuth(t, func(cfg *godevauth.Config) {
		cfg.Events.Handler = rec.handler()
		cfg.Events.DisableDefaultLogging = true
		if mutate != nil {
			mutate(cfg)
		}
	})
	return rec, tc
}

func TestSignInEventsRecordSuccessAndWhyItFailed(t *testing.T) {
	rec, tc := newRecordingAuth(t, nil)
	tc.signUp("events@example.com", "password123", "Events")

	signUp := rec.find(t, godevauth.EventSignUp)
	if signUp.Email != "events@example.com" || signUp.ActorID == "" {
		t.Fatalf("sign_up event = %+v", signUp)
	}

	// A wrong password and an address that does not exist look
	// identical to the client. The audit trail must tell them apart.
	tc.post("/sign-in/email", map[string]any{"email": "events@example.com", "password": "wrong-password"})
	tc.post("/sign-in/email", map[string]any{"email": "nobody@example.com", "password": "password123"})

	var reasons []godevauth.Reason
	for _, e := range rec.all() {
		if e.Type == godevauth.EventSignIn && e.Outcome == godevauth.OutcomeFailure {
			reasons = append(reasons, e.Reason)
		}
	}
	want := []godevauth.Reason{godevauth.ReasonInvalidPassword, godevauth.ReasonUnknownUser}
	if !reflect.DeepEqual(reasons, want) {
		t.Fatalf("failure reasons = %v, want %v", reasons, want)
	}

	// And the successful one carries a session id, an actor and an IP.
	tc.post("/sign-in/email", map[string]any{"email": "events@example.com", "password": "password123"})
	var ok *godevauth.Event
	for _, e := range rec.all() {
		if e.Type == godevauth.EventSignIn && e.Outcome == godevauth.OutcomeSuccess {
			ev := e
			ok = &ev
		}
	}
	if ok == nil {
		t.Fatalf("no successful sign_in event; got %v", rec.types())
	}
	if ok.SessionID == "" || ok.ActorID == "" || ok.ClientIP == "" || ok.Method != "credential" {
		t.Fatalf("sign_in event = %+v", *ok)
	}
	if ok.RequestPath != "/sign-in/email" {
		t.Fatalf("RequestPath = %q", ok.RequestPath)
	}
}

func TestSessionLifecycleEvents(t *testing.T) {
	rec, tc := newRecordingAuth(t, nil)
	tc.signUp("session-events@example.com", "password123", "S")

	if rec.count(godevauth.EventSessionCreated) != 1 {
		t.Fatalf("session.created count = %d, want 1", rec.count(godevauth.EventSessionCreated))
	}
	tc.post("/sign-out", nil)
	out := rec.find(t, godevauth.EventSignOut)
	if out.ActorID == "" || out.SessionID == "" {
		t.Fatalf("sign_out event = %+v", out)
	}

	tc.post("/sign-in/email", map[string]any{"email": "session-events@example.com", "password": "password123"})
	tc.post("/revoke-sessions", map[string]any{})
	revoked := rec.find(t, godevauth.EventSessionRevoked)
	if revoked.Action != "revoke_all_sessions" {
		t.Fatalf("session.revoked event = %+v", revoked)
	}
}

func TestPasswordAndEmailEvents(t *testing.T) {
	var resetToken string
	rec, tc := newRecordingAuth(t, func(cfg *godevauth.Config) {
		cfg.EmailAndPassword.ResetPasswordURL = "/reset"
		cfg.EmailAndPassword.SendResetPassword = func(_ context.Context, _ *storage.User, _, token string) error {
			resetToken = token
			return nil
		}
		cfg.User.ChangeEmail.Enabled = true
	})
	tc.signUp("pw-events@example.com", "password123", "P")

	tc.post("/change-password", map[string]any{
		"currentPassword": "password123", "newPassword": "password456",
	})
	if changed := rec.find(t, godevauth.EventPasswordChanged); changed.Outcome != godevauth.OutcomeSuccess {
		t.Fatalf("password.changed = %+v", changed)
	}

	tc.post("/forget-password", map[string]any{"email": "pw-events@example.com"})
	rec.find(t, godevauth.EventPasswordResetRequested)
	if resetToken == "" {
		t.Fatal("no reset token was issued")
	}
	tc.post("/reset-password", map[string]any{"token": resetToken, "newPassword": "password789"})
	rec.find(t, godevauth.EventPasswordReset)

	// Changing an unverified address happens immediately.
	tc.post("/sign-in/email", map[string]any{"email": "pw-events@example.com", "password": "password789"})
	tc.post("/change-email", map[string]any{"newEmail": "moved@example.com"})
	if moved := rec.find(t, godevauth.EventEmailChanged); moved.Email != "moved@example.com" {
		t.Fatalf("email.changed = %+v", moved)
	}
}

// The property that makes the trail safe to ship to a third-party SIEM:
// no event may contain a credential. Reflection over every string field
// means a field added later is covered without anyone remembering to
// extend this test.
func TestEventsCarryNoSecrets(t *testing.T) {
	const password = "correct-horse-battery-staple-1"
	var resetToken, verifyToken string

	rec, tc := newRecordingAuth(t, func(cfg *godevauth.Config) {
		cfg.EmailAndPassword.ResetPasswordURL = "/reset"
		cfg.EmailAndPassword.SendResetPassword = func(_ context.Context, _ *storage.User, _, token string) error {
			resetToken = token
			return nil
		}
		cfg.EmailVerification.SendVerificationEmail = func(_ context.Context, _ *storage.User, _, token string) error {
			verifyToken = token
			return nil
		}
		cfg.EmailVerification.SendOnSignUp = true
		cfg.User.ChangeEmail.Enabled = true
		cfg.User.DeleteUser.Enabled = true
	})

	// Drive every flow that touches a credential.
	tc.signUp("secrets@example.com", password, "Secrets")
	tc.post("/sign-in/email", map[string]any{"email": "secrets@example.com", "password": "wrong-" + password})
	tc.post("/sign-in/email", map[string]any{"email": "secrets@example.com", "password": password})
	sessionToken := currentSessionToken(t, tc)
	tc.post("/change-password", map[string]any{
		"currentPassword": password, "newPassword": password + "-two",
	})
	tc.post("/forget-password", map[string]any{"email": "secrets@example.com"})
	tc.post("/reset-password", map[string]any{"token": resetToken, "newPassword": password + "-three"})
	tc.post("/sign-in/email", map[string]any{"email": "secrets@example.com", "password": password + "-three"})
	tc.post("/delete-user", map[string]any{"password": password + "-three"})

	forbidden := map[string]string{
		"the password":      password,
		"a wrong password":  "wrong-" + password,
		"the new password":  password + "-two",
		"the last password": password + "-three",
		"the reset token":   resetToken,
		"a session token":   sessionToken,
	}
	if verifyToken != "" {
		forbidden["the verification token"] = verifyToken
	}

	events := rec.all()
	if len(events) == 0 {
		t.Fatal("no events were recorded, so this test proves nothing")
	}
	for _, e := range events {
		v := reflect.ValueOf(e)
		for i := 0; i < v.NumField(); i++ {
			field := v.Field(i)
			if field.Kind() != reflect.String {
				continue
			}
			got := field.String()
			if got == "" {
				continue
			}
			name := v.Type().Field(i).Name
			for label, secret := range forbidden {
				if secret == "" {
					continue
				}
				if strings.Contains(got, secret) {
					t.Fatalf("event %s field %s leaked %s: %q", e.Type, name, label, got)
				}
			}
		}
	}
}

// currentSessionToken reads the session cookie the client is holding.
func currentSessionToken(t *testing.T, tc *testClient) string {
	t.Helper()
	for _, c := range tc.client.Jar.Cookies(nil) {
		if strings.Contains(c.Name, "session_token") || strings.Contains(c.Name, "session-token") {
			// The cookie value is "<token>.<signature>"; the token half
			// is the bearer credential.
			return strings.SplitN(c.Value, ".", 2)[0]
		}
	}
	t.Fatal("no session cookie found")
	return ""
}

// With no Handler configured the trail still exists: it goes to the
// application's own logger. An audit trail that has to be switched on
// is missing from exactly the deployments that need it most.
func TestEventsDefaultToTheConfiguredLogger(t *testing.T) {
	var buf bytes.Buffer
	var mu sync.Mutex
	logger := slog.New(slog.NewTextHandler(&syncWriter{w: &buf, mu: &mu}, nil))

	_, tc := newTestAuth(t, func(cfg *godevauth.Config) {
		cfg.Logger = logger
		// The shared harness silences default event logging to keep test
		// output readable; this test is specifically about that default,
		// so it opts back in.
		cfg.Events.DisableDefaultLogging = false
	})
	tc.signUp("default-log@example.com", "password123", "D")
	tc.post("/sign-in/email", map[string]any{"email": "default-log@example.com", "password": "nope"})

	mu.Lock()
	out := buf.String()
	mu.Unlock()
	if !strings.Contains(out, "event=sign_in") {
		t.Fatalf("the default logger received no sign-in event:\n%s", out)
	}
	if !strings.Contains(out, "reason=invalid_password") {
		t.Fatalf("the failed sign-in was not logged with its reason:\n%s", out)
	}
	// Failures are warnings, not info: they are what alerting keys on.
	if !strings.Contains(out, "level=WARN") {
		t.Fatalf("a failed sign-in was not logged at WARN:\n%s", out)
	}
}

func TestDefaultLoggingCanBeDisabled(t *testing.T) {
	var buf bytes.Buffer
	var mu sync.Mutex
	_, tc := newTestAuth(t, func(cfg *godevauth.Config) {
		cfg.Logger = slog.New(slog.NewTextHandler(&syncWriter{w: &buf, mu: &mu}, nil))
		cfg.Events.DisableDefaultLogging = true
	})
	tc.signUp("quiet@example.com", "password123", "Q")

	mu.Lock()
	defer mu.Unlock()
	if strings.Contains(buf.String(), "auth event") {
		t.Fatalf("events were logged despite DisableDefaultLogging:\n%s", buf.String())
	}
}

type syncWriter struct {
	w  *bytes.Buffer
	mu *sync.Mutex
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

// A throttled request answers 429 and nothing else: Ctx.Error only logs
// 5xx, so without an event a brute-force attempt being blocked leaves no
// server-side trace at all.
func TestRateLimitedRequestsAreRecorded(t *testing.T) {
	rec, tc := newRecordingAuth(t, func(cfg *godevauth.Config) {
		cfg.RateLimit = godevauth.RateLimitConfig{}
	})
	var last int
	for i := 0; i < 6; i++ {
		res, _ := tc.post("/sign-in/email", map[string]any{
			"email": "throttle@example.com", "password": "password123",
		})
		last = res.StatusCode
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("last status = %d, want 429", last)
	}
	limited := rec.find(t, godevauth.EventRateLimited)
	if limited.Reason != godevauth.ReasonRateLimited || limited.RequestPath != "/sign-in/email" {
		t.Fatalf("rate_limited event = %+v", limited)
	}
}
