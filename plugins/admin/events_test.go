package admin_test

import (
	"context"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"

	godevauth "github.com/go-dev-auth/go-dev-auth"
	"github.com/go-dev-auth/go-dev-auth/plugins/admin"
	"github.com/go-dev-auth/go-dev-auth/plugins/plugintest"
	"github.com/go-dev-auth/go-dev-auth/storage"
)

// The administrative half of the audit trail.
//
// Impersonation is the case that matters most: while it is active every
// action is recorded against the impersonated user, so the start and
// stop events are the only thing that attributes them to the
// administrator who performed them.

type eventLog struct {
	mu     sync.Mutex
	events []godevauth.Event
}

func (l *eventLog) handler() func(context.Context, *godevauth.Event) {
	return func(_ context.Context, e *godevauth.Event) {
		l.mu.Lock()
		defer l.mu.Unlock()
		l.events = append(l.events, *e)
	}
}

func (l *eventLog) all() []godevauth.Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]godevauth.Event(nil), l.events...)
}

func (l *eventLog) find(t *testing.T, typ godevauth.EventType) godevauth.Event {
	t.Helper()
	for _, e := range l.all() {
		if e.Type == typ {
			return e
		}
	}
	var got []string
	for _, e := range l.all() {
		got = append(got, string(e.Type)+"/"+e.Action)
	}
	t.Fatalf("no %s event; got %v", typ, got)
	return godevauth.Event{}
}

// newAuditEnv mounts the admin plugin with an event recorder and an
// administrator signed in.
func newAuditEnv(t *testing.T) (*eventLog, *plugintest.Env, *storage.User) {
	t.Helper()
	log := &eventLog{}
	env := plugintest.NewWith(t, func(cfg *godevauth.Config) {
		cfg.Plugins = []godevauth.Plugin{admin.New()}
		cfg.Events.Handler = log.handler()
		cfg.Events.DisableDefaultLogging = true
		cfg.User.AdditionalFields = nil
	})
	adminUser := env.SignUp("admin@example.com", "password123")
	if _, err := env.Auth.UpdateUserRecord(context.Background(), adminUser.ID,
		map[string]any{"role": "admin"}); err != nil {
		t.Fatal(err)
	}
	return log, env, adminUser
}

func TestImpersonationIsRecordedAtBothEnds(t *testing.T) {
	log, env, adminUser := newAuditEnv(t)
	target := env.Client().SignUp("victim@example.com", "password123")

	res, body := env.POST("/admin/impersonate-user", map[string]any{"userId": target.ID})
	env.RequireStatus(res, body, http.StatusOK)

	started := log.find(t, godevauth.EventImpersonationStarted)
	if started.ActorID != adminUser.ID {
		t.Fatalf("start event actor = %q, want the administrator %q", started.ActorID, adminUser.ID)
	}
	if started.TargetID != target.ID {
		t.Fatalf("start event target = %q, want %q", started.TargetID, target.ID)
	}
	if started.SessionID == "" {
		t.Fatal("the start event does not name the session it created")
	}

	// The session created by impersonation must itself be attributed to
	// the administrator, not to the user being impersonated.
	var created *godevauth.Event
	for _, e := range log.all() {
		if e.Type == godevauth.EventSessionCreated && e.TargetID == target.ID {
			ev := e
			created = &ev
		}
	}
	if created == nil || created.ActorID != adminUser.ID {
		t.Fatalf("session.created for an impersonation = %+v, want the admin as actor", created)
	}

	res, body = env.POST("/admin/stop-impersonating", map[string]any{})
	env.RequireStatus(res, body, http.StatusOK)
	stopped := log.find(t, godevauth.EventImpersonationStopped)
	if stopped.ActorID != adminUser.ID || stopped.TargetID != target.ID {
		t.Fatalf("stop event = %+v", stopped)
	}
	if stopped.SessionID != started.SessionID {
		t.Fatalf("stop event closes session %q, start opened %q", stopped.SessionID, started.SessionID)
	}
}

func TestPrivilegedActionsAreRecorded(t *testing.T) {
	log, env, adminUser := newAuditEnv(t)
	target := env.Client().SignUp("subject@example.com", "password123")

	env.POST("/admin/ban-user", map[string]any{"userId": target.ID, "banReason": "spam"})
	banned := log.find(t, godevauth.EventUserBanned)
	if banned.ActorID != adminUser.ID || banned.TargetID != target.ID {
		t.Fatalf("ban event = %+v", banned)
	}
	// The reason is the administrator's free text about another person;
	// it stays out of the log stream.
	for _, e := range log.all() {
		if strings.Contains(e.Action, "spam") {
			t.Fatalf("the ban reason leaked into %+v", e)
		}
	}

	env.POST("/admin/unban-user", map[string]any{"userId": target.ID})
	log.find(t, godevauth.EventUserUnbanned)

	env.POST("/admin/set-role", map[string]any{"userId": target.ID, "role": "admin"})
	var roleEvent *godevauth.Event
	for _, e := range log.all() {
		if strings.HasPrefix(e.Action, "set-role:") {
			ev := e
			roleEvent = &ev
		}
	}
	if roleEvent == nil || roleEvent.TargetID != target.ID {
		t.Fatalf("granting a role was not recorded: %+v", roleEvent)
	}

	env.GET("/admin/list-users")
	if listed := log.find(t, godevauth.EventAdminAction); listed.ActorID == "" {
		t.Fatalf("admin action event has no actor: %+v", listed)
	}
}

// An ordinary user probing the admin surface is a privilege-escalation
// attempt. The client sees a bare 403; the trail must say who tried.
func TestRefusedAdminAccessIsRecorded(t *testing.T) {
	log, env, _ := newAuditEnv(t)
	intruder := env.Client()
	user := intruder.SignUp("intruder@example.com", "password123")

	res, body := intruder.GET("/admin/list-users")
	env.RequireStatus(res, body, http.StatusForbidden)

	var refusal *godevauth.Event
	for _, e := range log.all() {
		if e.Type == godevauth.EventAdminAction && e.Outcome == godevauth.OutcomeFailure {
			ev := e
			refusal = &ev
		}
	}
	if refusal == nil {
		t.Fatal("a refused admin request left no record")
	}
	if refusal.ActorID != user.ID || refusal.Reason != godevauth.ReasonNotAuthorized {
		t.Fatalf("refusal event = %+v", *refusal)
	}
	if refusal.Action != "/admin/list-users" {
		t.Fatalf("refusal event action = %q", refusal.Action)
	}
}

// Same reflection sweep as the core suite, over the administrative
// flows: a session token handed to /admin/revoke-user-session must not
// come back out in an event.
func TestAdminEventsCarryNoSecrets(t *testing.T) {
	log, env, _ := newAuditEnv(t)
	victim := env.Client()
	target := victim.SignUp("token-holder@example.com", "password123")

	sessions, err := env.Auth.ListSessions(context.Background(), target.ID)
	if err != nil || len(sessions) == 0 {
		t.Fatalf("expected a session for the target: %v", err)
	}
	sessionToken := sessions[0].Token

	env.POST("/admin/revoke-user-session", map[string]any{"sessionToken": sessionToken})
	env.POST("/admin/set-user-password", map[string]any{
		"userId": target.ID, "newPassword": "brand-new-password-1",
	})
	env.POST("/admin/create-user", map[string]any{
		"email": "made@example.com", "password": "another-new-password-1",
	})

	forbidden := []string{sessionToken, "brand-new-password-1", "another-new-password-1"}
	events := log.all()
	if len(events) == 0 {
		t.Fatal("no events recorded, so this test proves nothing")
	}
	for _, e := range events {
		v := reflect.ValueOf(e)
		for i := 0; i < v.NumField(); i++ {
			f := v.Field(i)
			if f.Kind() != reflect.String || f.String() == "" {
				continue
			}
			for _, secret := range forbidden {
				if strings.Contains(f.String(), secret) {
					t.Fatalf("event %s field %s leaked a credential: %q",
						e.Type, v.Type().Field(i).Name, f.String())
				}
			}
		}
	}
}
