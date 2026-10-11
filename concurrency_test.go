package godevauth_test

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"testing"

	godevauth "github.com/go-dev-auth/go-dev-auth"
	"github.com/go-dev-auth/go-dev-auth/plugins/apikey"
	"github.com/go-dev-auth/go-dev-auth/plugins/organization"
	"github.com/go-dev-auth/go-dev-auth/storage"
)

// TestConcurrentSignUpSameEmail asserts that racing sign-ups for the
// same address produce exactly one user (no TOCTOU duplicate).
func TestConcurrentSignUpSameEmail(t *testing.T) {
	auth, tc := newTestAuth(t, nil)
	const n = 8
	var wg sync.WaitGroup
	codes := make([]int, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			client := secondClient(t, tc)
			res, _ := client.post("/sign-up/email", map[string]any{
				"email": "race@example.com", "password": "password123", "name": "Race",
			})
			codes[i] = res.StatusCode
		}(i)
	}
	wg.Wait()
	count, err := auth.Storage().Count(context.Background(), storage.ModelUser,
		[]storage.Where{storage.W("email", "race@example.com")})
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 user after %d concurrent sign-ups, got %d (statuses %v)", n, count, codes)
	}
	ok := 0
	for _, c := range codes {
		if c == http.StatusOK {
			ok++
		}
		if c >= 500 {
			t.Errorf("concurrent sign-up produced a 5xx (%d); duplicates should map to a 4xx", c)
		}
	}
	if ok != 1 {
		t.Fatalf("expected exactly 1 successful sign-up, got %d (statuses %v)", ok, codes)
	}
}

// TestConcurrentSessionReads hammers session validation from many
// goroutines to surface data races in the session/cookie path.
func TestConcurrentSessionReads(t *testing.T) {
	_, tc := newTestAuth(t, func(cfg *godevauth.Config) {
		cfg.Session.CookieCache.Enabled = true
	})
	tc.signUp("reader@example.com", "password123", "Reader")
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				res, _ := tc.get("/get-session")
				if res.StatusCode != http.StatusOK {
					t.Errorf("get-session: %d", res.StatusCode)
					return
				}
			}
		}()
	}
	wg.Wait()
}

// TestAPIKeyQuotaUnderConcurrency asserts the remaining-requests quota
// is not over-spent when requests race.
func TestAPIKeyQuotaUnderConcurrency(t *testing.T) {
	_, tc := newTestAuth(t, func(cfg *godevauth.Config) {
		cfg.Plugins = []godevauth.Plugin{apikey.New()}
	})
	tc.signUp("quota@example.com", "password123", "Quota")
	remaining := int64(5)
	res, body := tc.post("/api-key/create", map[string]any{
		"name": "quota-key", "remaining": remaining,
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("create: %d %v", res.StatusCode, body)
	}
	key, _ := body["key"].(string)

	const attempts = 20
	var wg sync.WaitGroup
	var mu sync.Mutex
	accepted := 0
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest(http.MethodPost, tc.server.URL+"/api/auth/api-key/verify", nil)
			req.Header.Set("Content-Type", "application/json")
			req.Body = http.NoBody
			resp, verified := verifyKeyRequest(t, tc, key)
			if resp == http.StatusOK && verified {
				mu.Lock()
				accepted++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if int64(accepted) > remaining {
		t.Fatalf("quota over-spent: %d accepted with remaining=%d", accepted, remaining)
	}
}

func verifyKeyRequest(t *testing.T, tc *testClient, key string) (int, bool) {
	t.Helper()
	client := secondClient(t, tc)
	res, body := client.post("/api-key/verify", map[string]any{"key": key})
	valid, _ := body["valid"].(bool)
	return res.StatusCode, valid
}

// TestConcurrentOrgInvitationAccept asserts one invitation cannot be
// redeemed twice.
func TestConcurrentOrgInvitationAccept(t *testing.T) {
	var invitationID string
	orgPlugin := organization.New(organization.Options{
		SendInvitationEmail: func(ctx context.Context, inv *organization.Invitation, org *organization.Organization, inviter *storage.User) error {
			invitationID = inv.ID
			return nil
		},
	})
	auth, tc := newTestAuth(t, func(cfg *godevauth.Config) {
		cfg.Plugins = []godevauth.Plugin{orgPlugin}
	})
	tc.signUp("orgowner@example.com", "password123", "Owner")
	res, org := tc.post("/organization/create", map[string]any{"name": "Race Org"})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("create org: %d %v", res.StatusCode, org)
	}
	orgID := org["id"].(string)
	tc.post("/organization/invite-member", map[string]any{"email": "invitee@example.com"})
	if invitationID == "" {
		t.Fatal("no invitation")
	}

	invitee := secondClient(t, tc)
	invitee.signUp("invitee@example.com", "password123", "Invitee")
	markEmailVerified(t, auth, "invitee@example.com")

	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			invitee.post("/organization/accept-invitation", map[string]any{
				"invitationId": invitationID,
			})
		}()
	}
	wg.Wait()

	n, err := auth.Storage().Count(context.Background(), organization.ModelMember, []storage.Where{
		storage.W("organizationId", orgID),
	})
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("expected 2 members (owner + invitee), got %d", n)
	}
	_ = fmt.Sprint()
}
