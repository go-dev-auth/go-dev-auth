package godevauth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	godevauth "github.com/go-dev-auth/go-dev-auth"
	"github.com/go-dev-auth/go-dev-auth/crypto"
	"github.com/go-dev-auth/go-dev-auth/storage"
	"github.com/go-dev-auth/go-dev-auth/storage/memory"
)

func BenchmarkPasswordHash(b *testing.B) {
	h := crypto.ScryptHasher{}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := h.Hash("correct horse battery staple"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPasswordVerify(b *testing.B) {
	h := crypto.ScryptHasher{}
	hash, _ := h.Hash("correct horse battery staple")
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if ok, _ := h.Verify(hash, "correct horse battery staple"); !ok {
			b.Fatal("verify failed")
		}
	}
}

func BenchmarkGenerateID(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = crypto.GenerateID(32)
	}
}

func BenchmarkGenerateToken(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = crypto.GenerateToken(32)
	}
}

func BenchmarkSignHMAC(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = crypto.SignHMAC("secret", "some-session-token-value")
	}
}

func benchAuth(b *testing.B) (*godevauth.Auth, *http.Cookie) {
	b.Helper()
	auth, err := godevauth.New(godevauth.Config{
		BaseURL:          "http://localhost",
		Secret:           "bench-secret-0123456789",
		Database:         memory.New(),
		EmailAndPassword: godevauth.EmailPasswordConfig{Enabled: true},
		// measure the handler itself, not the (on by default) limiter
		RateLimit: godevauth.RateLimitConfig{Disabled: true},
	})
	if err != nil {
		b.Fatal(err)
	}
	user, err := auth.CreateUser(context.Background(), &storage.User{Name: "Bench", Email: "bench@example.com"})
	if err != nil {
		b.Fatal(err)
	}
	// create a session through the handler so the cookie is signed
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/auth/get-session", nil)
	c := auth.NewCtx(w, r)
	if _, err := auth.CreateSessionFor(c, user, true); err != nil {
		b.Fatal(err)
	}
	cookies := w.Result().Cookies()
	if len(cookies) == 0 {
		b.Fatal("no session cookie")
	}
	return auth, cookies[0]
}

// BenchmarkGetSession measures the hot path every authenticated request
// pays: cookie parse + signature verify + session lookup + user lookup.
func BenchmarkGetSession(b *testing.B) {
	auth, cookie := benchAuth(b)
	req := httptest.NewRequest(http.MethodGet, "/api/auth/get-session", nil)
	req.AddCookie(cookie)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := auth.GetSession(req); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGetSessionParallel(b *testing.B) {
	auth, cookie := benchAuth(b)
	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		req := httptest.NewRequest(http.MethodGet, "/api/auth/get-session", nil)
		req.AddCookie(cookie)
		for pb.Next() {
			if _, err := auth.GetSession(req); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkGetSessionHTTP measures the full HTTP request path through
// the router, hooks, CSRF check and JSON encoding.
func BenchmarkGetSessionHTTP(b *testing.B) {
	auth, cookie := benchAuth(b)
	handler := auth.Handler()
	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req := httptest.NewRequest(http.MethodGet, "/api/auth/get-session", nil)
			req.AddCookie(cookie)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				b.Fatalf("status %d", w.Code)
			}
		}
	})
}

// BenchmarkRouteMatch isolates router cost with all plugins loaded.
func BenchmarkRouteMatchMiss(b *testing.B) {
	auth, _ := benchAuth(b)
	handler := auth.Handler()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/auth/ok", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
	}
}

// BenchmarkMemoryAdapterScale shows how the memory adapter degrades as
// the session table grows (linear scan).
func BenchmarkMemoryAdapterScale(b *testing.B) {
	for _, n := range []int{100, 10000} {
		b.Run(sizeName(n), func(b *testing.B) {
			store := memory.New()
			// godevauth.New wires the schema in automatically; doing it
			// here makes the benchmark reflect real deployments, where
			// session.token is a unique (indexed) field.
			store.SetSchema(storage.CoreSchema())
			ctx := context.Background()
			for i := 0; i < n; i++ {
				_, _ = store.Create(ctx, storage.ModelSession, map[string]any{
					"id": crypto.GenerateID(8), "token": crypto.GenerateID(16),
				})
			}
			target, _ := store.Create(ctx, storage.ModelSession, map[string]any{
				"id": "target", "token": "target-token",
			})
			_ = target
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := store.FindOne(ctx, storage.ModelSession,
					[]storage.Where{storage.W("token", "target-token")}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func sizeName(n int) string {
	switch n {
	case 100:
		return "100rows"
	case 10000:
		return "10000rows"
	}
	return "n"
}
