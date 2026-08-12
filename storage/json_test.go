package storage

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

// referenceUserJSON is the encoding the previous map-based
// implementation produced. The hand-written encoder must agree with it
// field for field.
func referenceUserJSON(u *User) ([]byte, error) {
	m := map[string]any{
		"id":            u.ID,
		"name":          u.Name,
		"email":         u.Email,
		"emailVerified": u.EmailVerified,
		"createdAt":     u.CreatedAt,
		"updatedAt":     u.UpdatedAt,
	}
	if u.Image != "" {
		m["image"] = u.Image
	}
	for k, v := range u.Extra {
		if _, exists := m[k]; !exists {
			m[k] = v
		}
	}
	return json.Marshal(m)
}

func referenceSessionJSON(s *Session) ([]byte, error) {
	m := map[string]any{
		"id":        s.ID,
		"userId":    s.UserID,
		"expiresAt": s.ExpiresAt,
		"createdAt": s.CreatedAt,
		"updatedAt": s.UpdatedAt,
	}
	if s.IPAddress != "" {
		m["ipAddress"] = s.IPAddress
	}
	if s.UserAgent != "" {
		m["userAgent"] = s.UserAgent
	}
	for k, v := range s.Extra {
		if _, exists := m[k]; !exists {
			m[k] = v
		}
	}
	return json.Marshal(m)
}

// asMap decodes JSON so the comparison ignores key order, which JSON
// does not consider significant.
func asMap(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, raw)
	}
	return m
}

func TestUserMarshalMatchesEncodingJSON(t *testing.T) {
	now := time.Date(2026, 3, 4, 5, 6, 7, 89000000, time.UTC)
	cases := []*User{
		{},
		{ID: "u1", Name: "Alice", Email: "a@example.com", EmailVerified: true, CreatedAt: now, UpdatedAt: now},
		{ID: "u2", Name: "With Image", Image: "https://example.com/a.png", CreatedAt: now, UpdatedAt: now},
		// characters that must be escaped: quotes, backslashes, control
		// codes, HTML-significant characters, non-ASCII, invalid UTF-8
		{ID: "u3", Name: `He said "hi" \ back` + "\n\t", Email: "<script>&</script>@x.com"},
		{ID: "u4", Name: "Ünïcödé ✓ 日本語 🎉"},
		{ID: "u5", Name: string([]byte{0x80, 0x81, 'a'})},
		{ID: "u6", Name: "ctrl\x00\x01\x1f"},
		// extra fields of every supported kind
		{ID: "u7", Extra: map[string]any{
			"str": "s", "bool": true, "int": 42, "int64": int64(-9007199254740991),
			"float": 1.5, "time": now, "nil": nil,
			"nested": map[string]any{"a": []any{1.0, "two", false}},
		}},
		// Extra must never shadow an authoritative field
		{ID: "real-id", Email: "real@example.com", Extra: map[string]any{
			"id": "spoofed", "email": "spoofed@example.com", "emailVerified": true,
		}},
	}
	for _, u := range cases {
		t.Run(u.ID, func(t *testing.T) {
			got, err := json.Marshal(u)
			if err != nil {
				t.Fatal(err)
			}
			want, err := referenceUserJSON(u)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(asMap(t, got), asMap(t, want)) {
				t.Fatalf("encoding differs\n got: %s\nwant: %s", got, want)
			}
		})
	}
}

func TestSessionMarshalMatchesEncodingJSON(t *testing.T) {
	now := time.Date(2026, 3, 4, 5, 6, 7, 89000000, time.UTC)
	cases := []*Session{
		{},
		{ID: "s1", UserID: "u1", ExpiresAt: now, CreatedAt: now, UpdatedAt: now},
		{ID: "s2", UserID: "u1", IPAddress: "203.0.113.7", UserAgent: `Mozilla/5.0 "quoted"`},
		{ID: "s3", Extra: map[string]any{"activeOrganizationId": "org1", "impersonatedBy": "admin1"}},
	}
	for _, s := range cases {
		t.Run(s.ID, func(t *testing.T) {
			got, err := json.Marshal(s)
			if err != nil {
				t.Fatal(err)
			}
			want, err := referenceSessionJSON(s)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(asMap(t, got), asMap(t, want)) {
				t.Fatalf("encoding differs\n got: %s\nwant: %s", got, want)
			}
		})
	}
}

// TestSessionMarshalNeverLeaksToken is the security property the
// encoder must hold: the raw bearer token stays out of response bodies,
// and an Extra key cannot smuggle it back in.
func TestSessionMarshalNeverLeaksToken(t *testing.T) {
	s := &Session{
		ID: "s1", UserID: "u1", Token: "super-secret-token-value",
		Extra: map[string]any{"token": "super-secret-token-value"},
	}
	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "super-secret-token-value") {
		t.Fatalf("session JSON leaked the raw token: %s", raw)
	}
}

// TestMarshalEscapesHTML pins that output stays safe to embed in a
// <script> block, matching encoding/json's default behaviour.
func TestMarshalEscapesHTML(t *testing.T) {
	u := &User{ID: "u1", Name: `</script><script>alert(1)</script>`}
	raw, err := json.Marshal(u)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "<script>") {
		t.Fatalf("HTML was not escaped: %s", raw)
	}
	if !strings.Contains(string(raw), `\u003c`) {
		t.Fatalf("expected the < to be escaped as \\u003c: %s", raw)
	}
}

// TestMarshalAlwaysValidUTF8 asserts invalid input bytes cannot produce
// invalid JSON.
func TestMarshalAlwaysValidUTF8(t *testing.T) {
	u := &User{ID: "u1", Name: string([]byte{0xff, 0xfe, 0x00, 0x41, 0xc3})}
	raw, err := json.Marshal(u)
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("produced invalid JSON: %v\n%s", err, raw)
	}
}

func BenchmarkUserMarshal(b *testing.B) {
	now := time.Now()
	u := &User{
		ID: "01234567890123456789012345678901", Name: "Benchmark User",
		Email: "bench@example.com", EmailVerified: true, CreatedAt: now, UpdatedAt: now,
		Extra: map[string]any{"role": "user", "banned": false},
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := json.Marshal(u); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkUserMarshalReference(b *testing.B) {
	now := time.Now()
	u := &User{
		ID: "01234567890123456789012345678901", Name: "Benchmark User",
		Email: "bench@example.com", EmailVerified: true, CreatedAt: now, UpdatedAt: now,
		Extra: map[string]any{"role": "user", "banned": false},
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := referenceUserJSON(u); err != nil {
			b.Fatal(err)
		}
	}
}
