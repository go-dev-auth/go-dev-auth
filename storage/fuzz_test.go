package storage

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// Differential fuzzing for the hand-written JSON encoders.
//
// json.go replaced `map[string]any` plus reflection with direct byte
// appends. That is the kind of optimisation that is correct until it is
// not, and the failure mode is a response body that differs from what
// encoding/json would have produced — which, for the escaping rules,
// means a script-injection hole rather than a cosmetic difference.
//
// Each target compares three ways: byte for byte against an independent
// naive reimplementation, decoded-value equality against encoding/json,
// and a set of standing invariants that keep the output safe to embed in
// a <script> block.
//
//	go test -run '^$' -fuzz=FuzzAppendJSONString -fuzztime=30s ./storage/...

// JavaScript line terminators. They are legal inside a JSON string but
// terminate a string literal in JavaScript, so JSON embedded in a
// <script> block must escape them. encoding/json does.
var (
	lineSeparator      = string(rune(0x2028))
	paragraphSeparator = string(rune(0x2029))
)

// naiveJSONString is an independent, deliberately unoptimised
// implementation of the same escaping rules: one rune at a time, no
// run-slicing, no shared cursor. appendJSONString is the fast version of
// this, and the interesting class of bug in it is an off-by-one in the
// `start`/`i` bookkeeping that silently drops or duplicates a run of
// bytes. Comparing the two catches that; comparing only against
// encoding/json would not: its exact escape choices have changed between
// Go releases (1.26 emits the two-character escape for form feed where
// 1.22 emitted the six-character one), so a byte-exact comparison
// against the standard library is not stable across the toolchains this
// repository supports. Decoded-value equality against encoding/json is,
// and is asserted separately.
func naiveJSONString(s string) []byte {
	out := []byte{'"'}
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		switch {
		case r == utf8.RuneError && size == 1:
			out = append(out, '\\', 'u', 'f', 'f', 'f', 'd')
		case r == '"':
			out = append(out, `\"`...)
		case r == '\\':
			out = append(out, `\\`...)
		case r == '\n':
			out = append(out, `\n`...)
		case r == '\r':
			out = append(out, `\r`...)
		case r == '\t':
			out = append(out, `\t`...)
		case r < 0x20:
			out = append(out, fmt.Sprintf(`\u%04x`, r)...)
		case r == '<' || r == '>' || r == '&':
			out = append(out, fmt.Sprintf(`\u%04x`, r)...)
		case r == 0x2028 || r == 0x2029:
			out = append(out, fmt.Sprintf(`\u%04x`, r)...)
		default:
			out = utf8.AppendRune(out, r)
		}
	}
	return append(out, '"')
}

// FuzzAppendJSONString is the differential. Three properties, in
// increasing order of how badly a violation would hurt:
//
//  1. byte-for-byte agreement with naiveJSONString, the independent
//     reimplementation above;
//  2. the decoded value agrees with what encoding/json produces, so the
//     optimisation cannot change what a client actually receives;
//  3. the output is safe to interpolate into a <script> block.
func FuzzAppendJSONString(f *testing.F) {
	f.Add("")
	f.Add("plain")
	f.Add(`quote " backslash \ slash /`)
	f.Add("<script>alert(1)</script>")
	f.Add("amp & lt < gt >")
	f.Add("tab\tnewline\ncarriage\r")
	f.Add("ctrl\x00\x01\x1f\x7f")
	f.Add("unicode: é 日本語 \U0001F389")
	f.Add(string([]byte{0x80, 0x81, 'a'}))
	f.Add(string([]byte{0xff, 0xfe, 0x00, 0x41, 0xc3}))
	f.Add(lineSeparator)
	f.Add(paragraphSeparator)
	f.Add("before" + lineSeparator + "after")
	f.Add("�")                // a legitimately encoded replacement char
	f.Add("\xed\xa0\x80")     // UTF-16 surrogate half, invalid in UTF-8
	f.Add("\xc3")             // truncated two-byte sequence
	f.Add("\xf4\x90\x80\x80") // beyond U+10FFFF
	f.Add(strings.Repeat("a", 1000) + lineSeparator)

	f.Fuzz(func(t *testing.T, s string) {
		got := appendJSONString(nil, s)

		if want := naiveJSONString(s); !bytes.Equal(got, want) {
			t.Fatalf("appendJSONString differs from the reference implementation\ninput: %q\n got: %s\nwant: %s", s, got, want)
		}

		// What a client receives must be unchanged by the optimisation.
		stdlib, err := json.Marshal(s)
		if err != nil {
			t.Fatalf("encoding/json refused %q: %v", s, err)
		}
		var gotVal, wantVal string
		if err := json.Unmarshal(got, &gotVal); err != nil {
			t.Fatalf("appendJSONString produced unparseable JSON for %q: %s (%v)", s, got, err)
		}
		if err := json.Unmarshal(stdlib, &wantVal); err != nil {
			t.Fatalf("encoding/json produced unparseable JSON for %q: %s (%v)", s, stdlib, err)
		}
		if gotVal != wantVal {
			t.Fatalf("decoded value differs from encoding/json\ninput: %q\n got: %q\nwant: %q", s, gotVal, wantVal)
		}

		assertScriptSafe(t, got, s)
	})
}

// assertScriptSafe checks the invariants that let a response body be
// interpolated into an HTML <script> block: valid UTF-8, no raw
// HTML-significant characters, and no raw JavaScript line terminators.
func assertScriptSafe(t *testing.T, encoded []byte, input string) {
	t.Helper()
	if !utf8.Valid(encoded) {
		t.Fatalf("encoding %q produced invalid UTF-8: %q", input, encoded)
	}
	for _, bad := range []string{"<", ">", "&"} {
		if bytes.Contains(encoded, []byte(bad)) {
			t.Fatalf("encoding %q left a raw %q in the output: %s", input, bad, encoded)
		}
	}
	for name, bad := range map[string]string{
		"U+2028 LINE SEPARATOR":      lineSeparator,
		"U+2029 PARAGRAPH SEPARATOR": paragraphSeparator,
	} {
		if bytes.Contains(encoded, []byte(bad)) {
			t.Fatalf("encoding %q left a raw %s in the output: %q", input, name, encoded)
		}
	}
	// The result must round-trip through a JSON parser.
	var back any
	if err := json.Unmarshal(encoded, &back); err != nil {
		t.Fatalf("encoding %q produced unparseable JSON %s: %v", input, encoded, err)
	}
}

// referenceUserMap is the map-based encoding the hand-written one
// replaced. It is the behavioural contract for FuzzUserMarshalJSON.
func referenceUserMap(u *User) map[string]any {
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
	return m
}

// FuzzUserMarshalJSON drives User.MarshalJSON with arbitrary field
// values, including an arbitrary Extra key/value pair, and requires the
// result to decode to exactly what encoding/json would have produced
// from the equivalent map.
//
// Key order is not compared: JSON does not consider it significant, and
// the map form has no stable order anyway.
func FuzzUserMarshalJSON(f *testing.F) {
	f.Add("u1", "Alice", "a@example.com", "", true, "role", "admin")
	f.Add("", "", "", "", false, "", "")
	f.Add("u2", `</script><script>`, "<&>", "https://x/a.png", true, "x", lineSeparator)
	f.Add("u3", string([]byte{0xff, 0x80}), "e", "i", false, string([]byte{0xc3}), "v")
	f.Add("u4", "n", "e", "i", true, "id", "spoofed")
	f.Add("u5", "n", "e", "i", true, "emailVerified", "spoofed")
	f.Add("u6", "\x00\x01\x1f", "\t\n\r", "\\\"", false, "k"+paragraphSeparator, "v"+lineSeparator)

	f.Fuzz(func(t *testing.T, id, name, email, image string, verified bool, extraKey, extraVal string) {
		ts := time.Date(2026, 3, 4, 5, 6, 7, 89000000, time.UTC)
		u := &User{
			ID: id, Name: name, Email: email, Image: image,
			EmailVerified: verified,
			CreatedAt:     ts, UpdatedAt: ts,
			Extra: map[string]any{extraKey: extraVal},
		}

		got, err := json.Marshal(u)
		if err != nil {
			t.Fatalf("User.MarshalJSON failed: %v", err)
		}
		want, err := json.Marshal(referenceUserMap(u))
		if err != nil {
			t.Fatalf("reference encoding failed: %v", err)
		}

		var gotMap, wantMap map[string]any
		if err := json.Unmarshal(got, &gotMap); err != nil {
			t.Fatalf("hand-written encoder produced invalid JSON: %v\n%s", err, got)
		}
		if err := json.Unmarshal(want, &wantMap); err != nil {
			t.Fatalf("reference produced invalid JSON: %v\n%s", err, want)
		}
		if !reflect.DeepEqual(gotMap, wantMap) {
			t.Fatalf("User encoding differs\n got: %s\nwant: %s", got, want)
		}

		// The authoritative fields must survive whatever Extra contains:
		// this is the mass-assignment guard, stated directly.
		if gotMap["id"] != any(coerceInvalidUTF8(id)) {
			t.Fatalf("Extra[%q] rewrote the id: got %v, want %q", extraKey, gotMap["id"], id)
		}
		if gotMap["emailVerified"] != any(verified) {
			t.Fatalf("Extra[%q] rewrote emailVerified: got %v, want %v", extraKey, gotMap["emailVerified"], verified)
		}
		assertScriptSafe(t, got, name+email+image+extraKey+extraVal)
	})
}

// coerceInvalidUTF8 mirrors what a JSON round trip does to invalid input
// bytes, so string comparisons after Unmarshal are meaningful. Each
// invalid byte becomes one replacement character, which is what
// encoding/json does — not one per invalid run, which is what
// strings.ToValidUTF8 would do.
func coerceInvalidUTF8(s string) string {
	if utf8.ValidString(s) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			b.WriteRune(utf8.RuneError)
		} else {
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	return b.String()
}

// sessionTokenSentinel stands in for a real bearer token. It is not a
// fuzzer input: the token is minted by the server, never by the caller,
// and holding it fixed lets the leak assertion below be exact instead of
// having to guess whether a short fuzzed token coincidentally matches
// some other field.
const sessionTokenSentinel = "TOKEN-SENTINEL-6f2a91c4d0e7"

// FuzzSessionMarshalJSON is the same differential for Session, with the
// additional standing property that the raw bearer token must never
// appear in the output — not as the Token field and not smuggled back in
// through Extra.
func FuzzSessionMarshalJSON(f *testing.F) {
	f.Add("s1", "u1", "203.0.113.7", "Mozilla/5.0", "activeOrganizationId", "org1")
	f.Add("", "", "", "", "", "")
	f.Add("s2", "u1", "<&>", `"quoted"`, "token", sessionTokenSentinel)
	f.Add("s3", "u1", lineSeparator, paragraphSeparator, "k", "v")
	f.Add("s4", "u1", string([]byte{0xff}), string([]byte{0x80}), "impersonatedBy", "admin1")
	f.Add("s5", sessionTokenSentinel, "ip", "ua", "userId", "spoofed")

	f.Fuzz(func(t *testing.T, id, userID, ip, ua, extraKey, extraVal string) {
		ts := time.Date(2026, 3, 4, 5, 6, 7, 89000000, time.UTC)
		s := &Session{
			ID: id, UserID: userID, Token: sessionTokenSentinel,
			ExpiresAt: ts, IPAddress: ip, UserAgent: ua,
			CreatedAt: ts, UpdatedAt: ts,
			Extra: map[string]any{extraKey: extraVal},
		}

		got, err := json.Marshal(s)
		if err != nil {
			t.Fatalf("Session.MarshalJSON failed: %v", err)
		}

		var gotMap map[string]any
		if err := json.Unmarshal(got, &gotMap); err != nil {
			t.Fatalf("hand-written encoder produced invalid JSON: %v\n%s", err, got)
		}
		if !reflect.DeepEqual(gotMap, referenceSessionMap(s)) {
			t.Fatalf("Session encoding differs\n got: %v\nwant: %v", gotMap, referenceSessionMap(s))
		}
		if _, present := gotMap["token"]; present {
			t.Fatalf("session JSON contains a %q key: %s", "token", got)
		}
		// The only way the sentinel may appear is if the caller put it
		// in one of the echoed fields themselves.
		echoed := id + userID + ip + ua + extraKey + extraVal
		if !strings.Contains(echoed, sessionTokenSentinel) && bytes.Contains(got, []byte(sessionTokenSentinel)) {
			t.Fatalf("session JSON leaked the raw token: %s", got)
		}
		assertScriptSafe(t, got, echoed)
	})
}

// referenceSessionMap is what the map-based encoder produced, decoded
// back into the shape json.Unmarshal yields, so the two can be compared
// without depending on key order.
func referenceSessionMap(s *Session) map[string]any {
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
		if _, exists := m[k]; !exists && k != "token" {
			m[k] = v
		}
	}
	raw, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		panic(err)
	}
	return out
}
