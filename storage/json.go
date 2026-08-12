package storage

import (
	"encoding/json"
	"strconv"
	"time"
	"unicode/utf8"
)

// Hand-written JSON encoding for the two models that dominate response
// bodies.
//
// The obvious implementation — build a map[string]any and hand it to
// encoding/json — was the single largest source of allocations in the
// service: a map allocation per object, a boxed value per field, then
// reflection over all of it. Profiling the authenticated request path
// attributed roughly half of all allocations to that one pattern.
// Appending directly to a byte slice removes the map, the boxing and
// the reflection.
//
// The output is byte-for-byte identical to what encoding/json produces
// for the same string values (HTML-escaping included, so it stays safe
// to embed in a <script> block); only key order differs, which JSON does
// not consider significant. FuzzAppendJSONString enforces that.

// hexDigits is used to emit \u00XX escapes.
const hexDigits = "0123456789abcdef"

// lineSep and paragraphSep are legal inside a JSON string but terminate
// a string literal in JavaScript, so JSON embedded in a <script> block
// must escape them. encoding/json does.
const (
	lineSep      rune = 0x2028
	paragraphSep rune = 0x2029
)

// appendJSONString appends a JSON string literal, escaping exactly what
// encoding/json escapes by default (including <, > and & for HTML
// safety).
//
// "Exactly" is load-bearing and is enforced by FuzzAppendJSONString,
// which compares this function's output byte for byte against
// encoding/json. The U+2028/U+2029 rule below exists because that
// comparison found them unescaped, which would let a user-controlled
// name break out of a JavaScript string literal.
func appendJSONString(dst []byte, s string) []byte {
	dst = append(dst, '"')
	start := 0
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			if c >= ' ' && c != '"' && c != '\\' && c != '<' && c != '>' && c != '&' {
				i++
				continue
			}
			dst = append(dst, s[start:i]...)
			switch c {
			case '"':
				dst = append(dst, '\\', '"')
			case '\\':
				dst = append(dst, '\\', '\\')
			case '\n':
				dst = append(dst, '\\', 'n')
			case '\r':
				dst = append(dst, '\\', 'r')
			case '\t':
				dst = append(dst, '\\', 't')
			default:
				dst = append(dst, '\\', 'u', '0', '0', hexDigits[c>>4], hexDigits[c&0xF])
			}
			i++
			start = i
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		// A byte that is not valid UTF-8 becomes the replacement
		// character, as encoding/json does, so output is always valid
		// UTF-8. encoding/json emits the escape rather than the raw
		// character here; matching it keeps the differential exact.
		if r == utf8.RuneError && size == 1 {
			dst = append(dst, s[start:i]...)
			dst = append(dst, '\\', 'u', 'f', 'f', 'f', 'd')
			i += size
			start = i
			continue
		}
		if r == lineSep || r == paragraphSep {
			dst = append(dst, s[start:i]...)
			dst = append(dst, '\\', 'u', '2', '0', '2', hexDigits[r&0xF])
			i += size
			start = i
			continue
		}
		i += size
	}
	dst = append(dst, s[start:]...)
	return append(dst, '"')
}

func appendJSONKey(dst []byte, first *bool, key string) []byte {
	if *first {
		*first = false
	} else {
		dst = append(dst, ',')
	}
	dst = appendJSONString(dst, key)
	return append(dst, ':')
}

func appendJSONTime(dst []byte, t time.Time) []byte {
	dst = append(dst, '"')
	dst = t.AppendFormat(dst, time.RFC3339Nano)
	return append(dst, '"')
}

func appendJSONBool(dst []byte, v bool) []byte {
	if v {
		return append(dst, "true"...)
	}
	return append(dst, "false"...)
}

// appendJSONValue encodes an arbitrary extra-field value. Scalars are
// handled inline; anything else falls back to encoding/json so that
// application-defined field types keep working.
func appendJSONValue(dst []byte, v any) []byte {
	switch t := v.(type) {
	case nil:
		return append(dst, "null"...)
	case string:
		return appendJSONString(dst, t)
	case bool:
		return appendJSONBool(dst, t)
	case int:
		return strconv.AppendInt(dst, int64(t), 10)
	case int32:
		return strconv.AppendInt(dst, int64(t), 10)
	case int64:
		return strconv.AppendInt(dst, t, 10)
	case float64:
		return appendJSONFloat(dst, t)
	case float32:
		return appendJSONFloat(dst, float64(t))
	case time.Time:
		return appendJSONTime(dst, t)
	default:
		raw, err := json.Marshal(v)
		if err != nil {
			return append(dst, "null"...)
		}
		return append(dst, raw...)
	}
}

func appendJSONFloat(dst []byte, f float64) []byte {
	// Reject values JSON cannot represent rather than emitting invalid
	// output.
	if f != f || f > 1.7976931348623157e308 || f < -1.7976931348623157e308 {
		return append(dst, "null"...)
	}
	return strconv.AppendFloat(dst, f, 'g', -1, 64)
}

// appendExtra writes the caller-defined fields, skipping any name that
// would shadow a field already written. Shadowing matters: it is how a
// stray "id" or "emailVerified" in Extra could otherwise rewrite the
// authoritative value in a response.
func appendExtra(dst []byte, first *bool, extra map[string]any, reserved map[string]struct{}) []byte {
	for k, v := range extra {
		if _, taken := reserved[k]; taken {
			continue
		}
		dst = appendJSONKey(dst, first, k)
		dst = appendJSONValue(dst, v)
	}
	return dst
}

var userReserved = map[string]struct{}{
	"id": {}, "name": {}, "email": {}, "emailVerified": {},
	"image": {}, "createdAt": {}, "updatedAt": {},
}

var sessionReserved = map[string]struct{}{
	"id": {}, "userId": {}, "expiresAt": {}, "ipAddress": {},
	"userAgent": {}, "createdAt": {}, "updatedAt": {},
	// "token" is reserved so an Extra key cannot reintroduce the raw
	// session token into a response body.
	"token": {},
}

// MarshalJSON implements json.Marshaler for User, inlining Extra
// fields.
func (u *User) MarshalJSON() ([]byte, error) {
	dst := make([]byte, 0, 256+len(u.Name)+len(u.Email)+len(u.Image))
	dst = append(dst, '{')
	first := true

	dst = appendJSONKey(dst, &first, "id")
	dst = appendJSONString(dst, u.ID)
	dst = appendJSONKey(dst, &first, "name")
	dst = appendJSONString(dst, u.Name)
	dst = appendJSONKey(dst, &first, "email")
	dst = appendJSONString(dst, u.Email)
	dst = appendJSONKey(dst, &first, "emailVerified")
	dst = appendJSONBool(dst, u.EmailVerified)
	if u.Image != "" {
		dst = appendJSONKey(dst, &first, "image")
		dst = appendJSONString(dst, u.Image)
	}
	dst = appendJSONKey(dst, &first, "createdAt")
	dst = appendJSONTime(dst, u.CreatedAt)
	dst = appendJSONKey(dst, &first, "updatedAt")
	dst = appendJSONTime(dst, u.UpdatedAt)

	dst = appendExtra(dst, &first, u.Extra, userReserved)
	return append(dst, '}'), nil
}

// MarshalJSON implements json.Marshaler for Session, inlining Extra
// fields.
//
// The raw session token is deliberately omitted: it is a bearer
// credential equivalent to the password, and endpoints like
// /list-sessions would otherwise hand every one of a user's device
// tokens to any script that can read the response. Sign-in responses
// return the current token explicitly at the top level for clients that
// need it.
func (s *Session) MarshalJSON() ([]byte, error) {
	dst := make([]byte, 0, 256+len(s.IPAddress)+len(s.UserAgent))
	dst = append(dst, '{')
	first := true

	dst = appendJSONKey(dst, &first, "id")
	dst = appendJSONString(dst, s.ID)
	dst = appendJSONKey(dst, &first, "userId")
	dst = appendJSONString(dst, s.UserID)
	dst = appendJSONKey(dst, &first, "expiresAt")
	dst = appendJSONTime(dst, s.ExpiresAt)
	if s.IPAddress != "" {
		dst = appendJSONKey(dst, &first, "ipAddress")
		dst = appendJSONString(dst, s.IPAddress)
	}
	if s.UserAgent != "" {
		dst = appendJSONKey(dst, &first, "userAgent")
		dst = appendJSONString(dst, s.UserAgent)
	}
	dst = appendJSONKey(dst, &first, "createdAt")
	dst = appendJSONTime(dst, s.CreatedAt)
	dst = appendJSONKey(dst, &first, "updatedAt")
	dst = appendJSONTime(dst, s.UpdatedAt)

	dst = appendExtra(dst, &first, s.Extra, sessionReserved)
	return append(dst, '}'), nil
}
