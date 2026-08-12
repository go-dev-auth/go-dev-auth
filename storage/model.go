package storage

import "time"

// User is the core user model.
type User struct {
	ID            string         `json:"id"`
	Name          string         `json:"name"`
	Email         string         `json:"email"`
	EmailVerified bool           `json:"emailVerified"`
	Image         string         `json:"image,omitempty"`
	CreatedAt     time.Time      `json:"createdAt"`
	UpdatedAt     time.Time      `json:"updatedAt"`
	Extra         map[string]any `json:"-"`
}

// Session is the core session model.
type Session struct {
	ID        string         `json:"id"`
	UserID    string         `json:"userId"`
	Token     string         `json:"token"`
	ExpiresAt time.Time      `json:"expiresAt"`
	IPAddress string         `json:"ipAddress,omitempty"`
	UserAgent string         `json:"userAgent,omitempty"`
	CreatedAt time.Time      `json:"createdAt"`
	UpdatedAt time.Time      `json:"updatedAt"`
	Extra     map[string]any `json:"-"`
}

// Account links a user to an authentication method: either a credential
// (email/password, where Password is set) or a social/OAuth provider.
type Account struct {
	ID                    string         `json:"id"`
	UserID                string         `json:"userId"`
	AccountID             string         `json:"accountId"`
	ProviderID            string         `json:"providerId"`
	AccessToken           string         `json:"-"`
	RefreshToken          string         `json:"-"`
	IDToken               string         `json:"-"`
	AccessTokenExpiresAt  time.Time      `json:"accessTokenExpiresAt,omitempty"`
	RefreshTokenExpiresAt time.Time      `json:"refreshTokenExpiresAt,omitempty"`
	Scope                 string         `json:"scope,omitempty"`
	Password              string         `json:"-"`
	CreatedAt             time.Time      `json:"createdAt"`
	UpdatedAt             time.Time      `json:"updatedAt"`
	Extra                 map[string]any `json:"-"`
}

// Verification stores short lived verification values
// (email verification, password reset, magic links, OAuth state, ...).
type Verification struct {
	ID         string    `json:"id"`
	Identifier string    `json:"identifier"`
	Value      string    `json:"value"`
	ExpiresAt  time.Time `json:"expiresAt"`
	CreatedAt  time.Time `json:"createdAt"`
	UpdatedAt  time.Time `json:"updatedAt"`
}

// Model names for the core tables.
const (
	ModelUser         = "user"
	ModelSession      = "session"
	ModelAccount      = "account"
	ModelVerification = "verification"
)

// UserToMap converts a User to a generic record.
func UserToMap(u *User) map[string]any {
	m := map[string]any{
		"id":            u.ID,
		"name":          u.Name,
		"email":         u.Email,
		"emailVerified": u.EmailVerified,
		"image":         u.Image,
		"createdAt":     u.CreatedAt,
		"updatedAt":     u.UpdatedAt,
	}
	for k, v := range u.Extra {
		m[k] = v
	}
	return m
}

// UserFromMap converts a generic record to a User.
func UserFromMap(m map[string]any) *User {
	if m == nil {
		return nil
	}
	u := &User{
		ID:            str(m["id"]),
		Name:          str(m["name"]),
		Email:         str(m["email"]),
		EmailVerified: boolean(m["emailVerified"]),
		Image:         str(m["image"]),
		CreatedAt:     timeVal(m["createdAt"]),
		UpdatedAt:     timeVal(m["updatedAt"]),
		Extra:         map[string]any{},
	}
	for k, v := range m {
		switch k {
		case "id", "name", "email", "emailVerified", "image", "createdAt", "updatedAt":
		default:
			u.Extra[k] = v
		}
	}
	return u
}

// SessionToMap converts a Session to a generic record.
func SessionToMap(s *Session) map[string]any {
	m := map[string]any{
		"id":        s.ID,
		"userId":    s.UserID,
		"token":     s.Token,
		"expiresAt": s.ExpiresAt,
		"ipAddress": s.IPAddress,
		"userAgent": s.UserAgent,
		"createdAt": s.CreatedAt,
		"updatedAt": s.UpdatedAt,
	}
	for k, v := range s.Extra {
		m[k] = v
	}
	return m
}

// SessionFromMap converts a generic record to a Session.
func SessionFromMap(m map[string]any) *Session {
	if m == nil {
		return nil
	}
	s := &Session{
		ID:        str(m["id"]),
		UserID:    str(m["userId"]),
		Token:     str(m["token"]),
		ExpiresAt: timeVal(m["expiresAt"]),
		IPAddress: str(m["ipAddress"]),
		UserAgent: str(m["userAgent"]),
		CreatedAt: timeVal(m["createdAt"]),
		UpdatedAt: timeVal(m["updatedAt"]),
		Extra:     map[string]any{},
	}
	for k, v := range m {
		switch k {
		case "id", "userId", "token", "expiresAt", "ipAddress", "userAgent", "createdAt", "updatedAt":
		default:
			s.Extra[k] = v
		}
	}
	return s
}

// AccountToMap converts an Account to a generic record.
func AccountToMap(a *Account) map[string]any {
	m := map[string]any{
		"id":                    a.ID,
		"userId":                a.UserID,
		"accountId":             a.AccountID,
		"providerId":            a.ProviderID,
		"accessToken":           a.AccessToken,
		"refreshToken":          a.RefreshToken,
		"idToken":               a.IDToken,
		"accessTokenExpiresAt":  a.AccessTokenExpiresAt,
		"refreshTokenExpiresAt": a.RefreshTokenExpiresAt,
		"scope":                 a.Scope,
		"password":              a.Password,
		"createdAt":             a.CreatedAt,
		"updatedAt":             a.UpdatedAt,
	}
	for k, v := range a.Extra {
		m[k] = v
	}
	return m
}

// AccountFromMap converts a generic record to an Account.
func AccountFromMap(m map[string]any) *Account {
	if m == nil {
		return nil
	}
	a := &Account{
		ID:                    str(m["id"]),
		UserID:                str(m["userId"]),
		AccountID:             str(m["accountId"]),
		ProviderID:            str(m["providerId"]),
		AccessToken:           str(m["accessToken"]),
		RefreshToken:          str(m["refreshToken"]),
		IDToken:               str(m["idToken"]),
		AccessTokenExpiresAt:  timeVal(m["accessTokenExpiresAt"]),
		RefreshTokenExpiresAt: timeVal(m["refreshTokenExpiresAt"]),
		Scope:                 str(m["scope"]),
		Password:              str(m["password"]),
		CreatedAt:             timeVal(m["createdAt"]),
		UpdatedAt:             timeVal(m["updatedAt"]),
		Extra:                 map[string]any{},
	}
	for k, v := range m {
		switch k {
		case "id", "userId", "accountId", "providerId", "accessToken", "refreshToken",
			"idToken", "accessTokenExpiresAt", "refreshTokenExpiresAt", "scope",
			"password", "createdAt", "updatedAt":
		default:
			a.Extra[k] = v
		}
	}
	return a
}

// VerificationToMap converts a Verification to a generic record.
func VerificationToMap(v *Verification) map[string]any {
	return map[string]any{
		"id":         v.ID,
		"identifier": v.Identifier,
		"value":      v.Value,
		"expiresAt":  v.ExpiresAt,
		"createdAt":  v.CreatedAt,
		"updatedAt":  v.UpdatedAt,
	}
}

// VerificationFromMap converts a generic record to a Verification.
func VerificationFromMap(m map[string]any) *Verification {
	if m == nil {
		return nil
	}
	return &Verification{
		ID:         str(m["id"]),
		Identifier: str(m["identifier"]),
		Value:      str(m["value"]),
		ExpiresAt:  timeVal(m["expiresAt"]),
		CreatedAt:  timeVal(m["createdAt"]),
		UpdatedAt:  timeVal(m["updatedAt"]),
	}
}

func str(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func boolean(v any) bool {
	if v == nil {
		return false
	}
	switch t := v.(type) {
	case bool:
		return t
	case int64:
		return t != 0
	case int:
		return t != 0
	case float64:
		return t != 0
	}
	return false
}

func timeVal(v any) time.Time {
	if v == nil {
		return time.Time{}
	}
	switch t := v.(type) {
	case time.Time:
		return t
	case string:
		ts, err := time.Parse(time.RFC3339Nano, t)
		if err == nil {
			return ts
		}
	case int64:
		return time.UnixMilli(t)
	case float64:
		return time.UnixMilli(int64(t))
	}
	return time.Time{}
}
