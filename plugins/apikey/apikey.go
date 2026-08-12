// Package apikey lets users create and manage API keys that can
// authenticate requests in place of a session, mirroring better-auth's
// api-key plugin. Keys are stored hashed; the plain key is only returned
// on creation.
package apikey

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	godevauth "github.com/go-dev-auth/go-dev-auth"
	"github.com/go-dev-auth/go-dev-auth/crypto"
	"github.com/go-dev-auth/go-dev-auth/storage"
)

// ModelAPIKey is the table storing API keys.
const ModelAPIKey = "apikey"

// Options configures the api key plugin.
type Options struct {
	// HeaderName defaults to "x-api-key".
	HeaderName string
	// KeyPrefix is prepended to generated keys (e.g. "gda_").
	KeyPrefix string
	// DefaultKeyLength is the entropy in bytes. Defaults to 32.
	DefaultKeyLength int
	// MaximumKeysPerUser defaults to unlimited (0).
	MaximumKeysPerUser int
	// RateLimit configures default request budget metadata per key.
	RateLimitMax    int
	RateLimitWindow time.Duration
	// DisableSessionForAPIKeys prevents API keys from resolving to a
	// mock session (verification endpoints still work).
	DisableSessionForAPIKeys bool
	// UsageWriteInterval throttles how often lastRequest/requestCount
	// are persisted. Defaults to 1 minute; set it negative to disable
	// usage tracking entirely and keep API-key requests read-only.
	UsageWriteInterval time.Duration
}

// Plugin implements the api key plugin.
type Plugin struct {
	opts Options
	auth *godevauth.Auth
}

// New builds the plugin.
func New(opts ...Options) *Plugin {
	var o Options
	if len(opts) > 0 {
		o = opts[0]
	}
	if o.HeaderName == "" {
		o.HeaderName = "x-api-key"
	}
	if o.DefaultKeyLength == 0 {
		o.DefaultKeyLength = 32
	}
	if o.UsageWriteInterval == 0 {
		o.UsageWriteInterval = time.Minute
	}
	return &Plugin{opts: o}
}

// ID implements godevauth.Plugin.
func (p *Plugin) ID() string { return "api-key" }

// Init implements godevauth.Plugin.
func (p *Plugin) Init(a *godevauth.Auth) error {
	p.auth = a
	return nil
}

// Schema implements godevauth.SchemaPlugin.
func (p *Plugin) Schema(s *storage.Schema) {
	s.AddTable(&storage.Table{Name: ModelAPIKey, Fields: []storage.Field{
		{Name: "id", Type: storage.FieldString, Required: true, Unique: true},
		{Name: "name", Type: storage.FieldString},
		{Name: "start", Type: storage.FieldString},
		{Name: "prefix", Type: storage.FieldString},
		{Name: "key", Type: storage.FieldText, Required: true, Index: true},
		{Name: "userId", Type: storage.FieldString, Required: true, Index: true,
			References: &storage.Reference{Model: storage.ModelUser, Field: "id", OnDelete: "cascade"}},
		{Name: "enabled", Type: storage.FieldBool, Default: true},
		{Name: "expiresAt", Type: storage.FieldTime},
		{Name: "lastRequest", Type: storage.FieldTime},
		{Name: "requestCount", Type: storage.FieldInt, Default: 0},
		{Name: "remaining", Type: storage.FieldInt},
		{Name: "metadata", Type: storage.FieldText},
		{Name: "createdAt", Type: storage.FieldTime, Required: true},
		{Name: "updatedAt", Type: storage.FieldTime, Required: true},
	}})
}

// Routes implements godevauth.Plugin.
func (p *Plugin) Routes() []godevauth.Route {
	return []godevauth.Route{
		{Method: http.MethodPost, Path: "/api-key/create", Handler: p.handleCreate},
		{Method: http.MethodGet, Path: "/api-key/get", Handler: p.handleGet},
		{Method: http.MethodGet, Path: "/api-key/list", Handler: p.handleList},
		{Method: http.MethodPost, Path: "/api-key/update", Handler: p.handleUpdate},
		{Method: http.MethodPost, Path: "/api-key/delete", Handler: p.handleDelete},
		{Method: http.MethodPost, Path: "/api-key/verify", Handler: p.handleVerify},
	}
}

// BeforeRequest implements godevauth.HookPlugin: requests carrying a
// valid API key header are treated as authenticated sessions.
func (p *Plugin) BeforeRequest(c *godevauth.Ctx) error {
	if p.opts.DisableSessionForAPIKeys {
		return nil
	}
	key := c.R.Header.Get(p.opts.HeaderName)
	if key == "" {
		return nil
	}
	rec, user, err := p.verifyKey(c.Context(), key)
	if err != nil || rec == nil {
		return nil
	}
	id, _ := rec["id"].(string)
	now := time.Now().UTC()
	p.recordUsage(c.Context(), id, rec, now)
	c.SetSession(&godevauth.SessionData{
		User: user,
		Session: &storage.Session{
			ID:        "apikey:" + id,
			UserID:    user.ID,
			Token:     "",
			ExpiresAt: now.Add(time.Minute),
			CreatedAt: now,
			UpdatedAt: now,
		},
	})
	return nil
}

// AfterRequest implements godevauth.HookPlugin.
func (p *Plugin) AfterRequest(c *godevauth.Ctx) error { return nil }

// recordUsage updates the last-seen timestamp and request counter, but
// at most once per UsageWriteInterval per key. Writing on every request
// would turn every authenticated GET into a database write and make
// read-replica routing impossible.
func (p *Plugin) recordUsage(ctx context.Context, id string, rec map[string]any, now time.Time) {
	if p.opts.UsageWriteInterval < 0 {
		return
	}
	if last, ok := rec["lastRequest"].(time.Time); ok && !last.IsZero() &&
		now.Sub(last) < p.opts.UsageWriteInterval {
		return
	}
	count, _ := rec["requestCount"].(int64)
	_, _ = p.auth.Storage().UpdateMany(ctx, ModelAPIKey,
		[]storage.Where{storage.W("id", id)},
		map[string]any{"lastRequest": now, "requestCount": count + 1, "updatedAt": now})
}

// verifyKey authenticates a key and, when the key has a request quota,
// spends exactly one unit of it.
func (p *Plugin) verifyKey(ctx context.Context, key string) (map[string]any, *storage.User, error) {
	hashed := crypto.HashToken(key)
	rec, err := p.auth.Storage().FindOne(ctx, ModelAPIKey, []storage.Where{storage.W("key", hashed)})
	if err != nil {
		return nil, nil, err
	}
	// Fail closed on anything that is not an explicit true. A value of
	// the wrong type must not read as "enabled".
	if enabled, ok := rec["enabled"].(bool); !ok || !enabled {
		return nil, nil, errors.New("apikey: disabled or malformed enabled flag")
	}
	if exp, ok := rec["expiresAt"].(time.Time); ok && !exp.IsZero() && exp.Before(time.Now()) {
		return nil, nil, errors.New("apikey: expired")
	}
	if err := p.spendQuota(ctx, rec); err != nil {
		return nil, nil, err
	}
	userID, _ := rec["userId"].(string)
	user, err := p.auth.FindUserByID(ctx, userID)
	if err != nil {
		return nil, nil, err
	}
	// An API key is a credential for a user, so it is subject to the
	// same session guards as a cookie. Without this, banning a user
	// leaves every key they created working.
	sd := &godevauth.SessionData{User: user, Session: &storage.Session{UserID: user.ID}}
	if err := p.auth.CheckSessionGuards(ctx, sd); err != nil {
		return nil, nil, err
	}
	return rec, user, nil
}

// spendQuota decrements the remaining-requests counter with a
// compare-and-set, retrying on contention. A plain read-modify-write
// would let concurrent requests overwrite each other and spend the same
// unit many times, making the quota unenforceable.
func (p *Plugin) spendQuota(ctx context.Context, rec map[string]any) error {
	raw, present := rec["remaining"]
	if !present || raw == nil {
		return nil // no quota configured: unlimited
	}
	rem, ok := raw.(int64)
	if !ok {
		// A quota that cannot be read is treated as exhausted rather
		// than unlimited.
		return errors.New("apikey: malformed remaining-requests quota")
	}
	id, _ := rec["id"].(string)
	for attempt := 0; attempt < 5; attempt++ {
		if rem <= 0 {
			return errors.New("apikey: no remaining requests")
		}
		n, err := p.auth.Storage().UpdateMany(ctx, ModelAPIKey,
			[]storage.Where{storage.W("id", id), storage.W("remaining", rem)},
			map[string]any{"remaining": rem - 1})
		if err != nil {
			return err
		}
		if n == 1 {
			rec["remaining"] = rem - 1
			return nil
		}
		// someone else won the race; re-read and try again
		fresh, err := p.auth.Storage().FindOne(ctx, ModelAPIKey, []storage.Where{storage.W("id", id)})
		if err != nil {
			return err
		}
		raw, present = fresh["remaining"], fresh["remaining"] != nil
		if !present {
			return nil // the quota was removed: unlimited
		}
		rem, ok = raw.(int64)
		if !ok {
			// Same fail-closed direction as the first read above. These
			// two branches disagreeing is how a malformed column would
			// have meant "exhausted" on one path and "unlimited" on the
			// other.
			return errors.New("apikey: malformed remaining-requests quota")
		}
	}
	return errors.New("apikey: quota update contended")
}

type createBody struct {
	Name      string         `json:"name"`
	ExpiresIn *int64         `json:"expiresIn"` // seconds
	Prefix    string         `json:"prefix"`
	Remaining *int64         `json:"remaining"`
	Metadata  map[string]any `json:"metadata"`
}

func (p *Plugin) handleCreate(c *godevauth.Ctx) error {
	sd, err := c.RequireSession()
	if err != nil {
		return err
	}
	var body createBody
	if err := c.BindJSONOptional(&body); err != nil {
		return err
	}
	ctx := c.Context()
	if p.opts.MaximumKeysPerUser > 0 {
		n, err := p.auth.Storage().Count(ctx, ModelAPIKey, []storage.Where{storage.W("userId", sd.User.ID)})
		if err != nil {
			return err
		}
		if n >= int64(p.opts.MaximumKeysPerUser) {
			return godevauth.NewAPIError(http.StatusBadRequest, "KEY_LIMIT_REACHED",
				"Maximum number of API keys reached")
		}
	}
	prefix := body.Prefix
	if prefix == "" {
		prefix = p.opts.KeyPrefix
	}
	plain := prefix + crypto.GenerateToken(p.opts.DefaultKeyLength)
	now := time.Now().UTC()
	rec := map[string]any{
		"id":           crypto.GenerateID(32),
		"name":         body.Name,
		"start":        firstN(plain, 6),
		"prefix":       prefix,
		"key":          crypto.HashToken(plain),
		"userId":       sd.User.ID,
		"enabled":      true,
		"requestCount": int64(0),
		"createdAt":    now,
		"updatedAt":    now,
	}
	if body.ExpiresIn != nil && *body.ExpiresIn > 0 {
		rec["expiresAt"] = now.Add(time.Duration(*body.ExpiresIn) * time.Second)
	}
	if body.Remaining != nil {
		rec["remaining"] = *body.Remaining
	}
	if body.Metadata != nil {
		rec["metadata"] = jsonString(body.Metadata)
	}
	if _, err := p.auth.Storage().Create(ctx, ModelAPIKey, rec); err != nil {
		return err
	}
	out := publicKeyView(rec)
	out["key"] = plain
	return c.JSON(http.StatusOK, out)
}

func (p *Plugin) userKey(c *godevauth.Ctx, id string) (map[string]any, error) {
	sd, err := c.RequireSession()
	if err != nil {
		return nil, err
	}
	rec, err := p.auth.Storage().FindOne(c.Context(), ModelAPIKey, []storage.Where{
		storage.W("id", id), storage.W("userId", sd.User.ID),
	})
	if err != nil {
		return nil, godevauth.NewAPIError(http.StatusNotFound, "KEY_NOT_FOUND", "API key not found")
	}
	return rec, nil
}

func (p *Plugin) handleGet(c *godevauth.Ctx) error {
	rec, err := p.userKey(c, c.Query("id"))
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, publicKeyView(rec))
}

func (p *Plugin) handleList(c *godevauth.Ctx) error {
	sd, err := c.RequireSession()
	if err != nil {
		return err
	}
	recs, err := p.auth.Storage().FindMany(c.Context(), ModelAPIKey,
		[]storage.Where{storage.W("userId", sd.User.ID)},
		&storage.FindOptions{SortBy: &storage.SortBy{Field: "createdAt", Direction: "desc"}})
	if err != nil {
		return err
	}
	out := make([]map[string]any, 0, len(recs))
	for _, rec := range recs {
		out = append(out, publicKeyView(rec))
	}
	return c.JSON(http.StatusOK, out)
}

type updateBody struct {
	KeyID     string  `json:"keyId"`
	Name      *string `json:"name"`
	Enabled   *bool   `json:"enabled"`
	Remaining *int64  `json:"remaining"`
}

func (p *Plugin) handleUpdate(c *godevauth.Ctx) error {
	var body updateBody
	if err := c.BindJSON(&body); err != nil {
		return err
	}
	rec, err := p.userKey(c, body.KeyID)
	if err != nil {
		return err
	}
	update := map[string]any{"updatedAt": time.Now().UTC()}
	if body.Name != nil {
		update["name"] = *body.Name
	}
	if body.Enabled != nil {
		update["enabled"] = *body.Enabled
	}
	if body.Remaining != nil {
		update["remaining"] = *body.Remaining
	}
	id, _ := rec["id"].(string)
	updated, err := p.auth.Storage().Update(c.Context(), ModelAPIKey,
		[]storage.Where{storage.W("id", id)}, update)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, publicKeyView(updated))
}

type deleteBody struct {
	KeyID string `json:"keyId"`
}

func (p *Plugin) handleDelete(c *godevauth.Ctx) error {
	var body deleteBody
	if err := c.BindJSON(&body); err != nil {
		return err
	}
	rec, err := p.userKey(c, body.KeyID)
	if err != nil {
		return err
	}
	id, _ := rec["id"].(string)
	if err := p.auth.Storage().Delete(c.Context(), ModelAPIKey, []storage.Where{storage.W("id", id)}); err != nil {
		return err
	}
	return c.JSON(http.StatusOK, map[string]any{"success": true})
}

type verifyBody struct {
	Key string `json:"key"`
}

func (p *Plugin) handleVerify(c *godevauth.Ctx) error {
	var body verifyBody
	if err := c.BindJSON(&body); err != nil {
		return err
	}
	rec, _, err := p.verifyKey(c.Context(), body.Key)
	if err != nil || rec == nil {
		return c.JSON(http.StatusOK, map[string]any{"valid": false})
	}
	return c.JSON(http.StatusOK, map[string]any{"valid": true, "key": publicKeyView(rec)})
}

func publicKeyView(rec map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range rec {
		if k == "key" {
			continue
		}
		out[k] = v
	}
	return out
}

func firstN(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func jsonString(v map[string]any) string {
	if v == nil {
		return ""
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(raw)
}

var _ godevauth.HookPlugin = (*Plugin)(nil)
var _ godevauth.SchemaPlugin = (*Plugin)(nil)
