// Package passkey implements WebAuthn passkey registration and
// sign-in. Port of better-auth's passkey plugin, with no external
// dependencies: the CBOR/COSE parsing and signature verification live
// in this package and cover exactly the shapes WebAuthn produces.
//
//	auth, _ := godevauth.New(godevauth.Config{
//		// ...
//		Plugins: []godevauth.Plugin{passkey.New(passkey.Options{})},
//	})
//
// Registration requires a fresh session (adding a credential is as
// sensitive as setting a password); sign-in relies on discoverable
// credentials, so the browser prompts for any passkey the user holds
// for this site. Attestation is not verified ("none" policy, the
// better-auth default): the plugin trusts the authenticator's public
// key without vouching for the authenticator's make and model.
package passkey

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	godevauth "github.com/go-dev-auth/go-dev-auth"
	gcrypto "github.com/go-dev-auth/go-dev-auth/crypto"
	"github.com/go-dev-auth/go-dev-auth/ratelimit"
	"github.com/go-dev-auth/go-dev-auth/storage"
)

// ModelPasskey is the credential table name.
const ModelPasskey = "passkey"

const (
	tokenKindRegister     = "passkey-register"
	tokenKindAuthenticate = "passkey-authenticate"
)

// Options configures the passkey plugin.
type Options struct {
	// RPID is the WebAuthn relying-party id — the domain credentials
	// are scoped to. Defaults to the host of Config.BaseURL (without
	// port). Set it explicitly when the app spans subdomains.
	RPID string
	// RPName is the human-readable relying-party name shown by
	// authenticator UIs. Defaults to Config.AppName, then RPID.
	RPName string
	// Origins are the web origins allowed in clientDataJSON, e.g.
	// "https://app.example.com". The Config.BaseURL origin is always
	// allowed; list any additional frontend origins here.
	Origins []string
	// UserVerification is "required", "preferred" (default) or
	// "discouraged". With "required", assertions whose UV flag is
	// unset are rejected.
	UserVerification string
	// ChallengeTTL bounds how long issued challenges stay redeemable.
	// Defaults to 5 minutes.
	ChallengeTTL time.Duration
	// MaxPasskeysPerUser caps registered credentials per account.
	// Defaults to 10.
	MaxPasskeysPerUser int
}

// Plugin implements WebAuthn passkeys.
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
	if o.UserVerification == "" {
		o.UserVerification = "preferred"
	}
	if o.ChallengeTTL <= 0 {
		o.ChallengeTTL = 5 * time.Minute
	}
	if o.MaxPasskeysPerUser <= 0 {
		o.MaxPasskeysPerUser = 10
	}
	return &Plugin{opts: o}
}

// ID implements godevauth.Plugin.
func (p *Plugin) ID() string { return "passkey" }

// Init implements godevauth.Plugin.
func (p *Plugin) Init(a *godevauth.Auth) error {
	p.auth = a
	base, err := url.Parse(a.Config().BaseURL)
	if err != nil || base.Host == "" {
		return errors.New("passkey: Config.BaseURL must be a valid URL")
	}
	if p.opts.RPID == "" {
		p.opts.RPID = base.Hostname()
	}
	if p.opts.RPName == "" {
		p.opts.RPName = a.Config().AppName
	}
	if p.opts.RPName == "" {
		p.opts.RPName = p.opts.RPID
	}
	// The base origin is always acceptable; extra frontend origins are
	// opt-in and validated once here rather than per request.
	origin := base.Scheme + "://" + base.Host
	origins := []string{origin}
	for _, o := range p.opts.Origins {
		o = strings.TrimSuffix(o, "/")
		u, err := url.Parse(o)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return errors.New("passkey: Options.Origins entries must be scheme://host origins")
		}
		if o != origin {
			origins = append(origins, o)
		}
	}
	p.opts.Origins = origins
	switch p.opts.UserVerification {
	case "required", "preferred", "discouraged":
	default:
		return errors.New(`passkey: UserVerification must be "required", "preferred" or "discouraged"`)
	}
	return nil
}

// Schema implements godevauth.SchemaPlugin. The table matches
// better-auth's passkey model field for field.
func (p *Plugin) Schema(s *storage.Schema) {
	s.AddTable(&storage.Table{Name: ModelPasskey, Fields: []storage.Field{
		{Name: "id", Type: storage.FieldString, Required: true, Unique: true},
		{Name: "name", Type: storage.FieldString},
		{Name: "publicKey", Type: storage.FieldText, Required: true},
		{Name: "userId", Type: storage.FieldString, Required: true, Index: true,
			References: &storage.Reference{Model: storage.ModelUser, Field: "id", OnDelete: "cascade"}},
		{Name: "credentialID", Type: storage.FieldText, Required: true, Unique: true},
		{Name: "counter", Type: storage.FieldInt, Default: 0},
		{Name: "deviceType", Type: storage.FieldString},
		{Name: "backedUp", Type: storage.FieldBool, Default: false},
		{Name: "transports", Type: storage.FieldString},
		{Name: "aaguid", Type: storage.FieldString},
		{Name: "createdAt", Type: storage.FieldTime, Required: true},
	}})
}

// Routes implements godevauth.Plugin. Route names follow better-auth's
// passkey plugin so existing clients port over.
func (p *Plugin) Routes() []godevauth.Route {
	// The verification endpoints are credential oracles and carry the
	// same strict limit as password sign-in.
	strict := &ratelimit.Rule{Window: 10 * time.Second, Max: 3}
	moderate := &ratelimit.Rule{Window: 10 * time.Second, Max: 5}
	return []godevauth.Route{
		{Method: http.MethodGet, Path: "/passkey/generate-register-options", Handler: p.handleRegisterOptions, RateLimit: moderate},
		{Method: http.MethodPost, Path: "/passkey/verify-registration", Handler: p.handleVerifyRegistration, RateLimit: strict},
		{Method: http.MethodPost, Path: "/passkey/generate-authenticate-options", Handler: p.handleAuthenticateOptions, RateLimit: moderate},
		{Method: http.MethodPost, Path: "/passkey/verify-authentication", Handler: p.handleVerifyAuthentication, RateLimit: strict},
		{Method: http.MethodGet, Path: "/passkey/list-user-passkeys", Handler: p.handleList},
		{Method: http.MethodPost, Path: "/passkey/delete-passkey", Handler: p.handleDelete},
		{Method: http.MethodPost, Path: "/passkey/update-passkey", Handler: p.handleUpdate},
	}
}

// ---- registration ----

func (p *Plugin) handleRegisterOptions(c *godevauth.Ctx) error {
	sd, err := c.RequireSession()
	if err != nil {
		return err
	}
	// Adding a credential that can sign the user in forever is as
	// sensitive as setting a password, so a stale remembered session
	// is not enough.
	if !p.auth.IsFresh(sd.Session) {
		return godevauth.ErrSessionNotFresh
	}
	ctx := c.Context()
	existing, err := p.userPasskeys(ctx, sd.User.ID)
	if err != nil {
		return err
	}
	if len(existing) >= p.opts.MaxPasskeysPerUser {
		return godevauth.NewAPIError(http.StatusBadRequest, "TOO_MANY_PASSKEYS",
			"Passkey limit reached for this account")
	}

	challenge := gcrypto.GenerateToken(32)
	if err := p.auth.StoreTokenValue(ctx, tokenKindRegister, challenge, sd.User.ID, p.opts.ChallengeTTL); err != nil {
		return err
	}

	exclude := make([]map[string]any, 0, len(existing))
	for _, pk := range existing {
		exclude = append(exclude, map[string]any{
			"type": "public-key", "id": pk["credentialID"],
		})
	}
	return c.JSON(http.StatusOK, map[string]any{
		"challenge": challenge,
		"rp":        map[string]any{"id": p.opts.RPID, "name": p.opts.RPName},
		"user": map[string]any{
			"id":          base64.RawURLEncoding.EncodeToString([]byte(sd.User.ID)),
			"name":        sd.User.Email,
			"displayName": nonEmpty(sd.User.Name, sd.User.Email),
		},
		"pubKeyCredParams": []map[string]any{
			{"type": "public-key", "alg": coseAlgES256},
			{"type": "public-key", "alg": coseAlgRS256},
			{"type": "public-key", "alg": coseAlgEdDSA},
		},
		"timeout":     int(p.opts.ChallengeTTL / time.Millisecond),
		"attestation": "none",
		"authenticatorSelection": map[string]any{
			"residentKey":      "preferred",
			"userVerification": p.opts.UserVerification,
		},
		"excludeCredentials": exclude,
	})
}

type credentialResponseBody struct {
	Name     string `json:"name"`
	Response struct {
		ID       string `json:"id"`
		RawID    string `json:"rawId"`
		Type     string `json:"type"`
		Response struct {
			ClientDataJSON    string   `json:"clientDataJSON"`
			AttestationObject string   `json:"attestationObject"`
			AuthenticatorData string   `json:"authenticatorData"`
			Signature         string   `json:"signature"`
			UserHandle        string   `json:"userHandle"`
			Transports        []string `json:"transports"`
		} `json:"response"`
	} `json:"response"`
}

var errInvalidPasskey = godevauth.NewAPIError(http.StatusBadRequest, "INVALID_PASSKEY_RESPONSE",
	"The passkey response could not be verified")

func (p *Plugin) handleVerifyRegistration(c *godevauth.Ctx) error {
	sd, err := c.RequireSession()
	if err != nil {
		return err
	}
	if !p.auth.IsFresh(sd.Session) {
		return godevauth.ErrSessionNotFresh
	}
	var body credentialResponseBody
	if err := c.BindJSON(&body); err != nil {
		return err
	}
	ctx := c.Context()

	cd, _, err := p.clientData(body.Response.Response.ClientDataJSON, "webauthn.create")
	if err != nil {
		return errInvalidPasskey
	}
	// Consuming the challenge is the replay defence: one issued
	// challenge admits one registration, and it must belong to the
	// session that asked for it.
	ownerID, err := p.auth.ConsumeToken(ctx, tokenKindRegister, cd.Challenge)
	if err != nil || ownerID != sd.User.ID {
		return errInvalidPasskey
	}

	attRaw, err := b64(body.Response.Response.AttestationObject)
	if err != nil {
		return errInvalidPasskey
	}
	att, err := parseAttestationObject(attRaw)
	if err != nil {
		return errInvalidPasskey
	}
	ad := att.authData
	if !ad.checkRPIDHash(p.opts.RPID) || !ad.userPresent() || ad.credentialID == nil {
		return errInvalidPasskey
	}
	if p.opts.UserVerification == "required" && !ad.userVerified() {
		return godevauth.NewAPIError(http.StatusBadRequest, "USER_VERIFICATION_REQUIRED",
			"The authenticator did not verify the user")
	}
	// Parse (and thereby validate) the public key before storing it —
	// a credential that cannot be verified later must not be written.
	if _, err := parseCOSEKey(ad.publicKey); err != nil {
		return errInvalidPasskey
	}
	credentialID := base64.RawURLEncoding.EncodeToString(ad.credentialID)
	if body.Response.ID != "" && !b64Equal(body.Response.ID, credentialID) {
		return errInvalidPasskey
	}

	deviceType := "singleDevice"
	if ad.backupEligible() {
		deviceType = "multiDevice"
	}
	name := body.Name
	if name == "" {
		name = "Passkey"
	}
	rec := map[string]any{
		"id":           gcrypto.GenerateID(32),
		"name":         name,
		"publicKey":    base64.RawURLEncoding.EncodeToString(ad.publicKey),
		"userId":       sd.User.ID,
		"credentialID": credentialID,
		"counter":      int64(ad.signCount),
		"deviceType":   deviceType,
		"backedUp":     ad.backedUp(),
		"transports":   strings.Join(body.Response.Response.Transports, ","),
		"aaguid":       base64.RawURLEncoding.EncodeToString(ad.aaguid),
		"createdAt":    time.Now().UTC(),
	}
	if _, err := p.auth.Storage().Create(ctx, ModelPasskey, rec); err != nil {
		if errors.Is(err, storage.ErrUniqueViolation) {
			return godevauth.NewAPIError(http.StatusBadRequest, "PASSKEY_ALREADY_REGISTERED",
				"This passkey is already registered")
		}
		return err
	}
	p.auth.EmitEvent(c, godevauth.Event{
		Type: godevauth.EventType("passkey.registered"), ActorID: sd.User.ID, Email: sd.User.Email, Method: p.ID(),
	})
	return c.JSON(http.StatusOK, p.publicView(rec))
}

// ---- authentication ----

func (p *Plugin) handleAuthenticateOptions(c *godevauth.Ctx) error {
	ctx := c.Context()
	challenge := gcrypto.GenerateToken(32)
	if err := p.auth.StoreTokenValue(ctx, tokenKindAuthenticate, challenge, "1", p.opts.ChallengeTTL); err != nil {
		return err
	}
	out := map[string]any{
		"challenge":        challenge,
		"rpId":             p.opts.RPID,
		"timeout":          int(p.opts.ChallengeTTL / time.Millisecond),
		"userVerification": p.opts.UserVerification,
		// Discoverable credentials: no allowCredentials list. Serving a
		// per-email credential list here would let anyone probe which
		// addresses have passkeys, so the browser's own account picker
		// does the choosing. A signed-in user refining a re-auth prompt
		// is the one exception worth the roundtrip.
		"allowCredentials": []map[string]any{},
	}
	if sd, err := c.Session(); err == nil && sd != nil {
		if pks, err := p.userPasskeys(ctx, sd.User.ID); err == nil {
			allow := make([]map[string]any, 0, len(pks))
			for _, pk := range pks {
				allow = append(allow, map[string]any{"type": "public-key", "id": pk["credentialID"]})
			}
			out["allowCredentials"] = allow
		}
	}
	return c.JSON(http.StatusOK, out)
}

func (p *Plugin) handleVerifyAuthentication(c *godevauth.Ctx) error {
	var body credentialResponseBody
	if err := c.BindJSON(&body); err != nil {
		return err
	}
	ctx := c.Context()

	cd, cdRaw, err := p.clientData(body.Response.Response.ClientDataJSON, "webauthn.get")
	if err != nil {
		return errInvalidPasskey
	}
	if _, err := p.auth.ConsumeToken(ctx, tokenKindAuthenticate, cd.Challenge); err != nil {
		return errInvalidPasskey
	}

	credentialID := body.Response.ID
	if credentialID == "" {
		credentialID = body.Response.RawID
	}
	if credentialID == "" {
		return errInvalidPasskey
	}
	// Normalize to unpadded base64url, the stored form.
	if raw, err := b64(credentialID); err == nil {
		credentialID = base64.RawURLEncoding.EncodeToString(raw)
	}
	rec, err := p.auth.Storage().FindOne(ctx, ModelPasskey,
		[]storage.Where{storage.W("credentialID", credentialID)})
	if err != nil {
		p.auth.EmitEvent(c, godevauth.Event{
			Type: godevauth.EventSignIn, Outcome: godevauth.OutcomeFailure,
			Reason: godevauth.ReasonInvalidToken, Method: p.ID(),
		})
		return errInvalidPasskey
	}

	adRaw, err := b64(body.Response.Response.AuthenticatorData)
	if err != nil {
		return errInvalidPasskey
	}
	ad, err := parseAuthData(adRaw)
	if err != nil {
		return errInvalidPasskey
	}
	if !ad.checkRPIDHash(p.opts.RPID) || !ad.userPresent() {
		return errInvalidPasskey
	}
	if p.opts.UserVerification == "required" && !ad.userVerified() {
		return errInvalidPasskey
	}

	keyRaw, err := b64(str(rec["publicKey"]))
	if err != nil {
		return errInvalidPasskey
	}
	key, err := parseCOSEKey(keyRaw)
	if err != nil {
		return errInvalidPasskey
	}
	sig, err := b64(body.Response.Response.Signature)
	if err != nil {
		return errInvalidPasskey
	}
	digest := sha256.Sum256(cdRaw)
	if !key.verifySignature(append(adRaw, digest[:]...), sig) {
		p.auth.EmitEvent(c, godevauth.Event{
			Type: godevauth.EventSignIn, Outcome: godevauth.OutcomeFailure,
			Reason: godevauth.ReasonInvalidToken, Method: p.ID(),
		})
		return errInvalidPasskey
	}

	// Signature counter (WebAuthn §6.1.1): a counter that fails to
	// advance is the cloned-authenticator signal. Passkeys synced
	// across devices legitimately report 0 forever, so only enforce
	// once the credential has ever reported a positive count.
	stored := intVal(rec["counter"])
	if (stored > 0 || ad.signCount > 0) && int64(ad.signCount) <= stored {
		p.auth.EmitEvent(c, godevauth.Event{
			Type: godevauth.EventSignIn, Outcome: godevauth.OutcomeFailure,
			Reason: godevauth.ReasonInvalidToken, Method: p.ID(),
		})
		return godevauth.NewAPIError(http.StatusUnauthorized, "PASSKEY_COUNTER_REGRESSION",
			"This passkey may have been cloned; it has been rejected")
	}
	if _, err := p.auth.Storage().Update(ctx, ModelPasskey,
		[]storage.Where{storage.W("id", rec["id"])},
		map[string]any{"counter": int64(ad.signCount)}); err != nil {
		return err
	}

	// The optional user handle must agree with the credential's owner.
	if uh := body.Response.Response.UserHandle; uh != "" {
		if raw, err := b64(uh); err != nil || string(raw) != str(rec["userId"]) {
			return errInvalidPasskey
		}
	}

	user, err := p.auth.FindUserByID(ctx, str(rec["userId"]))
	if err != nil {
		return errInvalidPasskey
	}
	// Through SignInUser so sign-in guards (bans, two-factor policy)
	// apply to passkeys exactly as to every other method.
	c.SetAuthMethod(p.ID())
	sess, handled, err := p.auth.SignInUser(c, user, true)
	if err != nil {
		return err
	}
	if handled {
		return nil
	}
	return c.JSON(http.StatusOK, map[string]any{
		"token": sess.Token,
		"user":  user,
	})
}

// ---- management ----

func (p *Plugin) handleList(c *godevauth.Ctx) error {
	sd, err := c.RequireSession()
	if err != nil {
		return err
	}
	pks, err := p.userPasskeys(c.Context(), sd.User.ID)
	if err != nil {
		return err
	}
	out := make([]map[string]any, 0, len(pks))
	for _, pk := range pks {
		out = append(out, p.publicView(pk))
	}
	return c.JSON(http.StatusOK, out)
}

type passkeyIDBody struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func (p *Plugin) handleDelete(c *godevauth.Ctx) error {
	sd, err := c.RequireSession()
	if err != nil {
		return err
	}
	if !p.auth.IsFresh(sd.Session) {
		return godevauth.ErrSessionNotFresh
	}
	var body passkeyIDBody
	if err := c.BindJSON(&body); err != nil {
		return err
	}
	// The where clause carries the owner, so one user cannot delete
	// another's credential by id.
	if err := p.auth.Storage().Delete(c.Context(), ModelPasskey, []storage.Where{
		storage.W("id", body.ID), storage.W("userId", sd.User.ID),
	}); err != nil {
		return err
	}
	return c.JSON(http.StatusOK, map[string]any{"status": true})
}

func (p *Plugin) handleUpdate(c *godevauth.Ctx) error {
	sd, err := c.RequireSession()
	if err != nil {
		return err
	}
	var body passkeyIDBody
	if err := c.BindJSON(&body); err != nil {
		return err
	}
	if body.Name == "" {
		return godevauth.ErrInvalidBody
	}
	rec, err := p.auth.Storage().Update(c.Context(), ModelPasskey, []storage.Where{
		storage.W("id", body.ID), storage.W("userId", sd.User.ID),
	}, map[string]any{"name": body.Name})
	if err != nil {
		return godevauth.NewAPIError(http.StatusNotFound, "PASSKEY_NOT_FOUND", "Passkey not found")
	}
	return c.JSON(http.StatusOK, p.publicView(rec))
}

// ---- helpers ----

// clientData decodes and structurally validates clientDataJSON,
// including the origin check, returning the parsed form and raw bytes.
func (p *Plugin) clientData(encoded, wantType string) (*clientData, []byte, error) {
	raw, err := b64(encoded)
	if err != nil {
		return nil, nil, err
	}
	cd, err := parseClientData(raw)
	if err != nil {
		return nil, nil, err
	}
	if cd.Type != wantType {
		return nil, nil, errWebAuthn
	}
	originOK := false
	for _, o := range p.opts.Origins {
		if cd.Origin == o {
			originOK = true
			break
		}
	}
	if !originOK {
		return nil, nil, errWebAuthn
	}
	return cd, raw, nil
}

func (p *Plugin) userPasskeys(ctx context.Context, userID string) ([]map[string]any, error) {
	return p.auth.Storage().FindMany(ctx, ModelPasskey,
		[]storage.Where{storage.W("userId", userID)}, nil)
}

// publicView is the client-facing shape of a credential row. The public
// key is not secret, but nothing client-side needs it back either.
func (p *Plugin) publicView(rec map[string]any) map[string]any {
	return map[string]any{
		"id":           rec["id"],
		"name":         rec["name"],
		"userId":       rec["userId"],
		"credentialID": rec["credentialID"],
		"deviceType":   rec["deviceType"],
		"backedUp":     rec["backedUp"],
		"transports":   rec["transports"],
		"createdAt":    rec["createdAt"],
	}
}

func nonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func intVal(v any) int64 {
	switch n := v.(type) {
	case int64:
		return n
	case int:
		return int64(n)
	case float64:
		return int64(n)
	}
	return 0
}
