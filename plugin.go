package godevauth

import (
	"net/http"

	"github.com/go-dev-auth/go-dev-auth/oauth2"
	"github.com/go-dev-auth/go-dev-auth/storage"
)

// This file defines the contract a plugin implements. The Route type a
// plugin returns lives with the rest of the routing layer in router.go;
// see docs/writing-a-plugin.md for a worked example.

// Plugin extends an Auth instance with routes, schema and behaviour,
// mirroring better-auth's plugin system.
type Plugin interface {
	// ID is the unique plugin identifier, e.g. "two-factor".
	ID() string
	// Init is called once during New with the owning Auth instance.
	Init(a *Auth) error
	// Routes returns the plugin's endpoints.
	Routes() []Route
}

// SchemaPlugin is implemented by plugins that extend the database schema.
type SchemaPlugin interface {
	Plugin
	// Schema may add tables and fields.
	Schema(s *storage.Schema)
}

// ProviderSourcePlugin is implemented by plugins that contribute OAuth
// providers resolved at request time — tenant SSO configured in the
// database is the canonical case. Auth.SocialProvider consults sources
// after the statically configured providers, so a source can never
// shadow a configured provider; a source should namespace its ids (the
// sso plugin uses "sso:<providerId>") so a configured provider can
// never shadow it either.
type ProviderSourcePlugin interface {
	Plugin
	// SocialProvider returns the provider with the given id, or nil.
	SocialProvider(id string) oauth2.Provider
}

// MiddlewarePlugin is implemented by plugins that wrap every auth
// request (e.g. bearer token support).
type MiddlewarePlugin interface {
	Plugin
	// Middleware wraps the auth handler.
	Middleware(next http.Handler) http.Handler
}

// HookPlugin is implemented by plugins that hook the request lifecycle.
type HookPlugin interface {
	Plugin
	// BeforeRequest runs before routing. Returning a non-nil error
	// aborts the request; writing a response short-circuits it.
	BeforeRequest(c *Ctx) error
	// AfterRequest runs after the handler.
	AfterRequest(c *Ctx) error
}

// Plugin returns the plugin with the given id, or nil.
func (a *Auth) Plugin(id string) Plugin {
	for _, p := range a.config.Plugins {
		if p.ID() == id {
			return p
		}
	}
	return nil
}
