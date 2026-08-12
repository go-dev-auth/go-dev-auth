// Package organization adds multi-tenant organizations with members,
// roles, invitations and optional teams. Port of better-auth's
// organization plugin.
//
// Roles: "owner" (creator), "admin" and "member" by default. The active
// organization is tracked on the session.
package organization

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	godevauth "github.com/go-dev-auth/go-dev-auth"
	"github.com/go-dev-auth/go-dev-auth/crypto"
	"github.com/go-dev-auth/go-dev-auth/storage"
)

// Model names.
const (
	ModelOrganization = "organization"
	ModelMember       = "member"
	ModelInvitation   = "invitation"
	ModelTeam         = "team"
	ModelTeamMember   = "teamMember"
)

// Built-in roles.
const (
	RoleOwner  = "owner"
	RoleAdmin  = "admin"
	RoleMember = "member"
)

// Options configures the organization plugin.
type Options struct {
	// AllowUserToCreateOrganization defaults to true. Set the callback
	// to customize per user.
	DisableOrganizationCreation bool
	CanCreateOrganization       func(ctx context.Context, user *storage.User) bool
	// OrganizationLimit is the maximum number of organizations per
	// user. Defaults to 5.
	OrganizationLimit int
	// MembershipLimit is the maximum number of members per
	// organization. Defaults to 100.
	MembershipLimit int
	// CreatorRole defaults to "owner".
	CreatorRole string
	// InvitationExpiresIn defaults to 48 hours.
	InvitationExpiresIn time.Duration
	// SendInvitationEmail delivers invitation emails.
	SendInvitationEmail func(ctx context.Context, inv *Invitation, org *Organization, inviter *storage.User) error
	// Teams enables team support.
	Teams bool
	// OrganizationHooks run around organization lifecycle events.
	AfterCreate  func(ctx context.Context, org *Organization, creator *storage.User) error
	BeforeDelete func(ctx context.Context, org *Organization) error
}

// Organization is an organization record.
type Organization struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	Logo      string    `json:"logo,omitempty"`
	Metadata  string    `json:"metadata,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
}

// Member is an organization membership.
type Member struct {
	ID             string    `json:"id"`
	OrganizationID string    `json:"organizationId"`
	UserID         string    `json:"userId"`
	Role           string    `json:"role"`
	CreatedAt      time.Time `json:"createdAt"`
}

// Invitation is a pending invite.
type Invitation struct {
	ID             string    `json:"id"`
	OrganizationID string    `json:"organizationId"`
	Email          string    `json:"email"`
	Role           string    `json:"role"`
	Status         string    `json:"status"`
	TeamID         string    `json:"teamId,omitempty"`
	InviterID      string    `json:"inviterId"`
	ExpiresAt      time.Time `json:"expiresAt"`
}

// Team is a sub-group of an organization.
type Team struct {
	ID             string    `json:"id"`
	OrganizationID string    `json:"organizationId"`
	Name           string    `json:"name"`
	CreatedAt      time.Time `json:"createdAt"`
}

// Plugin implements the organization plugin.
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
	if o.OrganizationLimit == 0 {
		o.OrganizationLimit = 5
	}
	if o.MembershipLimit == 0 {
		o.MembershipLimit = 100
	}
	if o.CreatorRole == "" {
		o.CreatorRole = RoleOwner
	}
	if o.InvitationExpiresIn == 0 {
		o.InvitationExpiresIn = 48 * time.Hour
	}
	return &Plugin{opts: o}
}

// ID implements godevauth.Plugin.
func (p *Plugin) ID() string { return "organization" }

// Init implements godevauth.Plugin.
func (p *Plugin) Init(a *godevauth.Auth) error {
	p.auth = a
	return nil
}

// Schema implements godevauth.SchemaPlugin.
func (p *Plugin) Schema(s *storage.Schema) {
	s.AddFields(storage.ModelSession,
		storage.Field{Name: "activeOrganizationId", Type: storage.FieldString})
	s.AddTable(&storage.Table{Name: ModelOrganization, Fields: []storage.Field{
		{Name: "id", Type: storage.FieldString, Required: true, Unique: true},
		{Name: "name", Type: storage.FieldString, Required: true},
		{Name: "slug", Type: storage.FieldString, Required: true, Unique: true},
		{Name: "logo", Type: storage.FieldText},
		{Name: "metadata", Type: storage.FieldText},
		{Name: "createdAt", Type: storage.FieldTime, Required: true},
	}})
	s.AddTable(&storage.Table{Name: ModelMember, Fields: []storage.Field{
		{Name: "id", Type: storage.FieldString, Required: true, Unique: true},
		{Name: "organizationId", Type: storage.FieldString, Required: true, Index: true,
			References: &storage.Reference{Model: ModelOrganization, Field: "id", OnDelete: "cascade"}},
		{Name: "userId", Type: storage.FieldString, Required: true, Index: true,
			References: &storage.Reference{Model: storage.ModelUser, Field: "id", OnDelete: "cascade"}},
		{Name: "role", Type: storage.FieldString, Required: true},
		{Name: "createdAt", Type: storage.FieldTime, Required: true},
	},
		// A user belongs to an organization at most once. The database
		// backstops the check-then-create in accept-invitation so two
		// concurrent accepts cannot create two membership rows.
		UniqueConstraints: []storage.UniqueConstraint{{Columns: []string{"organizationId", "userId"}}},
	})
	s.AddTable(&storage.Table{Name: ModelInvitation, Fields: []storage.Field{
		{Name: "id", Type: storage.FieldString, Required: true, Unique: true},
		{Name: "organizationId", Type: storage.FieldString, Required: true, Index: true,
			References: &storage.Reference{Model: ModelOrganization, Field: "id", OnDelete: "cascade"}},
		{Name: "email", Type: storage.FieldString, Required: true, Index: true},
		{Name: "role", Type: storage.FieldString, Required: true},
		{Name: "status", Type: storage.FieldString, Required: true},
		{Name: "teamId", Type: storage.FieldString},
		{Name: "inviterId", Type: storage.FieldString, Required: true},
		{Name: "expiresAt", Type: storage.FieldTime, Required: true},
		{Name: "createdAt", Type: storage.FieldTime, Required: true},
	}})
	if p.opts.Teams {
		s.AddTable(&storage.Table{Name: ModelTeam, Fields: []storage.Field{
			{Name: "id", Type: storage.FieldString, Required: true, Unique: true},
			{Name: "organizationId", Type: storage.FieldString, Required: true, Index: true,
				References: &storage.Reference{Model: ModelOrganization, Field: "id", OnDelete: "cascade"}},
			{Name: "name", Type: storage.FieldString, Required: true},
			{Name: "createdAt", Type: storage.FieldTime, Required: true},
		}})
		s.AddTable(&storage.Table{Name: ModelTeamMember, Fields: []storage.Field{
			{Name: "id", Type: storage.FieldString, Required: true, Unique: true},
			{Name: "teamId", Type: storage.FieldString, Required: true, Index: true,
				References: &storage.Reference{Model: ModelTeam, Field: "id", OnDelete: "cascade"}},
			{Name: "userId", Type: storage.FieldString, Required: true, Index: true},
			{Name: "createdAt", Type: storage.FieldTime, Required: true},
		}})
	}
}

// Routes implements godevauth.Plugin.
func (p *Plugin) Routes() []godevauth.Route {
	routes := []godevauth.Route{
		{Method: http.MethodPost, Path: "/organization/create", Handler: p.handleCreate},
		{Method: http.MethodPost, Path: "/organization/update", Handler: p.handleUpdate},
		{Method: http.MethodPost, Path: "/organization/delete", Handler: p.handleDelete},
		{Method: http.MethodGet, Path: "/organization/list", Handler: p.handleList},
		{Method: http.MethodPost, Path: "/organization/set-active", Handler: p.handleSetActive},
		{Method: http.MethodGet, Path: "/organization/get-full-organization", Handler: p.handleGetFull},
		{Method: http.MethodPost, Path: "/organization/check-slug", Handler: p.handleCheckSlug},
		{Method: http.MethodPost, Path: "/organization/invite-member", Handler: p.handleInviteMember},
		{Method: http.MethodPost, Path: "/organization/accept-invitation", Handler: p.handleAcceptInvitation},
		{Method: http.MethodPost, Path: "/organization/reject-invitation", Handler: p.handleRejectInvitation},
		{Method: http.MethodPost, Path: "/organization/cancel-invitation", Handler: p.handleCancelInvitation},
		{Method: http.MethodGet, Path: "/organization/get-invitation", Handler: p.handleGetInvitation},
		{Method: http.MethodGet, Path: "/organization/list-invitations", Handler: p.handleListInvitations},
		{Method: http.MethodPost, Path: "/organization/remove-member", Handler: p.handleRemoveMember},
		{Method: http.MethodPost, Path: "/organization/update-member-role", Handler: p.handleUpdateMemberRole},
		{Method: http.MethodGet, Path: "/organization/get-active-member", Handler: p.handleGetActiveMember},
		{Method: http.MethodPost, Path: "/organization/leave", Handler: p.handleLeave},
	}
	if p.opts.Teams {
		routes = append(routes,
			godevauth.Route{Method: http.MethodPost, Path: "/organization/create-team", Handler: p.handleCreateTeam},
			godevauth.Route{Method: http.MethodPost, Path: "/organization/remove-team", Handler: p.handleRemoveTeam},
			godevauth.Route{Method: http.MethodGet, Path: "/organization/list-teams", Handler: p.handleListTeams},
		)
	}
	return routes
}

// ---- helpers ----

func orgFromMap(m map[string]any) *Organization {
	if m == nil {
		return nil
	}
	o := &Organization{}
	o.ID, _ = m["id"].(string)
	o.Name, _ = m["name"].(string)
	o.Slug, _ = m["slug"].(string)
	o.Logo, _ = m["logo"].(string)
	o.Metadata, _ = m["metadata"].(string)
	o.CreatedAt, _ = m["createdAt"].(time.Time)
	return o
}

func memberFromMap(m map[string]any) *Member {
	if m == nil {
		return nil
	}
	mm := &Member{}
	mm.ID, _ = m["id"].(string)
	mm.OrganizationID, _ = m["organizationId"].(string)
	mm.UserID, _ = m["userId"].(string)
	mm.Role, _ = m["role"].(string)
	mm.CreatedAt, _ = m["createdAt"].(time.Time)
	return mm
}

func invitationFromMap(m map[string]any) *Invitation {
	if m == nil {
		return nil
	}
	inv := &Invitation{}
	inv.ID, _ = m["id"].(string)
	inv.OrganizationID, _ = m["organizationId"].(string)
	inv.Email, _ = m["email"].(string)
	inv.Role, _ = m["role"].(string)
	inv.Status, _ = m["status"].(string)
	inv.TeamID, _ = m["teamId"].(string)
	inv.InviterID, _ = m["inviterId"].(string)
	inv.ExpiresAt, _ = m["expiresAt"].(time.Time)
	return inv
}

// Membership loads the member row for user in org.
func (p *Plugin) Membership(ctx context.Context, orgID, userID string) (*Member, error) {
	rec, err := p.auth.Storage().FindOne(ctx, ModelMember, []storage.Where{
		storage.W("organizationId", orgID), storage.W("userId", userID),
	})
	if err != nil {
		return nil, err
	}
	return memberFromMap(rec), nil
}

// activeOrg resolves the active organization from the session (falling
// back to an explicit organizationId parameter).
func (p *Plugin) activeOrg(c *godevauth.Ctx, sd *godevauth.SessionData, explicit string) string {
	if explicit != "" {
		return explicit
	}
	if v, ok := sd.Session.Extra["activeOrganizationId"].(string); ok {
		return v
	}
	return ""
}

// requireRole asserts the user has one of the given roles in the org.
func (p *Plugin) requireRole(c *godevauth.Ctx, orgID string, sd *godevauth.SessionData, roles ...string) (*Member, error) {
	member, err := p.Membership(c.Context(), orgID, sd.User.ID)
	if err != nil {
		return nil, godevauth.NewAPIError(http.StatusForbidden, "NOT_A_MEMBER",
			"You are not a member of this organization")
	}
	if len(roles) == 0 {
		return member, nil
	}
	for _, r := range roles {
		if member.Role == r {
			return member, nil
		}
	}
	return nil, godevauth.NewAPIError(http.StatusForbidden, "INSUFFICIENT_PERMISSION",
		"You don't have permission to perform this action")
}

// errSlugTaken is returned for both the pre-check and the unique-index
// race, so callers see one stable error code.
var errSlugTaken = godevauth.NewAPIError(http.StatusBadRequest, "SLUG_TAKEN",
	"Organization slug is already taken")

var slugRe = regexp.MustCompile(`[^a-z0-9-]+`)

func slugify(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, " ", "-")
	s = slugRe.ReplaceAllString(s, "")
	if s == "" {
		s = strings.ToLower(crypto.GenerateID(8))
	}
	return s
}

// ---- organization CRUD ----

type createBody struct {
	Name                          string `json:"name"`
	Slug                          string `json:"slug"`
	Logo                          string `json:"logo"`
	Metadata                      string `json:"metadata"`
	KeepCurrentActiveOrganization bool   `json:"keepCurrentActiveOrganization"`
}

func (p *Plugin) handleCreate(c *godevauth.Ctx) error {
	sd, err := c.RequireSession()
	if err != nil {
		return err
	}
	if p.opts.DisableOrganizationCreation {
		return godevauth.NewAPIError(http.StatusForbidden, "ORGANIZATION_CREATION_DISABLED",
			"Organization creation is disabled")
	}
	if p.opts.CanCreateOrganization != nil && !p.opts.CanCreateOrganization(c.Context(), sd.User) {
		return godevauth.NewAPIError(http.StatusForbidden, "NOT_ALLOWED_TO_CREATE_ORGANIZATION",
			"You are not allowed to create organizations")
	}
	var body createBody
	if err := c.BindJSON(&body); err != nil {
		return err
	}
	if body.Name == "" {
		return godevauth.ErrInvalidBody
	}
	ctx := c.Context()

	n, err := p.auth.Storage().Count(ctx, ModelMember, []storage.Where{
		storage.W("userId", sd.User.ID), storage.W("role", p.opts.CreatorRole),
	})
	if err != nil {
		return err
	}
	if n >= int64(p.opts.OrganizationLimit) {
		return godevauth.NewAPIError(http.StatusForbidden, "ORGANIZATION_LIMIT_REACHED",
			"You have reached the organization limit")
	}

	slug := body.Slug
	if slug == "" {
		slug = slugify(body.Name)
	} else {
		slug = slugify(slug)
	}
	if _, err := p.auth.Storage().FindOne(ctx, ModelOrganization, []storage.Where{storage.W("slug", slug)}); err == nil {
		return errSlugTaken
	} else if !errors.Is(err, storage.ErrNotFound) {
		return err
	}

	now := time.Now().UTC()
	orgRec := map[string]any{
		"id":        crypto.GenerateID(32),
		"name":      body.Name,
		"slug":      slug,
		"logo":      body.Logo,
		"metadata":  body.Metadata,
		"createdAt": now,
	}
	if _, err := p.auth.Storage().Create(ctx, ModelOrganization, orgRec); err != nil {
		if errors.Is(err, storage.ErrUniqueViolation) {
			return errSlugTaken
		}
		return err
	}
	memberRec := map[string]any{
		"id":             crypto.GenerateID(32),
		"organizationId": orgRec["id"],
		"userId":         sd.User.ID,
		"role":           p.opts.CreatorRole,
		"createdAt":      now,
	}
	if _, err := p.auth.Storage().Create(ctx, ModelMember, memberRec); err != nil {
		return err
	}
	org := orgFromMap(orgRec)
	if !body.KeepCurrentActiveOrganization {
		_ = p.setActiveOrganization(c, sd, org.ID)
	}
	if p.opts.AfterCreate != nil {
		_ = p.opts.AfterCreate(ctx, org, sd.User)
	}
	return c.JSON(http.StatusOK, org)
}

type updateBody struct {
	OrganizationID string         `json:"organizationId"`
	Data           map[string]any `json:"data"`
}

func (p *Plugin) handleUpdate(c *godevauth.Ctx) error {
	sd, err := c.RequireSession()
	if err != nil {
		return err
	}
	var body updateBody
	if err := c.BindJSON(&body); err != nil {
		return err
	}
	orgID := p.activeOrg(c, sd, body.OrganizationID)
	if orgID == "" {
		return godevauth.NewAPIError(http.StatusBadRequest, "NO_ACTIVE_ORGANIZATION", "No active organization")
	}
	if _, err := p.requireRole(c, orgID, sd, RoleOwner, RoleAdmin); err != nil {
		return err
	}
	update := map[string]any{}
	for _, k := range []string{"name", "logo", "metadata"} {
		if v, ok := body.Data[k].(string); ok {
			update[k] = v
		}
	}
	if v, ok := body.Data["slug"].(string); ok && v != "" {
		slug := slugify(v)
		if existing, err := p.auth.Storage().FindOne(c.Context(), ModelOrganization,
			[]storage.Where{storage.W("slug", slug)}); err == nil {
			if id, _ := existing["id"].(string); id != orgID {
				return errSlugTaken
			}
		} else if !errors.Is(err, storage.ErrNotFound) {
			return err
		}
		update["slug"] = slug
	}
	if len(update) == 0 {
		return godevauth.ErrInvalidBody
	}
	rec, err := p.auth.Storage().Update(c.Context(), ModelOrganization,
		[]storage.Where{storage.W("id", orgID)}, update)
	if err != nil {
		if errors.Is(err, storage.ErrUniqueViolation) {
			return errSlugTaken
		}
		return err
	}
	return c.JSON(http.StatusOK, orgFromMap(rec))
}

type orgIDBody struct {
	OrganizationID string `json:"organizationId"`
}

func (p *Plugin) handleDelete(c *godevauth.Ctx) error {
	sd, err := c.RequireSession()
	if err != nil {
		return err
	}
	var body orgIDBody
	if err := c.BindJSON(&body); err != nil {
		return err
	}
	orgID := p.activeOrg(c, sd, body.OrganizationID)
	if orgID == "" {
		return godevauth.NewAPIError(http.StatusBadRequest, "NO_ACTIVE_ORGANIZATION", "No active organization")
	}
	if _, err := p.requireRole(c, orgID, sd, RoleOwner); err != nil {
		return err
	}
	ctx := c.Context()
	rec, err := p.auth.Storage().FindOne(ctx, ModelOrganization, []storage.Where{storage.W("id", orgID)})
	if err != nil {
		return godevauth.NewAPIError(http.StatusNotFound, "ORGANIZATION_NOT_FOUND", "Organization not found")
	}
	org := orgFromMap(rec)
	if p.opts.BeforeDelete != nil {
		if err := p.opts.BeforeDelete(ctx, org); err != nil {
			return err
		}
	}
	_, _ = p.auth.Storage().DeleteMany(ctx, ModelMember, []storage.Where{storage.W("organizationId", orgID)})
	_, _ = p.auth.Storage().DeleteMany(ctx, ModelInvitation, []storage.Where{storage.W("organizationId", orgID)})
	if p.opts.Teams {
		// Remove team memberships explicitly: SQLite does not enforce
		// the declared cascade unless foreign keys are switched on.
		teams, _ := p.auth.Storage().FindMany(ctx, ModelTeam,
			[]storage.Where{storage.W("organizationId", orgID)}, nil)
		for _, t := range teams {
			teamID, _ := t["id"].(string)
			_, _ = p.auth.Storage().DeleteMany(ctx, ModelTeamMember,
				[]storage.Where{storage.W("teamId", teamID)})
		}
		_, _ = p.auth.Storage().DeleteMany(ctx, ModelTeam, []storage.Where{storage.W("organizationId", orgID)})
	}
	if err := p.auth.Storage().Delete(ctx, ModelOrganization, []storage.Where{storage.W("id", orgID)}); err != nil {
		return err
	}
	return c.JSON(http.StatusOK, org)
}

func (p *Plugin) handleList(c *godevauth.Ctx) error {
	sd, err := c.RequireSession()
	if err != nil {
		return err
	}
	ctx := c.Context()
	members, err := p.auth.Storage().FindMany(ctx, ModelMember,
		[]storage.Where{storage.W("userId", sd.User.ID)}, nil)
	if err != nil {
		return err
	}
	orgs := []*Organization{}
	if len(members) == 0 {
		return c.JSON(http.StatusOK, orgs)
	}
	// One IN query instead of a lookup per membership.
	ids := make([]any, 0, len(members))
	for _, m := range members {
		if id, ok := m["organizationId"].(string); ok {
			ids = append(ids, id)
		}
	}
	recs, err := p.auth.Storage().FindMany(ctx, ModelOrganization,
		[]storage.Where{{Field: "id", Operator: storage.OpIn, Value: ids}}, nil)
	if err != nil {
		return err
	}
	for _, rec := range recs {
		orgs = append(orgs, orgFromMap(rec))
	}
	return c.JSON(http.StatusOK, orgs)
}

func (p *Plugin) setActiveOrganization(c *godevauth.Ctx, sd *godevauth.SessionData, orgID string) error {
	_, err := p.auth.UpdateSessionRecord(c.Context(), sd.Session.Token, map[string]any{
		"activeOrganizationId": orgID,
	})
	if sd.Session.Extra == nil {
		sd.Session.Extra = map[string]any{}
	}
	sd.Session.Extra["activeOrganizationId"] = orgID
	return err
}

type setActiveBody struct {
	OrganizationID   string `json:"organizationId"`
	OrganizationSlug string `json:"organizationSlug"`
}

func (p *Plugin) handleSetActive(c *godevauth.Ctx) error {
	sd, err := c.RequireSession()
	if err != nil {
		return err
	}
	var body setActiveBody
	if err := c.BindJSONOptional(&body); err != nil {
		return err
	}
	ctx := c.Context()
	orgID := body.OrganizationID
	if orgID == "" && body.OrganizationSlug != "" {
		rec, err := p.auth.Storage().FindOne(ctx, ModelOrganization,
			[]storage.Where{storage.W("slug", body.OrganizationSlug)})
		if err != nil {
			return godevauth.NewAPIError(http.StatusNotFound, "ORGANIZATION_NOT_FOUND", "Organization not found")
		}
		orgID = orgFromMap(rec).ID
	}
	if orgID == "" {
		// unset
		if err := p.setActiveOrganization(c, sd, ""); err != nil {
			return err
		}
		return c.JSON(http.StatusOK, nil)
	}
	if _, err := p.Membership(ctx, orgID, sd.User.ID); err != nil {
		return godevauth.NewAPIError(http.StatusForbidden, "NOT_A_MEMBER",
			"You are not a member of this organization")
	}
	if err := p.setActiveOrganization(c, sd, orgID); err != nil {
		return err
	}
	rec, err := p.auth.Storage().FindOne(ctx, ModelOrganization, []storage.Where{storage.W("id", orgID)})
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, orgFromMap(rec))
}

func (p *Plugin) handleGetFull(c *godevauth.Ctx) error {
	sd, err := c.RequireSession()
	if err != nil {
		return err
	}
	ctx := c.Context()
	orgID := c.Query("organizationId")
	if orgID == "" {
		if slug := c.Query("organizationSlug"); slug != "" {
			rec, err := p.auth.Storage().FindOne(ctx, ModelOrganization,
				[]storage.Where{storage.W("slug", slug)})
			if err != nil {
				return godevauth.NewAPIError(http.StatusNotFound, "ORGANIZATION_NOT_FOUND", "Organization not found")
			}
			orgID = orgFromMap(rec).ID
		}
	}
	orgID = p.activeOrg(c, sd, orgID)
	if orgID == "" {
		return c.JSON(http.StatusOK, nil)
	}
	if _, err := p.Membership(ctx, orgID, sd.User.ID); err != nil {
		return godevauth.NewAPIError(http.StatusForbidden, "NOT_A_MEMBER",
			"You are not a member of this organization")
	}
	rec, err := p.auth.Storage().FindOne(ctx, ModelOrganization, []storage.Where{storage.W("id", orgID)})
	if err != nil {
		return godevauth.NewAPIError(http.StatusNotFound, "ORGANIZATION_NOT_FOUND", "Organization not found")
	}
	memberRecs, err := p.auth.Storage().FindMany(ctx, ModelMember,
		[]storage.Where{storage.W("organizationId", orgID)},
		&storage.FindOptions{Limit: p.opts.MembershipLimit})
	if err != nil {
		return err
	}
	// Resolve every member's user in one query rather than one per
	// member: at the default membership limit that was 100+ round trips
	// for a single page load.
	userIDs := make([]any, 0, len(memberRecs))
	for _, m := range memberRecs {
		if id, ok := m["userId"].(string); ok {
			userIDs = append(userIDs, id)
		}
	}
	usersByID := map[string]map[string]any{}
	if len(userIDs) > 0 {
		userRecs, err := p.auth.Storage().FindMany(ctx, storage.ModelUser,
			[]storage.Where{{Field: "id", Operator: storage.OpIn, Value: userIDs}}, nil)
		if err != nil {
			return err
		}
		for _, u := range userRecs {
			id, _ := u["id"].(string)
			usersByID[id] = map[string]any{
				"id":    u["id"],
				"name":  u["name"],
				"email": u["email"],
				"image": u["image"],
			}
		}
	}
	members := make([]map[string]any, 0, len(memberRecs))
	for _, m := range memberRecs {
		member := memberFromMap(m)
		entry := map[string]any{
			"id":             member.ID,
			"organizationId": member.OrganizationID,
			"userId":         member.UserID,
			"role":           member.Role,
			"createdAt":      member.CreatedAt,
		}
		if u, ok := usersByID[member.UserID]; ok {
			entry["user"] = u
		}
		members = append(members, entry)
	}
	invRecs, _ := p.auth.Storage().FindMany(ctx, ModelInvitation, []storage.Where{
		storage.W("organizationId", orgID), storage.W("status", "pending"),
	}, nil)
	invitations := make([]*Invitation, 0, len(invRecs))
	for _, r := range invRecs {
		invitations = append(invitations, invitationFromMap(r))
	}
	out := map[string]any{
		"id":          rec["id"],
		"name":        rec["name"],
		"slug":        rec["slug"],
		"logo":        rec["logo"],
		"metadata":    rec["metadata"],
		"createdAt":   rec["createdAt"],
		"members":     members,
		"invitations": invitations,
	}
	if p.opts.Teams {
		teamRecs, _ := p.auth.Storage().FindMany(ctx, ModelTeam,
			[]storage.Where{storage.W("organizationId", orgID)}, nil)
		out["teams"] = teamRecs
	}
	return c.JSON(http.StatusOK, out)
}

type checkSlugBody struct {
	Slug string `json:"slug"`
}

func (p *Plugin) handleCheckSlug(c *godevauth.Ctx) error {
	// A session is required even though this only reads: without one,
	// the endpoint is an unauthenticated oracle for which organisations
	// exist, and it is the only route in the plugin that did not check.
	// Availability is checked while creating an organisation, which
	// already needs a session.
	if _, err := c.RequireSession(); err != nil {
		return err
	}
	var body checkSlugBody
	if err := c.BindJSON(&body); err != nil {
		return err
	}
	_, err := p.auth.Storage().FindOne(c.Context(), ModelOrganization,
		[]storage.Where{storage.W("slug", slugify(body.Slug))})
	if err == nil {
		return godevauth.NewAPIError(http.StatusBadRequest, "SLUG_TAKEN", "Slug is taken")
	}
	if !errors.Is(err, storage.ErrNotFound) {
		return err
	}
	return c.JSON(http.StatusOK, map[string]any{"status": true})
}
