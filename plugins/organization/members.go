package organization

import (
	"errors"
	"net/http"
	"strings"
	"time"

	godevauth "github.com/go-dev-auth/go-dev-auth"
	"github.com/go-dev-auth/go-dev-auth/crypto"
	"github.com/go-dev-auth/go-dev-auth/storage"
)

// ---- invitations ----

type inviteBody struct {
	Email          string `json:"email"`
	Role           string `json:"role"`
	OrganizationID string `json:"organizationId"`
	TeamID         string `json:"teamId"`
	Resend         bool   `json:"resend"`
}

func (p *Plugin) handleInviteMember(c *godevauth.Ctx) error {
	sd, err := c.RequireSession()
	if err != nil {
		return err
	}
	var body inviteBody
	if err := c.BindJSON(&body); err != nil {
		return err
	}
	// Validate the address with the same rule sign-up uses: an invite for
	// a malformed address is one that can never be redeemed.
	if err := p.auth.ValidateEmail(body.Email); err != nil {
		return err
	}
	role := body.Role
	if role == "" {
		role = RoleMember
	}
	if role == RoleOwner {
		return godevauth.NewAPIError(http.StatusBadRequest, "CANNOT_INVITE_OWNER",
			"You cannot invite a member as owner")
	}
	// Constrain the role to the known set, exactly as update-member-role
	// does. Without this an unknown role is written to the invitation
	// and copied onto the member on accept, where no requireRole check
	// will ever match it — silently locking the member out of every
	// role-gated route while still counting as a member.
	if role != RoleAdmin && role != RoleMember {
		return godevauth.NewAPIError(http.StatusBadRequest, "INVALID_ROLE", "Invalid role")
	}
	orgID := p.activeOrg(c, sd, body.OrganizationID)
	if orgID == "" {
		return godevauth.NewAPIError(http.StatusBadRequest, "NO_ACTIVE_ORGANIZATION", "No active organization")
	}
	if _, err := p.requireRole(c, orgID, sd, RoleOwner, RoleAdmin); err != nil {
		return err
	}
	ctx := c.Context()
	email := strings.ToLower(strings.TrimSpace(body.Email))

	// member already?
	if user, err := p.auth.FindUserByEmail(ctx, email); err == nil {
		if _, err := p.Membership(ctx, orgID, user.ID); err == nil {
			return godevauth.NewAPIError(http.StatusBadRequest, "USER_ALREADY_A_MEMBER",
				"User is already a member of this organization")
		}
	}
	// membership limit
	n, err := p.auth.Storage().Count(ctx, ModelMember, []storage.Where{storage.W("organizationId", orgID)})
	if err != nil {
		return err
	}
	if n >= int64(p.opts.MembershipLimit) {
		return godevauth.NewAPIError(http.StatusForbidden, "MEMBER_LIMIT_REACHED",
			"Organization member limit reached")
	}
	// pending invitation already?
	existing, err := p.auth.Storage().FindOne(ctx, ModelInvitation, []storage.Where{
		storage.W("organizationId", orgID),
		storage.W("email", email),
		storage.W("status", "pending"),
	})
	if err == nil && !body.Resend {
		return godevauth.NewAPIError(http.StatusBadRequest, "INVITATION_ALREADY_SENT",
			"An invitation was already sent to this email")
	}
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		return err
	}

	// A team invitation must name a team in this organization.
	if body.TeamID != "" {
		if !p.opts.Teams {
			return godevauth.NewAPIError(http.StatusBadRequest, "TEAMS_DISABLED", "Teams are not enabled")
		}
		if _, err := p.auth.Storage().FindOne(ctx, ModelTeam, []storage.Where{
			storage.W("id", body.TeamID), storage.W("organizationId", orgID),
		}); err != nil {
			return godevauth.NewAPIError(http.StatusBadRequest, "TEAM_NOT_FOUND",
				"Team not found in this organization")
		}
	}

	now := time.Now().UTC()
	var rec map[string]any
	if existing != nil && body.Resend {
		rec, err = p.auth.Storage().Update(ctx, ModelInvitation,
			[]storage.Where{storage.W("id", existing["id"])},
			map[string]any{"expiresAt": now.Add(p.opts.InvitationExpiresIn), "role": role})
		if err != nil {
			return err
		}
	} else {
		rec = map[string]any{
			"id":             crypto.GenerateID(32),
			"organizationId": orgID,
			"email":          email,
			"role":           role,
			"status":         "pending",
			"teamId":         body.TeamID,
			"inviterId":      sd.User.ID,
			"expiresAt":      now.Add(p.opts.InvitationExpiresIn),
			"createdAt":      now,
		}
		if _, err := p.auth.Storage().Create(ctx, ModelInvitation, rec); err != nil {
			return err
		}
	}
	inv := invitationFromMap(rec)
	if p.opts.SendInvitationEmail != nil {
		orgRec, _ := p.auth.Storage().FindOne(ctx, ModelOrganization, []storage.Where{storage.W("id", orgID)})
		if err := p.opts.SendInvitationEmail(ctx, inv, orgFromMap(orgRec), sd.User); err != nil {
			p.auth.Logger().Error("organization: failed to send invitation", "err", err)
		}
	}
	return c.JSON(http.StatusOK, inv)
}

type invitationIDBody struct {
	InvitationID string `json:"invitationId"`
}

// loadInvitation loads a pending, unexpired invitation addressed to the
// current user.
func (p *Plugin) loadInvitation(c *godevauth.Ctx, sd *godevauth.SessionData, id string) (*Invitation, error) {
	rec, err := p.auth.Storage().FindOne(c.Context(), ModelInvitation, []storage.Where{storage.W("id", id)})
	if err != nil {
		return nil, godevauth.NewAPIError(http.StatusNotFound, "INVITATION_NOT_FOUND", "Invitation not found")
	}
	inv := invitationFromMap(rec)
	if inv.Status != "pending" || inv.ExpiresAt.Before(time.Now()) {
		return nil, godevauth.NewAPIError(http.StatusBadRequest, "INVITATION_EXPIRED",
			"Invitation is no longer valid")
	}
	if !strings.EqualFold(inv.Email, sd.User.Email) {
		return nil, godevauth.NewAPIError(http.StatusForbidden, "NOT_YOUR_INVITATION",
			"This invitation is not addressed to you")
	}
	return inv, nil
}

func (p *Plugin) handleAcceptInvitation(c *godevauth.Ctx) error {
	sd, err := c.RequireSession()
	if err != nil {
		return err
	}
	var body invitationIDBody
	if err := c.BindJSON(&body); err != nil {
		return err
	}
	inv, err := p.loadInvitation(c, sd, body.InvitationID)
	if err != nil {
		return err
	}
	ctx := c.Context()

	// Already a member? Accepting again must not create a second row.
	if _, err := p.Membership(ctx, inv.OrganizationID, sd.User.ID); err == nil {
		return godevauth.NewAPIError(http.StatusBadRequest, "USER_ALREADY_A_MEMBER",
			"You are already a member of this organization")
	}
	// The limit is enforced here too: invitations issued while there was
	// room can otherwise all be redeemed after the org filled up.
	n, err := p.auth.Storage().Count(ctx, ModelMember,
		[]storage.Where{storage.W("organizationId", inv.OrganizationID)})
	if err != nil {
		return err
	}
	if n >= int64(p.opts.MembershipLimit) {
		return godevauth.NewAPIError(http.StatusForbidden, "MEMBER_LIMIT_REACHED",
			"Organization member limit reached")
	}

	// Claim the invitation with a conditional transition first: only the
	// request that moves it out of "pending" goes on to insert a member,
	// so concurrent accepts cannot both succeed.
	claimed, err := p.auth.Storage().UpdateMany(ctx, ModelInvitation,
		[]storage.Where{storage.W("id", inv.ID), storage.W("status", "pending")},
		map[string]any{"status": "accepted"})
	if err != nil {
		return err
	}
	if claimed == 0 {
		return godevauth.NewAPIError(http.StatusBadRequest, "INVITATION_EXPIRED",
			"Invitation is no longer valid")
	}

	now := time.Now().UTC()
	memberRec := map[string]any{
		"id":             crypto.GenerateID(32),
		"organizationId": inv.OrganizationID,
		"userId":         sd.User.ID,
		"role":           inv.Role,
		"createdAt":      now,
	}
	if _, err := p.auth.Storage().Create(ctx, ModelMember, memberRec); err != nil {
		if errors.Is(err, storage.ErrUniqueViolation) {
			// A membership row for (organizationId, userId) already
			// exists — a concurrent accept, or another invitation to the
			// same organization, won the race. The composite unique
			// constraint is the backstop that makes the up-front
			// Membership check race-safe; report the same client error it
			// does, and leave the invitation claimed (the user is in).
			return godevauth.NewAPIError(http.StatusBadRequest, "USER_ALREADY_A_MEMBER",
				"You are already a member of this organization")
		}
		// hand the invitation back so it is not silently burned
		_, _ = p.auth.Storage().UpdateMany(ctx, ModelInvitation,
			[]storage.Where{storage.W("id", inv.ID)}, map[string]any{"status": "pending"})
		return err
	}
	if p.opts.Teams && inv.TeamID != "" {
		_, _ = p.auth.Storage().Create(ctx, ModelTeamMember, map[string]any{
			"id":        crypto.GenerateID(32),
			"teamId":    inv.TeamID,
			"userId":    sd.User.ID,
			"createdAt": now,
		})
	}
	_ = p.setActiveOrganization(c, sd, inv.OrganizationID)
	return c.JSON(http.StatusOK, map[string]any{
		"invitation": inv,
		"member":     memberFromMap(memberRec),
	})
}

func (p *Plugin) handleRejectInvitation(c *godevauth.Ctx) error {
	sd, err := c.RequireSession()
	if err != nil {
		return err
	}
	var body invitationIDBody
	if err := c.BindJSON(&body); err != nil {
		return err
	}
	inv, err := p.loadInvitation(c, sd, body.InvitationID)
	if err != nil {
		return err
	}
	if _, err := p.auth.Storage().Update(c.Context(), ModelInvitation,
		[]storage.Where{storage.W("id", inv.ID)}, map[string]any{"status": "rejected"}); err != nil {
		return err
	}
	return c.JSON(http.StatusOK, map[string]any{"status": true})
}

func (p *Plugin) handleCancelInvitation(c *godevauth.Ctx) error {
	sd, err := c.RequireSession()
	if err != nil {
		return err
	}
	var body invitationIDBody
	if err := c.BindJSON(&body); err != nil {
		return err
	}
	rec, err := p.auth.Storage().FindOne(c.Context(), ModelInvitation,
		[]storage.Where{storage.W("id", body.InvitationID)})
	if err != nil {
		return godevauth.NewAPIError(http.StatusNotFound, "INVITATION_NOT_FOUND", "Invitation not found")
	}
	inv := invitationFromMap(rec)
	if _, err := p.requireRole(c, inv.OrganizationID, sd, RoleOwner, RoleAdmin); err != nil {
		return err
	}
	if _, err := p.auth.Storage().Update(c.Context(), ModelInvitation,
		[]storage.Where{storage.W("id", inv.ID)}, map[string]any{"status": "canceled"}); err != nil {
		return err
	}
	return c.JSON(http.StatusOK, map[string]any{"status": true})
}

func (p *Plugin) handleGetInvitation(c *godevauth.Ctx) error {
	sd, err := c.RequireSession()
	if err != nil {
		return err
	}
	id := c.Query("id")
	if id == "" {
		return godevauth.ErrInvalidBody
	}
	inv, err := p.loadInvitation(c, sd, id)
	if err != nil {
		return err
	}
	ctx := c.Context()
	orgRec, _ := p.auth.Storage().FindOne(ctx, ModelOrganization,
		[]storage.Where{storage.W("id", inv.OrganizationID)})
	inviter, _ := p.auth.FindUserByID(ctx, inv.InviterID)
	out := map[string]any{
		"id":             inv.ID,
		"email":          inv.Email,
		"role":           inv.Role,
		"status":         inv.Status,
		"expiresAt":      inv.ExpiresAt,
		"organizationId": inv.OrganizationID,
	}
	if orgRec != nil {
		out["organizationName"] = orgRec["name"]
		out["organizationSlug"] = orgRec["slug"]
	}
	if inviter != nil {
		out["inviterEmail"] = inviter.Email
	}
	return c.JSON(http.StatusOK, out)
}

func (p *Plugin) handleListInvitations(c *godevauth.Ctx) error {
	sd, err := c.RequireSession()
	if err != nil {
		return err
	}
	orgID := p.activeOrg(c, sd, c.Query("organizationId"))
	if orgID == "" {
		return godevauth.NewAPIError(http.StatusBadRequest, "NO_ACTIVE_ORGANIZATION", "No active organization")
	}
	if _, err := p.requireRole(c, orgID, sd); err != nil {
		return err
	}
	recs, err := p.auth.Storage().FindMany(c.Context(), ModelInvitation,
		[]storage.Where{storage.W("organizationId", orgID)}, nil)
	if err != nil {
		return err
	}
	out := make([]*Invitation, 0, len(recs))
	for _, r := range recs {
		out = append(out, invitationFromMap(r))
	}
	return c.JSON(http.StatusOK, out)
}

// ---- members ----

type memberBody struct {
	MemberIDOrEmail string `json:"memberIdOrEmail"`
	OrganizationID  string `json:"organizationId"`
}

func (p *Plugin) findMember(c *godevauth.Ctx, orgID, idOrEmail string) (*Member, error) {
	ctx := c.Context()
	rec, err := p.auth.Storage().FindOne(ctx, ModelMember, []storage.Where{
		storage.W("organizationId", orgID), storage.W("id", idOrEmail),
	})
	if err == nil {
		return memberFromMap(rec), nil
	}
	if user, uerr := p.auth.FindUserByEmail(ctx, idOrEmail); uerr == nil {
		if m, merr := p.Membership(ctx, orgID, user.ID); merr == nil {
			return m, nil
		}
	}
	return nil, godevauth.NewAPIError(http.StatusNotFound, "MEMBER_NOT_FOUND", "Member not found")
}

func (p *Plugin) handleRemoveMember(c *godevauth.Ctx) error {
	sd, err := c.RequireSession()
	if err != nil {
		return err
	}
	var body memberBody
	if err := c.BindJSON(&body); err != nil {
		return err
	}
	orgID := p.activeOrg(c, sd, body.OrganizationID)
	if orgID == "" {
		return godevauth.NewAPIError(http.StatusBadRequest, "NO_ACTIVE_ORGANIZATION", "No active organization")
	}
	actor, err := p.requireRole(c, orgID, sd, RoleOwner, RoleAdmin)
	if err != nil {
		return err
	}
	target, err := p.findMember(c, orgID, body.MemberIDOrEmail)
	if err != nil {
		return err
	}
	if target.Role == RoleOwner && actor.Role != RoleOwner {
		return godevauth.NewAPIError(http.StatusForbidden, "CANNOT_REMOVE_OWNER",
			"Only the owner can remove an owner")
	}
	if target.UserID == sd.User.ID {
		return godevauth.NewAPIError(http.StatusBadRequest, "CANNOT_REMOVE_YOURSELF",
			"Use leave to remove yourself from an organization")
	}
	if err := p.auth.Storage().Delete(c.Context(), ModelMember,
		[]storage.Where{storage.W("id", target.ID)}); err != nil {
		return err
	}
	return c.JSON(http.StatusOK, map[string]any{"member": target})
}

type updateRoleBody struct {
	MemberID       string `json:"memberId"`
	Role           string `json:"role"`
	OrganizationID string `json:"organizationId"`
}

func (p *Plugin) handleUpdateMemberRole(c *godevauth.Ctx) error {
	sd, err := c.RequireSession()
	if err != nil {
		return err
	}
	var body updateRoleBody
	if err := c.BindJSON(&body); err != nil {
		return err
	}
	if body.Role != RoleOwner && body.Role != RoleAdmin && body.Role != RoleMember {
		return godevauth.NewAPIError(http.StatusBadRequest, "INVALID_ROLE", "Invalid role")
	}
	orgID := p.activeOrg(c, sd, body.OrganizationID)
	if orgID == "" {
		return godevauth.NewAPIError(http.StatusBadRequest, "NO_ACTIVE_ORGANIZATION", "No active organization")
	}
	actor, err := p.requireRole(c, orgID, sd, RoleOwner, RoleAdmin)
	if err != nil {
		return err
	}
	rec, err := p.auth.Storage().FindOne(c.Context(), ModelMember, []storage.Where{
		storage.W("organizationId", orgID), storage.W("id", body.MemberID),
	})
	if err != nil {
		return godevauth.NewAPIError(http.StatusNotFound, "MEMBER_NOT_FOUND", "Member not found")
	}
	target := memberFromMap(rec)
	if (target.Role == RoleOwner || body.Role == RoleOwner) && actor.Role != RoleOwner {
		return godevauth.NewAPIError(http.StatusForbidden, "INSUFFICIENT_PERMISSION",
			"Only the owner can change owner roles")
	}
	updated, err := p.auth.Storage().Update(c.Context(), ModelMember,
		[]storage.Where{storage.W("id", target.ID)}, map[string]any{"role": body.Role})
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, memberFromMap(updated))
}

func (p *Plugin) handleGetActiveMember(c *godevauth.Ctx) error {
	sd, err := c.RequireSession()
	if err != nil {
		return err
	}
	orgID := p.activeOrg(c, sd, "")
	if orgID == "" {
		return c.JSON(http.StatusOK, nil)
	}
	member, err := p.Membership(c.Context(), orgID, sd.User.ID)
	if err != nil {
		return c.JSON(http.StatusOK, nil)
	}
	return c.JSON(http.StatusOK, member)
}

func (p *Plugin) handleLeave(c *godevauth.Ctx) error {
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
	member, err := p.Membership(c.Context(), orgID, sd.User.ID)
	if err != nil {
		return godevauth.NewAPIError(http.StatusForbidden, "NOT_A_MEMBER",
			"You are not a member of this organization")
	}
	if member.Role == RoleOwner {
		owners, err := p.auth.Storage().Count(c.Context(), ModelMember, []storage.Where{
			storage.W("organizationId", orgID), storage.W("role", RoleOwner),
		})
		if err != nil {
			return err
		}
		if owners <= 1 {
			return godevauth.NewAPIError(http.StatusBadRequest, "CANNOT_LEAVE_AS_ONLY_OWNER",
				"You cannot leave an organization as its only owner")
		}
	}
	if err := p.auth.Storage().Delete(c.Context(), ModelMember,
		[]storage.Where{storage.W("id", member.ID)}); err != nil {
		return err
	}
	_ = p.setActiveOrganization(c, sd, "")
	return c.JSON(http.StatusOK, map[string]any{"status": true})
}

// ---- teams ----

type createTeamBody struct {
	Name           string `json:"name"`
	OrganizationID string `json:"organizationId"`
}

func (p *Plugin) handleCreateTeam(c *godevauth.Ctx) error {
	sd, err := c.RequireSession()
	if err != nil {
		return err
	}
	var body createTeamBody
	if err := c.BindJSON(&body); err != nil {
		return err
	}
	if body.Name == "" {
		return godevauth.ErrInvalidBody
	}
	orgID := p.activeOrg(c, sd, body.OrganizationID)
	if orgID == "" {
		return godevauth.NewAPIError(http.StatusBadRequest, "NO_ACTIVE_ORGANIZATION", "No active organization")
	}
	if _, err := p.requireRole(c, orgID, sd, RoleOwner, RoleAdmin); err != nil {
		return err
	}
	rec := map[string]any{
		"id":             crypto.GenerateID(32),
		"organizationId": orgID,
		"name":           body.Name,
		"createdAt":      time.Now().UTC(),
	}
	if _, err := p.auth.Storage().Create(c.Context(), ModelTeam, rec); err != nil {
		return err
	}
	return c.JSON(http.StatusOK, rec)
}

type teamIDBody struct {
	TeamID         string `json:"teamId"`
	OrganizationID string `json:"organizationId"`
}

func (p *Plugin) handleRemoveTeam(c *godevauth.Ctx) error {
	sd, err := c.RequireSession()
	if err != nil {
		return err
	}
	var body teamIDBody
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
	ctx := c.Context()
	if _, err := p.auth.Storage().FindOne(ctx, ModelTeam, []storage.Where{
		storage.W("id", body.TeamID), storage.W("organizationId", orgID),
	}); err != nil {
		return godevauth.NewAPIError(http.StatusNotFound, "TEAM_NOT_FOUND", "Team not found")
	}
	_, _ = p.auth.Storage().DeleteMany(ctx, ModelTeamMember, []storage.Where{storage.W("teamId", body.TeamID)})
	if err := p.auth.Storage().Delete(ctx, ModelTeam, []storage.Where{storage.W("id", body.TeamID)}); err != nil {
		return err
	}
	return c.JSON(http.StatusOK, map[string]any{"status": true})
}

func (p *Plugin) handleListTeams(c *godevauth.Ctx) error {
	sd, err := c.RequireSession()
	if err != nil {
		return err
	}
	orgID := p.activeOrg(c, sd, c.Query("organizationId"))
	if orgID == "" {
		return godevauth.NewAPIError(http.StatusBadRequest, "NO_ACTIVE_ORGANIZATION", "No active organization")
	}
	if _, err := p.requireRole(c, orgID, sd); err != nil {
		return err
	}
	recs, err := p.auth.Storage().FindMany(c.Context(), ModelTeam,
		[]storage.Where{storage.W("organizationId", orgID)}, nil)
	if err != nil {
		return err
	}
	if recs == nil {
		recs = []map[string]any{}
	}
	return c.JSON(http.StatusOK, recs)
}
