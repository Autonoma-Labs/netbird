package autonoma

import (
	"fmt"

	"github.com/autonoma-ai/sdk/sdks/go/autonoma"

	"github.com/netbirdio/netbird/management/server/idp"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/auth"
)

// AccountInput seeds a whole tenant: an owner in the identity provider plus the
// account that provisioning it creates.
type AccountInput struct {
	// OwnerEmail must be unique across the identity provider, so the recipe puts
	// the run id in it.
	OwnerEmail string `json:"ownerEmail"`
	OwnerName  string `json:"ownerName"`
	// OwnerPassword is what the auth callback hands the test runner to log in
	// with. The embedded IdP enforces a minimum length of 8.
	OwnerPassword string `json:"ownerPassword"`
	// Domain is the account's email domain. Left empty the account is private to
	// its owner, which is what keeps concurrent runs from being merged into one
	// tenant by the domain-matching in getAccountIDWithAuthorizationClaims.
	Domain string `json:"domain,omitempty"`
}

// accountFactory creates the owner in the embedded IdP the way /api/setup does,
// then lets the account manager provision the account around them. That single
// call is what mints the All group, the default policy, the account settings,
// the onboarding row and the overlay network.
func (f *factories) accountFactory(in *AccountInput, _ autonoma.FactoryContext) (map[string]any, error) {
	ctx := f.ctx()

	embedded, ok := f.deps.IdpManager.(*idp.EmbeddedIdPManager)
	if !ok || embedded == nil {
		return nil, fmt.Errorf("account seeding needs the embedded identity provider; this deployment uses %T", f.deps.IdpManager)
	}

	userData, err := embedded.CreateUserWithPassword(ctx, in.OwnerEmail, in.OwnerPassword, in.OwnerName)
	if err != nil {
		return nil, fmt.Errorf("create owner in identity provider: %w", err)
	}

	acc, err := f.deps.AccountManager.GetOrCreateAccountByUser(ctx, auth.UserAuth{
		UserId: userData.ID,
		Email:  in.OwnerEmail,
		Name:   in.OwnerName,
		Domain: in.Domain,
	})
	if err != nil {
		// The IdP user would otherwise linger with no account to delete it.
		if delErr := embedded.DeleteUser(ctx, userData.ID); delErr != nil {
			return nil, fmt.Errorf("provision account: %w (rolling back identity-provider user also failed: %v)", err, delErr)
		}
		return nil, fmt.Errorf("provision account: %w", err)
	}

	allGroupID := ""
	for _, group := range acc.Groups {
		if group.Name == "All" {
			allGroupID = group.ID
			break
		}
	}

	return map[string]any{
		"id":            acc.Id,
		"accountId":     acc.Id,
		"ownerUserId":   userData.ID,
		"ownerEmail":    in.OwnerEmail,
		"ownerPassword": in.OwnerPassword,
		"allGroupId":    allGroupID,
	}, nil
}

// accountTeardown removes the tenant. DeleteAccount deletes the account's users
// (and their identity-provider records) and then the account with every
// association GORM knows about, so it also sweeps rows a test created mid-run
// that were never part of "up".
func (f *factories) accountTeardown(record map[string]any, _ autonoma.FactoryContext) error {
	accountID := recordString(record, "id")
	ownerID := recordString(record, "ownerUserId")
	if accountID == "" || ownerID == "" {
		return nil
	}

	// The Agent Network gateway settings are keyed on the account but hang off no
	// association GORM walks, so the account delete below would leave the row
	// behind - and its globally unique endpoint with it.
	if _, err := f.deps.Store.GetAgentNetworkSettings(f.ctx(), store.LockingStrengthNone, accountID); err == nil {
		if err := f.deps.AgentNetwork.DeleteSettings(f.ctx(), accountID, ownerID); err != nil {
			return fmt.Errorf("delete agent network settings: %w", err)
		}
	}

	return ignoreNotFound(f.deps.AccountManager.DeleteAccount(f.ctx(), accountID, ownerID))
}

// SettingsInput updates the account settings row provisioning created.
type SettingsInput struct {
	AccountID string `json:"accountId"`
	// PeerLoginExpirationMinutes is how long a peer's login stays valid. It is a
	// duration, not an instant, so a fixed value stays correct.
	PeerLoginExpirationMinutes int64  `json:"peerLoginExpirationMinutes"`
	PeerLoginExpirationEnabled bool   `json:"peerLoginExpirationEnabled"`
	LocalMfaEnabled            bool   `json:"localMfaEnabled"`
	RegularUsersViewBlocked    bool   `json:"regularUsersViewBlocked"`
	GroupsPropagationEnabled   bool   `json:"groupsPropagationEnabled"`
	JWTGroupsEnabled           bool   `json:"jwtGroupsEnabled"`
	JWTGroupsClaimName         string `json:"jwtGroupsClaimName,omitempty"`
	RoutingPeerDNSResolution   bool   `json:"routingPeerDnsResolutionEnabled"`
}

// settingsFactory edits the settings the account already owns, which is the only
// way the application itself ever writes that row after provisioning.
func (f *factories) settingsFactory(in *SettingsInput, ctx autonoma.FactoryContext) (map[string]any, error) {
	owner, err := accountOwner(ctx, in.AccountID)
	if err != nil {
		return nil, err
	}

	current, err := f.deps.AccountManager.GetAccountSettings(f.ctx(), in.AccountID, owner)
	if err != nil {
		return nil, fmt.Errorf("read account settings: %w", err)
	}

	updated := current.Copy()
	updated.PeerLoginExpirationEnabled = in.PeerLoginExpirationEnabled
	if in.PeerLoginExpirationMinutes > 0 {
		updated.PeerLoginExpiration = minutesToDuration(in.PeerLoginExpirationMinutes)
	}
	updated.LocalMfaEnabled = in.LocalMfaEnabled
	updated.RegularUsersViewBlocked = in.RegularUsersViewBlocked
	updated.GroupsPropagationEnabled = in.GroupsPropagationEnabled
	updated.JWTGroupsEnabled = in.JWTGroupsEnabled
	if in.JWTGroupsClaimName != "" {
		updated.JWTGroupsClaimName = in.JWTGroupsClaimName
	}
	updated.RoutingPeerDNSResolutionEnabled = in.RoutingPeerDNSResolution

	if _, err := f.deps.AccountManager.UpdateAccountSettings(f.ctx(), in.AccountID, owner, updated); err != nil {
		return nil, fmt.Errorf("update account settings: %w", err)
	}

	// Settings are embedded on the account row, so the account's own teardown
	// removes them; the id is the account's for reference purposes only.
	return map[string]any{"id": in.AccountID, "accountId": in.AccountID}, nil
}

// UserInput invites a user into the account. With the embedded identity
// provider this creates them outright rather than mailing an invitation.
type UserInput struct {
	AccountID string `json:"accountId"`
	Email     string `json:"email"`
	Name      string `json:"name"`
	// Role is one of owner, admin, user, network_admin, billing_admin or auditor.
	Role       string   `json:"role"`
	AutoGroups []string `json:"autoGroups,omitempty"`
}

func (f *factories) userFactory(in *UserInput, ctx autonoma.FactoryContext) (map[string]any, error) {
	owner, err := accountOwner(ctx, in.AccountID)
	if err != nil {
		return nil, err
	}

	autoGroups := in.AutoGroups
	if autoGroups == nil {
		autoGroups = []string{}
	}

	info, err := f.deps.AccountManager.CreateUser(f.ctx(), in.AccountID, owner, &types.UserInfo{
		Email:      in.Email,
		Name:       in.Name,
		Role:       in.Role,
		AutoGroups: autoGroups,
		Issued:     types.UserIssuedAPI,
	})
	if err != nil {
		return nil, fmt.Errorf("create user %s: %w", in.Email, err)
	}

	return map[string]any{
		"id":        info.ID,
		"accountId": in.AccountID,
		"email":     info.Email,
		"name":      info.Name,
		"role":      info.Role,
	}, nil
}

func (f *factories) userTeardown(record map[string]any, ctx autonoma.FactoryContext) error {
	accountID := recordString(record, "accountId")
	owner, err := accountOwner(ctx, accountID)
	if err != nil {
		return err
	}
	return ignoreNotFound(f.deps.AccountManager.DeleteUser(f.ctx(), accountID, owner, recordString(record, "id")))
}

// PersonalAccessTokenInput mints an API token for a seeded user.
type PersonalAccessTokenInput struct {
	AccountID string `json:"accountId"`
	UserID    string `json:"userId"`
	Name      string `json:"name"`
	// ExpiresInDays is an offset from seeding time, between 1 and 365. The token
	// is rejected by the API the moment it passes, so it cannot be an instant.
	ExpiresInDays int `json:"expiresInDays"`
}

func (f *factories) patFactory(in *PersonalAccessTokenInput, _ autonoma.FactoryContext) (map[string]any, error) {
	// A token can only be minted for yourself unless the target is a service
	// user, so the token's own user is the initiator - the same call the
	// dashboard makes from the user's profile page.
	generated, err := f.deps.AccountManager.CreatePAT(f.ctx(), in.AccountID, in.UserID, in.UserID, in.Name, in.ExpiresInDays)
	if err != nil {
		return nil, fmt.Errorf("create personal access token %s: %w", in.Name, err)
	}

	return map[string]any{
		"id":        generated.ID,
		"accountId": in.AccountID,
		"userId":    in.UserID,
		"name":      generated.Name,
		"token":     generated.PlainToken,
	}, nil
}

func (f *factories) patTeardown(record map[string]any, _ autonoma.FactoryContext) error {
	userID := recordString(record, "userId")
	return ignoreNotFound(f.deps.AccountManager.DeletePAT(f.ctx(), recordString(record, "accountId"), userID,
		userID, recordString(record, "id")))
}

// UserInviteInput creates a pending invitation link.
type UserInviteInput struct {
	AccountID string `json:"accountId"`
	Email     string `json:"email"`
	Name      string `json:"name"`
	Role      string `json:"role"`
	// ExpiresInSeconds is an offset from seeding time; the invite endpoints
	// reject a link once it passes. Minimum one hour.
	ExpiresInSeconds int `json:"expiresInSeconds"`
}

func (f *factories) userInviteFactory(in *UserInviteInput, ctx autonoma.FactoryContext) (map[string]any, error) {
	owner, err := accountOwner(ctx, in.AccountID)
	if err != nil {
		return nil, err
	}

	invite, err := f.deps.AccountManager.CreateUserInvite(f.ctx(), in.AccountID, owner, &types.UserInfo{
		Email:      in.Email,
		Name:       in.Name,
		Role:       in.Role,
		AutoGroups: []string{},
		Issued:     types.UserIssuedAPI,
	}, in.ExpiresInSeconds)
	if err != nil {
		return nil, fmt.Errorf("create invite for %s: %w", in.Email, err)
	}

	inviteID := ""
	if invite.UserInfo != nil {
		inviteID = invite.UserInfo.ID
	}

	return map[string]any{
		"id":        inviteID,
		"accountId": in.AccountID,
		"email":     in.Email,
		"token":     invite.InviteToken,
	}, nil
}

func (f *factories) userInviteTeardown(record map[string]any, ctx autonoma.FactoryContext) error {
	accountID := recordString(record, "accountId")
	owner, err := accountOwner(ctx, accountID)
	if err != nil {
		return err
	}
	return ignoreNotFound(f.deps.AccountManager.DeleteUserInvite(f.ctx(), accountID, owner, recordString(record, "id")))
}

// InstallationInput sets the instance's installation identifier. The row is a
// singleton keyed on a fixed primary key rather than on an account, so the
// factory records the previous value and restores it on teardown instead of
// deleting a row the instance needs.
type InstallationInput struct {
	InstallationID string `json:"installationId"`
}

func (f *factories) installationFactory(in *InstallationInput, _ autonoma.FactoryContext) (map[string]any, error) {
	previous := f.deps.Store.GetInstallationID()
	if err := f.deps.Store.SaveInstallationID(f.ctx(), in.InstallationID); err != nil {
		return nil, fmt.Errorf("save installation id: %w", err)
	}
	return map[string]any{
		"id":                 in.InstallationID,
		"previousInstallID":  previous,
		"installationIDSeen": in.InstallationID,
	}, nil
}

func (f *factories) installationTeardown(record map[string]any, _ autonoma.FactoryContext) error {
	previous := recordString(record, "previousInstallID")
	if previous == "" {
		return nil
	}
	return f.deps.Store.SaveInstallationID(f.ctx(), previous)
}

// auth returns credentials the test runner signs in with. The dashboard
// authenticates through the OpenID Connect flow against the embedded identity
// provider, so there is no cookie or bearer token this endpoint could mint that
// the browser would accept: the runner has to walk the real login form. It
// therefore gets the seeded owner's email and password, which are real
// credentials created by the same call /api/setup uses.
func (f *factories) auth(user map[string]any, ctx autonoma.AuthContext) (map[string]any, error) {
	accounts := ctx.Refs["Account"]
	if len(accounts) == 0 {
		return map[string]any{}, nil
	}

	seeded := accounts[0]
	if user != nil {
		if accountID, _ := user["accountId"].(string); accountID != "" {
			for _, candidate := range accounts {
				if id, _ := candidate["id"].(string); id == accountID {
					seeded = candidate
					break
				}
			}
		}
	}

	email := recordString(seeded, "ownerEmail")
	password := recordString(seeded, "ownerPassword")
	if email == "" || password == "" {
		return nil, fmt.Errorf("seeded account %q carries no owner credentials", recordString(seeded, "id"))
	}

	return map[string]any{
		"credentials": map[string]string{
			"email":    email,
			"username": email,
			"password": password,
		},
	}, nil
}
