package cloudflare

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	PermissionZoneRead      = "Zone Read"
	PermissionDNSRead       = "DNS Read"
	PermissionDNSWrite      = "DNS Write"
	PermissionSendingRead   = "Email Sending Read"
	PermissionSendingWrite  = "Email Sending Write"
	PermissionRoutingRead   = "Email Routing Rules Read"
	PermissionRoutingWrite  = "Email Routing Rules Write"
	PermissionSettingsRead  = "Zone Settings Read"
	PermissionSettingsWrite = "Zone Settings Write"
	PermissionWorkersRead   = "Workers Scripts Read"
	PermissionWorkersWrite  = "Workers Scripts Write"
	PermissionTunnelRead    = "Cloudflare Tunnel Read"
	PermissionVPCRead       = "Connectivity Directory Read"
	PermissionVPCWrite      = "Connectivity Directory Admin"
)

type PermissionGroup struct {
	ID     string   `json:"id"`
	Name   string   `json:"name"`
	Scopes []string `json:"scopes,omitempty"`
}

type TokenPolicy struct {
	Effect           string            `json:"effect"`
	Resources        map[string]any    `json:"resources"`
	PermissionGroups []PermissionGroup `json:"permission_groups"`
}

type Token struct {
	ID        string        `json:"id"`
	Status    string        `json:"status"`
	ExpiresOn *time.Time    `json:"expires_on,omitempty"`
	NotBefore *time.Time    `json:"not_before,omitempty"`
	Policies  []TokenPolicy `json:"policies,omitempty"`
}

type Zone struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Status  string `json:"status"`
	Type    string `json:"type"`
	Account struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"account"`
}

// TokenAccess preserves uncertainty: verification does NOT reveal policies.
// A least-privilege mail token may be unable to read its own token metadata or
// enumerate zones. The wizard can still request an explicit zone identifier.
type TokenAccess struct {
	Token         Token             `json:"token"`
	PoliciesKnown bool              `json:"policiesKnown"`
	Permissions   []PermissionGroup `json:"permissions"`
	Zones         []Zone            `json:"zones"`
	PoliciesError *Error            `json:"policiesError,omitempty"`
	ZonesError    *Error            `json:"zonesError,omitempty"`
}

func (c *Client) tokenPath(suffix ...string) (string, error) {
	parts := []string{"user", "tokens"}
	if c.tokenAccountID != "" {
		parts = []string{"accounts", c.tokenAccountID, "tokens"}
	}
	return path(append(parts, suffix...)...)
}

func (c *Client) VerifyToken(ctx context.Context) (Token, error) {
	p, _ := c.tokenPath("verify")
	var token Token
	_, err := c.request(ctx, http.MethodGet, p, nil, nil, &token)
	if err == nil && (token.Status != "active" || !identifier.MatchString(token.ID)) {
		err = &Error{Kind: ErrAuth, Operation: "token verification"}
	}
	return token, err
}

// InspectToken reads the token's actual policies, never the permission-group
// catalog (which describes selectable permissions, not this token's grants).
func (c *Client) InspectToken(ctx context.Context) (TokenAccess, error) {
	token, err := c.VerifyToken(ctx)
	if err != nil {
		return TokenAccess{}, err
	}
	result := TokenAccess{Token: token}
	p, _ := c.tokenPath(token.ID)
	var detail Token
	_, err = c.request(ctx, http.MethodGet, p, nil, nil, &detail, "API Tokens Read")
	if err != nil {
		if !IsKind(err, ErrPermission) && !IsKind(err, ErrNotFound) {
			return result, err
		}
		result.PoliciesError = asError(err)
	} else {
		if detail.ID != token.ID || detail.Status != "active" || detail.Policies == nil {
			return result, &Error{Kind: ErrProtocol, Operation: "token policies"}
		}
		result.Token = detail
		result.PoliciesKnown = true
		seen := map[string]bool{}
		for _, policy := range detail.Policies {
			if policy.Effect != "allow" {
				continue
			}
			for _, permission := range policy.PermissionGroups {
				if !seen[permission.ID] {
					result.Permissions = append(result.Permissions, permission)
					seen[permission.ID] = true
				}
			}
		}
		sort.Slice(result.Permissions, func(i, j int) bool { return result.Permissions[i].Name < result.Permissions[j].Name })
	}
	result.Zones, err = c.ListZones(ctx)
	if err != nil {
		if !IsKind(err, ErrPermission) {
			return result, err
		}
		result.ZonesError = asError(err)
	}
	return result, nil
}

// PermissionState reports a permission *name* in the actual policy document.
// Scope and deny policies are intentionally not inferred; Resources in Token
// must be reviewed and the actual operation remains the authority.
func (a TokenAccess) PermissionState(name string) string {
	if !a.PoliciesKnown {
		return "unknown"
	}
	for _, permission := range a.Permissions {
		if permission.Name == name {
			return "present"
		}
	}
	return "missing"
}

func (c *Client) ListZones(ctx context.Context) ([]Zone, error) {
	return list[Zone](ctx, c, "/zones", nil, PermissionZoneRead)
}

func (c *Client) GetZone(ctx context.Context, zoneID string) (Zone, error) {
	p, err := path("zones", zoneID)
	if err != nil {
		return Zone{}, err
	}
	var zone Zone
	_, err = c.request(ctx, http.MethodGet, p, nil, nil, &zone, PermissionZoneRead)
	return zone, err
}

// FindZone tries exact domain suffixes in order, without assuming public suffix
// length (co.uk, private/delegated zones and international IDNA names work).
func (c *Client) FindZone(ctx context.Context, domain string) (Zone, error) {
	name, err := domainName(domain)
	if err != nil {
		return Zone{}, err
	}
	for candidate := name; candidate != ""; {
		zones, err := list[Zone](ctx, c, "/zones", url.Values{"name": {candidate}}, PermissionZoneRead)
		if err != nil {
			return Zone{}, err
		}
		var matching []Zone
		for _, zone := range zones {
			if strings.EqualFold(zone.Name, candidate) {
				matching = append(matching, zone)
			}
		}
		if len(matching) == 1 {
			return matching[0], nil
		}
		if len(matching) > 1 {
			return Zone{}, conflict("ambiguous zone")
		}
		_, next, ok := strings.Cut(candidate, ".")
		if !ok {
			break
		}
		candidate = next
	}
	return Zone{}, &Error{Kind: ErrNotFound, Operation: "find zone"}
}

// asError finds the typed Cloudflare error even when a caller wrapped it.
func asError(err error) *Error {
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	return nil
}

// Account is one Cloudflare account the token can see.
type Account struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// ListAccounts lists the accounts the token can see (GET /accounts). A token
// limited to zone permissions may be refused; callers then fall back to the
// accounts named by the zones it can read.
func (c *Client) ListAccounts(ctx context.Context) ([]Account, error) {
	return list[Account](ctx, c, "/accounts", nil)
}

// ListAccountZones lists one account's zones. Cloudflare filters by
// account.id; the result is filtered again so a zone of another account is
// never offered.
func (c *Client) ListAccountZones(ctx context.Context, accountID string) ([]Zone, error) {
	if !identifier.MatchString(accountID) {
		return nil, invalid("account ID")
	}
	zones, err := list[Zone](ctx, c, "/zones", url.Values{"account.id": {accountID}}, PermissionZoneRead)
	if err != nil {
		return nil, err
	}
	out := []Zone{}
	for _, z := range zones {
		if z.Account.ID == accountID {
			out = append(out, z)
		}
	}
	return out, nil
}
