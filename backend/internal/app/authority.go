package app

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"time"

	"SynoMailPlusSetupAssistant/internal/core/dsmauthority"
	"github.com/synopackageland/syno-pkg-land-sdk/api"
	"github.com/synopackageland/syno-pkg-land-sdk/delegate"
)

func (cfg Config) webAPIClient() delegate.ExecutorClient {
	if cfg.WebAPIExecutor != nil {
		return cfg.WebAPIExecutor
	}
	return delegate.Local(cfg.PackageID)
}

func (cfg Config) authorityRoutes() []api.Route {
	return []api.Route{
		api.HandleRequest("dsm.authority.status", cfg.authorityStatus),
		api.HandleRequest("dsm.authority.grant", cfg.authorityGrant),
		api.HandleRequest("dsm.authority.revoke", cfg.authorityRevoke),
	}
}

func (cfg Config) authorityCapability(ctx context.Context, auth map[string]string) delegate.Capability {
	s := delegate.Service{Client: cfg.webAPIClient(), ExecutorDigest: cfg.ExecutorDigest, PolicyDigest: cfg.PolicyDigest}
	// Production pins are supplied only by the package build, never by params.
	if cfg.ExecutorDigest == "" || cfg.PolicyDigest == "" {
		return delegate.Capability{State: "needs-admin-approval", Reason: "approval-pins-missing"}
	}
	return s.Status(ctx, auth)
}

func (cfg Config) callerGrants(ctx context.Context, auth map[string]string) ([]delegate.Grant, error) {
	var out struct {
		Delegations []delegate.Grant `json:"delegations"`
	}
	if err := cfg.webAPIClient().Call(ctx, "delegate.list", auth, nil, &out); err != nil {
		return nil, err
	}
	grants := []delegate.Grant{}
	for _, g := range out.Delegations {
		if _, ok := dsmauthority.Profiles()[g.Scope]; ok && g.Lifetime == "until-revoked" {
			grants = append(grants, g)
		}
	}
	return grants, nil
}

func (cfg Config) authorityStatus(ctx context.Context, c api.Caller, req *http.Request, raw json.RawMessage) (any, error) {
	if err := api.RequireAdmin(c); err != nil {
		return nil, err
	}
	if err := decodeParams(raw, &struct{}{}); err != nil {
		return nil, err
	}
	auth, err := api.DSMSession(req)
	if err != nil {
		return nil, err
	}
	stored, err := cfg.callCore(ctx, c, "dsm.authority.status", json.RawMessage(`{}`))
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(stored)
	if err != nil {
		return nil, err
	}
	var bindings map[string]dsmauthority.Binding
	if json.Unmarshal(b, &bindings) != nil {
		return nil, &api.Error{Code: "bad_response", Message: "Authority state is unavailable"}
	}
	capability := cfg.authorityCapability(ctx, auth)
	grants := []delegate.Grant{}
	if capability.State == "ready" {
		grants, err = cfg.callerGrants(ctx, auth)
		if err != nil {
			return nil, err
		}
	}
	type profileView struct {
		Name         string                     `json:"name"`
		Profile      dsmauthority.WebAPIProfile `json:"profile"`
		State        string                     `json:"state"`
		ConfiguredBy string                     `json:"configuredBy,omitempty"`
		GrantID      string                     `json:"grantId,omitempty"`
		CanRevoke    bool                       `json:"canRevoke"`
	}
	profiles := []profileView{}
	for name, p := range dsmauthority.Profiles() {
		binding := bindings[name]
		v := profileView{Name: name, Profile: p, State: "missing", ConfiguredBy: binding.Grant.Subject.Username}
		switch {
		case capability.State != "ready":
			v.State = "needs-admin-approval"
		case binding.Grant.DelegationID == "":
		case binding.Grant.Subject.Username != c.User():
			v.State = "other-administrator"
		default:
			v.State = "needs-authorization"
			for _, g := range grants {
				if g.DelegationID == binding.Grant.DelegationID {
					v.GrantID = g.DelegationID
					v.CanRevoke = !g.Revoked
					if !g.Revoked && (g.ExpiresAt.IsZero() || g.ExpiresAt.After(time.Now())) && binding.State == "configured" {
						v.State = "granted"
					}
				}
			}
		}
		profiles = append(profiles, v)
	}
	sort.Slice(profiles, func(i, j int) bool { return profiles[i].Name < profiles[j].Name })
	return map[string]any{"capability": capability, "profiles": profiles, "grants": grants}, nil
}

func (cfg Config) authorityGrant(ctx context.Context, c api.Caller, req *http.Request, raw json.RawMessage) (any, error) {
	if err := api.RequireAdmin(c); err != nil {
		return nil, err
	}
	var in struct {
		Profile   string `json:"profile"`
		Confirmed bool   `json:"confirmed"`
	}
	if err := decodeParams(raw, &in); err != nil {
		return nil, err
	}
	if _, ok := dsmauthority.Profiles()[in.Profile]; !ok || !in.Confirmed {
		return nil, api.BadRequest("Confirm an approved authority profile")
	}
	auth, err := api.DSMSession(req)
	if err != nil {
		return nil, err
	}
	if capability := cfg.authorityCapability(ctx, auth); capability.State != "ready" {
		return nil, api.WithDetails(&api.Error{Code: "authority_required", Message: "Approve the package in Administrator setup first"}, map[string]string{"profile": in.Profile})
	}
	g, err := delegate.CreateWebAPIGrant(ctx, cfg.webAPIClient(), auth, in.Profile, delegate.WebAPIGrantOptions{UntilRevoked: true})
	if err != nil {
		return nil, err
	}
	// The executor validates the live session's nonzero UID and administrator
	// entry. Reject a corrupt/mismatched response before remembering anything.
	if g.Scope != in.Profile || g.Subject.Username != c.User() {
		return nil, &api.Error{Code: "bad_response", Message: "Authority grant did not match the caller"}
	}
	p, err := json.Marshal(g)
	if err != nil {
		return nil, err
	}
	if _, err = cfg.callCore(ctx, c, "dsm.authority.grant", p); err != nil {
		// A subsequent explicit grant repeats SDK idempotent consent and
		// recovers the same reference; it never replays a mutation.
		return nil, err
	}
	return map[string]any{"granted": true, "profile": in.Profile, "grantId": g.DelegationID}, nil
}

func (cfg Config) authorityRevoke(ctx context.Context, c api.Caller, req *http.Request, raw json.RawMessage) (any, error) {
	if err := api.RequireAdmin(c); err != nil {
		return nil, err
	}
	var in struct {
		Profile string `json:"profile"`
		ID      string `json:"id"`
	}
	if err := decodeParams(raw, &in); err != nil {
		return nil, err
	}
	if _, ok := dsmauthority.Profiles()[in.Profile]; !ok || in.ID == "" {
		return nil, api.BadRequest("Select an authority grant")
	}
	auth, err := api.DSMSession(req)
	if err != nil {
		return nil, err
	}
	grants, err := cfg.callerGrants(ctx, auth)
	if err != nil {
		return nil, err
	}
	found := false
	for _, g := range grants {
		if g.DelegationID == in.ID && g.Scope == in.Profile && g.Subject.Username == c.User() {
			found = true
		}
	}
	if !found {
		return nil, api.WithDetails(&api.Error{Code: "authority_required", Message: "Only the granting administrator may revoke this grant"}, map[string]string{"profile": in.Profile})
	}
	// Always repeat protected revoke, including after a lost reply. It drains
	// in-flight calls before acknowledgment; clearing a mirror is insufficient.
	if err := cfg.webAPIClient().Call(ctx, "delegate.revoke", auth, map[string]string{"delegation_id": in.ID}, nil); err != nil {
		return nil, err
	}
	p, _ := json.Marshal(in)
	if _, err = cfg.callCore(ctx, c, "dsm.authority.revoke", p); err != nil {
		return nil, err
	}
	return map[string]any{"revoked": true}, nil
}
