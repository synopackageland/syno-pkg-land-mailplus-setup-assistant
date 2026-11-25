package setup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"

	"SynoMailPlusSetupAssistant/internal/core"
)

// ConfidentialDSM is supplied by core's DSM transport for MailPlus credential
// payload encryption. A plain DSM.Call is deliberately insufficient for AUTH.
// This is a local adapter contract, not a change to core/contract.go.
type ConfidentialDSM interface {
	CallConfidential(context.Context, string, string, int, map[string]any, any) error
}

// MailPlusAdapter supports the researched SMTP, outbound signing, and empty
// default-Delivery setup, and (build 50) creating the mail domain on
// a MailPlus Server that finished its first-run setup. Members, licences and
// the first-run setup stay in MailPlus's own wizard; DSM accounts are never
// created.
//
// The domain step (mailplus.domain) creates exactly one domain with the
// setup's name (SYNO.MailPlusServer.Domain create v1, verified on MailPlus
// Server 4.1.1-31785: {name, desc, default_alias_pattern,
// is_automatically_adding_users} → {domain_id}; a new domain has no member
// and DKIM signing off). Its operation records the created ID. Rollback and
// removal delete only that domain (delete v1 {domain_ids}), only while it
// still has that name, the App's description and no user; with users it
// refuses (ErrDomainInUse) and the administrator decides.
const domainMarker = "Created by MailPlus Setup Assistant"

type MailPlusAdapter struct{}

func NewMailPlus() *MailPlusAdapter { return &MailPlusAdapter{} }

var _ MailPlus = (*MailPlusAdapter)(nil)

type relayConfig struct {
	Listen      string `json:"listen"`
	UsernameRef string `json:"usernameRef"`
	PasswordRef string `json:"passwordRef"`
	STARTTLS    bool   `json:"starttls"`
	Auth        bool   `json:"auth"`
	Fallback    bool   `json:"fallback"`
}
type mpOperation struct {
	Kind     string          `json:"kind"`
	DomainID int             `json:"domainId,omitempty"`
	Before   json.RawMessage `json:"before"`
	After    json.RawMessage `json:"after"`
	Relay    relayConfig     `json:"relay,omitempty"`
}

func mpRead(ctx context.Context, env core.Env, api, method string, version int, params map[string]any) (json.RawMessage, error) {
	if env.DSM == nil {
		return nil, ErrUnavailable
	}
	var out json.RawMessage
	if err := env.DSM.Call(ctx, api, method, version, params, &out); err != nil {
		return nil, publicError(err)
	}
	if !json.Valid(out) {
		return nil, ErrUnsafeReply
	}
	return out, nil
}
func mpWrite(ctx context.Context, env core.Env, api, method string, version int, params map[string]any) error {
	if env.DSM == nil {
		return ErrUnavailable
	}
	// MailPlus writes answer {"success":true} with no data field: decoding
	// one would turn every completed write into a bad reply.
	if e := env.DSM.Call(ctx, api, method, version, params, nil); e != nil {
		return publicError(e)
	}
	return nil
}
func (m *MailPlusAdapter) Plan(ctx context.Context, env core.Env, r PlanRequest, prior []core.Change) (Prepared, error) {
	p := Prepared{Restorable: true, Changes: []core.Change{}}
	if env.DSM == nil || env.Secrets == nil {
		return p, ErrUnavailable
	}
	for _, need := range r.Decision.Needs {
		if need == "mailplus.members" {
			return p, ErrUnavailable
		}
		op := mpOperation{Kind: need}
		var before, after any
		var target string
		switch need {
		case "mailplus.domain":
			name := r.Domain
			if r.State.Domains.IsKnown() {
				for _, dm := range r.State.Domains.Value {
					if dm.Name == name {
						return p, ErrStale // created meanwhile: detect again
					}
				}
			}
			op.Before, _ = json.Marshal(domainState{Name: name})
			op.After, _ = json.Marshal(domainState{Name: name, Exists: true})
			before = "No MailPlus Server mail domain " + name
			after = map[string]any{"domain": name, "users": 0, "description": domainMarker}
			target = "mailplus.domain"
		case "mailplus.smtp":
			b, e := mpRead(ctx, env, "SYNO.MailPlusServer.Service.SMTP", "get", 1, map[string]any{})
			if e != nil {
				return p, e
			}
			var values map[string]json.RawMessage
			if json.Unmarshal(b, &values) != nil {
				return p, ErrUnsafeReply
			}
			required := []string{"account_type", "account_domain_name", "enable_smtp", "smtp_port", "enable_smtp_ssl", "smtp_ssl_port", "enable_smtp_tls", "smtp_tls_port"}
			kept := map[string]json.RawMessage{}
			for _, k := range required {
				v, ok := values[k]
				if !ok {
					return p, ErrUnsafeReply
				}
				kept[k] = v
			}
			op.Before, _ = json.Marshal(kept)
			kept["enable_smtp"] = json.RawMessage("true")
			op.After, _ = json.Marshal(kept)
			before = "SMTP disabled"
			after = "SMTP enabled with all existing ports and account settings preserved"
			target = "mailplus.smtp"
		case "mailplus.dkim.disable":
			id := 0
			for _, dm := range r.State.Domains.Value {
				if dm.Name == r.Domain {
					id = dm.ID
				}
			}
			if id == 0 {
				return p, ErrUnsafeReply
			}
			op.DomainID = id
			b, e := mpRead(ctx, env, "SYNO.MailPlusServer.Domain", "get_security", 2, map[string]any{"domain_id": id})
			if e != nil {
				return p, e
			}
			var v struct {
				Enabled  *bool  `json:"enable_dkim_sign"`
				Selector string `json:"dkim_selector"`
			}
			if json.Unmarshal(b, &v) != nil || v.Enabled == nil || !*v.Enabled {
				return p, ErrStale
			}
			op.Before, _ = json.Marshal(map[string]any{"enable_dkim_sign": true, "dkim_selector": v.Selector})
			op.After, _ = json.Marshal(map[string]any{"enable_dkim_sign": false, "dkim_selector": v.Selector})
			before = map[string]any{"enable_dkim_sign": true, "selector": v.Selector}
			after = map[string]any{"enable_dkim_sign": false, "selector": v.Selector}
			target = "mailplus.dkim"
		case "mailplus.delivery":
			if _, ok := env.DSM.(ConfidentialDSM); !ok {
				return p, ErrUnavailable
			}
			var relay *core.Change
			for index := range prior {
				if prior[index].Target == "homekeeper.relay" {
					if relay != nil {
						return p, ErrUnsafePlanCheck
					}
					relay = &prior[index]
				}
			}
			if relay == nil {
				return p, ErrUnsafePlanCheck
			}
			conf := relayConfig{Listen: relay.Params["listen"], UsernameRef: relay.Params["usernameRef"], PasswordRef: relay.Params["passwordRef"], STARTTLS: true, Auth: true, Fallback: false}
			host, port, e := net.SplitHostPort(conf.Listen)
			ip := net.ParseIP(host)
			n, pe := strconv.Atoi(port)
			if e != nil || pe != nil || n < 1 || n > 65535 || ip == nil || !ip.IsLoopback() || !secretReference(conf.UsernameRef) || !secretReference(conf.PasswordRef) || relay.Params["starttls"] != "required" {
				return p, ErrUnsafePlanCheck
			}
			typ, e := mpRead(ctx, env, "SYNO.MailPlusServer.SMTP.Delivery", "get_type", 3, map[string]any{})
			if e != nil {
				return p, e
			}
			hosts, e := mpRead(ctx, env, "SYNO.MailPlusServer.SMTP.Delivery", "get_multiple", 3, map[string]any{"list_type": "default"})
			if e != nil {
				return p, e
			}
			var v struct {
				Type     string `json:"host_type"`
				Fallback *bool  `json:"enable_fallback_relay"`
			}
			var h struct {
				Hosts *[]json.RawMessage `json:"host_list"`
			}
			if json.Unmarshal(typ, &v) != nil || json.Unmarshal(hosts, &h) != nil || v.Type != "none" || v.Fallback == nil || *v.Fallback || h.Hosts == nil || len(*h.Hosts) != 0 {
				return p, ErrUnsafeReply
			}
			op.Before, _ = json.Marshal(map[string]any{"host_type": "none", "enable_fallback_relay": false, "host_list": []any{}})
			op.Relay = conf
			op.After, _ = json.Marshal(conf)
			before = "No default relay or fallback"
			after = map[string]any{"server": host, "port": n, "starttls": true, "auth": true, "fallback": false, "scope": "all default-routed senders"}
			target = "mailplus.delivery"
		default:
			continue
		}
		if digest(op.Before) == digest(op.After) {
			return p, ErrStale
		}
		ref := "secret:mail.setup.operation." + digest(struct{ Session, Need string }{r.SessionID, need})
		b, _ := json.Marshal(op)
		if e := env.Secrets.Put(ctx, ref, string(b)); e != nil {
			return p, ErrUnavailable
		}
		cb, _ := json.Marshal(before)
		ca, _ := json.Marshal(after)
		p.Changes = append(p.Changes, core.Change{ID: need, Target: target, ActionKey: "mail.setup.change." + need, Params: map[string]string{"domain": r.Domain, "operationRef": ref}, Before: string(cb), After: string(ca)})
	}
	return p, nil
}
func mpLoad(ctx context.Context, env core.Env, c core.Change) (mpOperation, error) {
	var op mpOperation
	if env.Secrets == nil || !secretReference(c.Params["operationRef"]) {
		return op, ErrUnsafeRecord
	}
	value, e := env.Secrets.Get(ctx, c.Params["operationRef"])
	if e != nil || json.Unmarshal([]byte(value), &op) != nil {
		return op, ErrUnavailable
	}
	return op, nil
}
func mpCurrent(ctx context.Context, env core.Env, op mpOperation) (json.RawMessage, error) {
	switch op.Kind {
	case "mailplus.smtp":
		b, e := mpRead(ctx, env, "SYNO.MailPlusServer.Service.SMTP", "get", 1, map[string]any{})
		if e != nil {
			return nil, e
		}
		var full map[string]json.RawMessage
		var keys map[string]json.RawMessage
		if json.Unmarshal(b, &full) != nil || json.Unmarshal(op.Before, &keys) != nil {
			return nil, ErrUnsafeReply
		}
		for k := range keys {
			v, ok := full[k]
			if !ok {
				return nil, ErrUnsafeReply
			}
			keys[k] = v
		}
		return json.Marshal(keys)
	case "mailplus.dkim.disable":
		b, e := mpRead(ctx, env, "SYNO.MailPlusServer.Domain", "get_security", 2, map[string]any{"domain_id": op.DomainID})
		if e != nil {
			return nil, e
		}
		var v struct {
			Enabled  *bool  `json:"enable_dkim_sign"`
			Selector string `json:"dkim_selector"`
		}
		if json.Unmarshal(b, &v) != nil || v.Enabled == nil {
			return nil, ErrUnsafeReply
		}
		return json.Marshal(map[string]any{"enable_dkim_sign": *v.Enabled, "dkim_selector": v.Selector})
	case "mailplus.delivery":
		return mpDeliveryCurrent(ctx, env, op)
	case "mailplus.domain":
		var want domainState
		if json.Unmarshal(op.Before, &want) != nil || want.Name == "" {
			return nil, ErrUnsafeRecord
		}
		found, ok, e := mpDomain(ctx, env, want.Name)
		if e != nil {
			return nil, e
		}
		return json.Marshal(domainState{Name: want.Name, Exists: ok && found.ID > 0})
	}
	return nil, ErrUnsafePlanCheck
}

// domainState is the domain step's before and after: whether MailPlus Server
// has a domain with the setup's name.
type domainState struct {
	Name   string `json:"name"`
	Exists bool   `json:"exists"`
}

// mailDomain is one MailPlus Server domain as the domain step reads it.
type mailDomain struct {
	ID    int    `json:"domain_id"`
	Name  string `json:"name"`
	Desc  string `json:"desc"`
	Users *int   `json:"user_num"`
}

// mpDomain finds the domain named name (Domain list v1, every domain, as
// detection reads it).
func mpDomain(ctx context.Context, env core.Env, name string) (mailDomain, bool, error) {
	b, e := mpRead(ctx, env, "SYNO.MailPlusServer.Domain", "list", 1, map[string]any{"offset": 0, "limit": -1})
	if e != nil {
		return mailDomain{}, false, e
	}
	var v struct {
		Domains *[]mailDomain `json:"domains"`
	}
	if json.Unmarshal(b, &v) != nil || v.Domains == nil {
		return mailDomain{}, false, ErrUnsafeReply
	}
	for _, d := range *v.Domains {
		if d.ID <= 0 || d.Name == "" {
			return mailDomain{}, false, ErrUnsafeReply
		}
		if d.Name == name {
			return d, true, nil
		}
	}
	return mailDomain{}, false, nil
}

// mpCreateDomain creates the domain and records its ID in the operation
// (before anything else may fail), so rollback and removal delete exactly it.
// A create whose reply was lost is reconciled by the next apply: the domain
// then exists with the App's description and its ID is recorded.
func mpCreateDomain(ctx context.Context, env core.Env, c core.Change, op mpOperation) error {
	var want domainState
	if json.Unmarshal(op.Before, &want) != nil || want.Name == "" {
		return ErrUnsafeRecord
	}
	var created struct {
		ID *int `json:"domain_id"`
	}
	if e := env.DSM.Call(ctx, "SYNO.MailPlusServer.Domain", "create", 1, map[string]any{"name": want.Name, "desc": domainMarker,
		"default_alias_pattern": "<a>", "is_automatically_adding_users": false}, &created); e != nil {
		return publicError(e)
	}
	found, ok, e := mpDomain(ctx, env, want.Name)
	if e != nil {
		return afterSent(e)
	}
	if !ok || created.ID == nil || found.ID != *created.ID {
		return ErrUnsafeReply
	}
	return mpRecordDomain(ctx, env, c, op, found.ID)
}

func mpRecordDomain(ctx context.Context, env core.Env, c core.Change, op mpOperation, id int) error {
	op.DomainID = id
	b, _ := json.Marshal(op)
	if e := env.Secrets.Put(ctx, c.Params["operationRef"], string(b)); e != nil {
		return ErrUnavailable
	}
	return nil
}

// mpDeleteDomain deletes the domain this setup created, only that one.
func mpDeleteDomain(ctx context.Context, env core.Env, op mpOperation) error {
	var want domainState
	if json.Unmarshal(op.Before, &want) != nil || want.Name == "" {
		return ErrUnsafeRecord
	}
	found, ok, e := mpDomain(ctx, env, want.Name)
	if e != nil {
		return e
	}
	if !ok {
		return nil // already gone
	}
	if (op.DomainID != 0 && found.ID != op.DomainID) || (op.DomainID == 0 && found.Desc != domainMarker) {
		return ErrStale // another domain with this name: not the App's
	}
	if found.Users == nil {
		return ErrUnsafeReply
	}
	if *found.Users > 0 {
		return ErrDomainInUse
	}
	return mpWrite(ctx, env, "SYNO.MailPlusServer.Domain", "delete", 1, map[string]any{"domain_ids": []int{found.ID}})
}
func (m *MailPlusAdapter) Snapshot(ctx context.Context, env core.Env, c core.Change) (json.RawMessage, error) {
	op, e := mpLoad(ctx, env, c)
	if e != nil {
		return nil, e
	}
	current, e := mpCurrent(ctx, env, op)
	if e != nil {
		return nil, e
	}
	if digest(current) != digest(op.Before) {
		return nil, ErrStale
	}
	return json.Marshal(struct {
		OperationRef string `json:"operationRef"`
		BeforeDigest string `json:"beforeDigest"`
	}{c.Params["operationRef"], digest(op.Before)})
}
func (m *MailPlusAdapter) Apply(ctx context.Context, env core.Env, c core.Change) error {
	op, e := mpLoad(ctx, env, c)
	if e != nil {
		return e
	}
	current, e := mpCurrent(ctx, env, op)
	if e != nil {
		return e
	}
	if digest(current) == digest(op.After) {
		if op.Kind == "mailplus.domain" && op.DomainID == 0 {
			// A create whose reply was lost: record the domain if it is ours.
			var want domainState
			_ = json.Unmarshal(op.Before, &want)
			found, ok, e := mpDomain(ctx, env, want.Name)
			if e != nil {
				return e
			}
			if !ok || found.Desc != domainMarker {
				return ErrStale
			}
			return mpRecordDomain(ctx, env, c, op, found.ID)
		}
		return nil
	}
	if op.Kind == "mailplus.delivery" && isPartial(current, op) {
		return mpWrite(ctx, env, "SYNO.MailPlusServer.SMTP.Delivery", "set_type", 3, map[string]any{"host_type": "list"})
	}
	if digest(current) != digest(op.Before) {
		return ErrStale
	}
	if op.Kind == "mailplus.delivery" {
		return mpSetDelivery(ctx, env, op)
	}
	if op.Kind == "mailplus.domain" {
		return mpCreateDomain(ctx, env, c, op)
	}
	return mpSet(ctx, env, op, op.After)
}
func (m *MailPlusAdapter) Rollback(ctx context.Context, env core.Env, c core.Change, snapshot json.RawMessage) error {
	op, e := mpLoad(ctx, env, c)
	if e != nil {
		return e
	}
	var snap struct {
		OperationRef string `json:"operationRef"`
		BeforeDigest string `json:"beforeDigest"`
	}
	if json.Unmarshal(snapshot, &snap) != nil || snap.OperationRef != c.Params["operationRef"] || snap.BeforeDigest != digest(op.Before) {
		return ErrUnsafeRecord
	}
	current, e := mpCurrent(ctx, env, op)
	if e != nil {
		return e
	}
	if digest(current) == digest(op.Before) {
		return nil
	}
	if op.Kind == "mailplus.domain" {
		return mpDeleteDomain(ctx, env, op)
	}
	if digest(current) != digest(op.After) && !(op.Kind == "mailplus.delivery" && isPartial(current, op)) {
		return ErrStale
	}
	if op.Kind == "mailplus.delivery" {
		// Turn off the new route before removing only its created row.
		if e = mpWrite(ctx, env, "SYNO.MailPlusServer.SMTP.Delivery", "set_type", 3, map[string]any{"host_type": "none", "enable_fallback_relay": false}); e != nil {
			return e
		}
		return afterSent(mpWrite(ctx, env, "SYNO.MailPlusServer.SMTP.Delivery", "set_multiple", 3, map[string]any{"list_type": "default", "host_list": []any{}}))
	}
	return mpSet(ctx, env, op, op.Before)
}
func mpSet(ctx context.Context, env core.Env, op mpOperation, value json.RawMessage) error {
	var params map[string]any
	if json.Unmarshal(value, &params) != nil {
		return ErrUnsafePlanCheck
	}
	switch op.Kind {
	case "mailplus.smtp":
		return mpWrite(ctx, env, "SYNO.MailPlusServer.Service.SMTP", "set", 1, params)
	case "mailplus.dkim.disable":
		params["domain_id"] = op.DomainID
		return mpWrite(ctx, env, "SYNO.MailPlusServer.Domain", "set_security", 2, params)
	}
	return ErrUnsafePlanCheck
}
func mpDeliveryCurrent(ctx context.Context, env core.Env, op mpOperation) (json.RawMessage, error) {
	typ, e := mpRead(ctx, env, "SYNO.MailPlusServer.SMTP.Delivery", "get_type", 3, map[string]any{})
	if e != nil {
		return nil, e
	}
	hosts, e := mpRead(ctx, env, "SYNO.MailPlusServer.SMTP.Delivery", "get_multiple", 3, map[string]any{"list_type": "default"})
	if e != nil {
		return nil, e
	}
	var t struct {
		Type     string `json:"host_type"`
		Fallback *bool  `json:"enable_fallback_relay"`
	}
	var h struct {
		Hosts *[]struct {
			Server string `json:"server"`
			Port   int    `json:"port"`
			TLS    bool   `json:"security_connection"`
			Auth   bool   `json:"enable_auth"`
			Name   string `json:"auth_name"`
		} `json:"host_list"`
	}
	if json.Unmarshal(typ, &t) != nil || json.Unmarshal(hosts, &h) != nil || t.Fallback == nil || h.Hosts == nil {
		return nil, ErrUnsafeReply
	}
	if t.Type == "none" && !*t.Fallback && len(*h.Hosts) == 0 {
		return op.Before, nil
	}
	if len(*h.Hosts) == 1 && !*t.Fallback {
		v := (*h.Hosts)[0]
		host, port, _ := net.SplitHostPort(op.Relay.Listen)
		name, e := env.Secrets.Get(ctx, op.Relay.UsernameRef)
		if e != nil {
			return nil, ErrUnavailable
		}
		if v.Server == host && strconv.Itoa(v.Port) == port && v.TLS && v.Auth && v.Name == name {
			if t.Type == "list" {
				return op.After, nil
			}
			// A set_multiple reply was lost before activation or rollback was interrupted;
			// preserve a distinguishable partial state for explicit reconciliation.
			if t.Type == "none" {
				return json.Marshal(map[string]string{"partial": digest(op.After)})
			}
		}
	}
	return nil, ErrStale
}
func mpSetDelivery(ctx context.Context, env core.Env, op mpOperation) error {
	confidential, ok := env.DSM.(ConfidentialDSM)
	if !ok {
		return ErrUnavailable
	}
	username, e := env.Secrets.Get(ctx, op.Relay.UsernameRef)
	if e != nil || username == "" {
		return ErrUnavailable
	}
	password, e := env.Secrets.Get(ctx, op.Relay.PasswordRef)
	if e != nil || password == "" {
		return ErrUnavailable
	}
	host, port, _ := net.SplitHostPort(op.Relay.Listen)
	n, _ := strconv.Atoi(port)
	// Like every MailPlus write, the reply carries no data (see mpWrite).
	if e = confidential.CallConfidential(ctx, "SYNO.MailPlusServer.SMTP.Delivery", "set_multiple", 3, map[string]any{"list_type": "default", "host_list": []any{map[string]any{"server": host, "port": n, "security_connection": true, "enable_auth": true, "auth_name": username, "auth_password": password}}}, nil); e != nil {
		return publicError(e)
	}
	return afterSent(mpWrite(ctx, env, "SYNO.MailPlusServer.SMTP.Delivery", "set_type", 3, map[string]any{"host_type": "list"}))
}

// afterSent classifies a later write of one change whose earlier write went
// out: if it never started, the change is still partly applied, so it is
// not "not started" (the next apply or rollback reconciles it).
func afterSent(err error) error {
	if errors.Is(err, ErrNotStarted) {
		return fmt.Errorf("partly applied: %w", ErrUnavailable)
	}
	return err
}

func isPartial(current json.RawMessage, op mpOperation) bool {
	var v map[string]string
	return json.Unmarshal(current, &v) == nil && v["partial"] == digest(op.After)
}
