package detect

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"SynoMailPlusSetupAssistant/internal/core"

	sdkapi "github.com/synopackageland/syno-pkg-land-sdk/api"
)

var errResponse = errors.New("probe_unavailable")

// Fixed causes of facts that are not DSM reads.
const (
	// CauseUnsupported: MailPlus Server does not offer the API version read.
	CauseUnsupported = "api_unsupported"
	// CauseNotChecked: this version has no source for the fact (address
	// type, tunnel, inbound probe): unknown by design, not a failure.
	CauseNotChecked = "not_checked"
	// CauseNoDomain: DNS says the domain does not exist (no lookup of it
	// returned records).
	CauseNoDomain = "dns_no_domain"
	// CauseNotInMailPlus: MailPlus Server's domain list was read and does not
	// have the domain, so its accounts and DKIM signing were not read.
	CauseNotInMailPlus = "mailplus_no_domain"
	// CauseDNSUnknown: a DNS lookup gave no usable answer.
	CauseDNSUnknown = "dns_unknown"
	// CauseIPUnknown: the public IP is unknown, so facts about it (reverse
	// DNS, its forward match, blocklists) were not checked.
	CauseIPUnknown = "ip_unknown"
	// CausePTRNone: the IP has no reverse DNS name.
	CausePTRNone = "ptr_none"
	// CauseIncomplete: a DSM reply lacks a field the fact needs.
	CauseIncomplete = "reply_incomplete"
	// CauseBadResponse: a DSM reply could not be read (core.ErrDSMBadResponse,
	// or a failure without an error code).
	CauseBadResponse = "dsm_bad_response"
	// CauseTooManyAccounts: the domain has more accounts than this app reads
	// (1000), so whether an active account exists is unknown.
	CauseTooManyAccounts = "accounts_too_many"
	// causeExecutor prefixes an executor refusal code (executor_<CODE>).
	causeExecutor = "executor_"
)

// dsmCause is core.Cause for a DSM read, telling apart what core reports as
// unavailable: an unreadable reply, a failure without a code, and an
// executor refusal (its fixed protocol code, never its message).
func dsmCause(err error) string {
	c := core.Cause(err)
	if c != core.CauseUnavailable {
		return c
	}
	var dsm core.DSMError
	var refusal *sdkapi.Error
	switch {
	case errors.Is(err, core.ErrDSMBadResponse), errors.As(err, &dsm):
		return CauseBadResponse
	case errors.As(err, &refusal) && refusalCode(refusal.Code):
		return causeExecutor + refusal.Code
	}
	return c
}

// executorCauses maps an executor refusal code (SDK protocol v1
// spec/protocol/v1/errors.json) to the catalog key that says what happened and
// what the user can do. Any other code gets mail.setup.cause.executor.
var executorCauses = map[string]string{
	// The approved access does not cover this read: approve again in Settings.
	"POLICY_DENIED":        "mail.setup.cause.executorApproval",
	"UNKNOWN_OP":           "mail.setup.cause.executorApproval",
	"DELEGATION_DENIED":    "mail.setup.cause.executorApproval",
	"SCOPE_DENIED":         "mail.setup.cause.executorApproval",
	"SCOPE_APPROVAL_STALE": "mail.setup.cause.executorApproval",
	"IDENTITY_CHANGED":     "mail.setup.cause.executorApproval",
	// The DSM sign-in is missing or expired.
	"AUTH_DENIED": "mail.setup.cause.dsmSession",
	// This DSM account may not do it.
	"ADMIN_REQUIRED":    "mail.setup.cause.dsmPermission",
	"APP_DENIED":        "mail.setup.cause.dsmPermission",
	"INELIGIBLE":        "mail.setup.cause.dsmPermission",
	"PERMISSION_DENIED": "mail.setup.cause.dsmPermission",
	// The App is starting, pausing or busy: wait, then check again.
	"EXECUTOR_PAUSED":      "mail.setup.cause.executorBusy",
	"EXECUTOR_STARTING":    "mail.setup.cause.executorBusy",
	"EXECUTOR_UNAVAILABLE": "mail.setup.cause.executorBusy",
	"APP_STARTING":         "mail.setup.cause.executorBusy",
	"ROOT_BUSY":            "mail.setup.cause.executorBusy",
	// The App is stopped.
	"APP_STOPPED": "mail.setup.cause.executorStopped",
	// A request or reply over its size limit.
	"REQUEST_TOO_LARGE":      core.CauseTooLarge,
	"EXECUTOR_TOO_LARGE":     core.CauseTooLarge,
	"WEBAPI_REPLY_TOO_LARGE": core.CauseTooLarge,
}

// ExecutorCauseKey is the catalog key for an executor refusal code; one
// generic key for a code it does not know. The key never contains the code.
func ExecutorCauseKey(code string) string {
	key, ok := executorCauses[code]
	switch {
	case !ok:
		return "mail.setup.cause.executor"
	case key == core.CauseTooLarge:
		return "mail.setup.cause.tooLarge"
	}
	return key
}

// IsExecutorCause: exactly "executor_" and a protocol code (a raw cause that
// must reach the page as its catalog key, never as text).
func IsExecutorCause(s string) bool {
	code, ok := strings.CutPrefix(s, causeExecutor)
	return ok && refusalCode(code)
}

// refusalCode admits protocol codes only (A-Z, 0-9, _; at most 40 bytes).
func refusalCode(code string) bool {
	if code == "" || len(code) > 40 {
		return false
	}
	for _, r := range code {
		if !(r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_') {
			return false
		}
	}
	return true
}

// DSMPassBudget bounds one whole MailPlus read pass. core gives each call its
// full DSMReadTimeout once it holds one of the executor's two slots, and never
// starts a call with less left. The pass shares two slots (lanes), and its
// dependent chain holds one of them from its first read to its last:
//
//   - the chain takes its slot before the pass's first read, when no other
//     read of the pass exists, so it never waits: package list → API info
//     (the gate) → domain list → ten account pages (1000 accounts at 100 per
//     page) is 13 calls in a row;
//   - the other reads (SMTP, four delivery reads, queue, two licence reads
//     and the domain's DKIM read: 9 calls) start after the gate and always
//     have the second slot, so they end by 2 + 9 = 11, and use both slots
//     once the chain is done.
//
// The diagnosis snapshot (no accounts) holds the slot only through the
// domain list: after it, eighteen independent reads at most (ten DKIM reads,
// eight others, one already done beside the list) share both slots, ending
// by 3 + 9 = 12. So the pass needs at most 13 full budgets, and fourteen fit
// with one to spare even when every call needs all of its time and every read
// competes for a slot. A plain shared queue did not: each account page
// re-queued behind the other reads (up to 2 + 4.5 + 11 = 18 units). Waiting
// for slots held by other callers (core.DSMSlotWait) comes out of the same
// pass budget.
const DSMPassBudget = 14 * core.DSMReadTimeout

// lanes keeps a pass to two concurrent reads, as the executor admits.
type lanes struct {
	core.DSM
	slots chan struct{}
}

func (l *lanes) Call(ctx context.Context, api, method string, version int, params map[string]any, out any) error {
	select {
	case l.slots <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-l.slots }()
	return l.DSM.Call(ctx, api, method, version, params, out)
}

// hold takes one slot for a chain of reads made one after another on the
// returned DSM, until release (safe to call more than once). Take it before
// any other read of the pass is queued, so it is free at once.
func (l *lanes) hold() (chain core.DSM, release func()) {
	l.slots <- struct{}{}
	var once sync.Once
	return l.DSM, func() { once.Do(func() { <-l.slots }) }
}

// read makes one DSM call bounded by ctx; a failure keeps its fixed cause.
func read[T any](ctx context.Context, dsm core.DSM, api, method string, version int, params map[string]any) Observation[T] {
	return boundedCause(ctx, 0, func(c context.Context) (T, error) {
		var v T
		e := dsm.Call(c, api, method, version, params, &v)
		return v, e
	}, dsmCause)
}

func unknown[T any](cause string) Observation[T] {
	if cause == "" {
		cause = core.CauseUnavailable
	}
	return Observation[T]{Status: Unknown, Detail: cause}
}

func (d *Detector) dsmBudget() time.Duration {
	if d.DSMBudget > 0 {
		return d.DSMBudget
	}
	return DSMPassBudget
}

// ReadMailPlus reads only MailPlus Server through DSM: the package, SMTP,
// every configured domain's DKIM (at most ten domains), delivery and queue.
// It reads no accounts and runs no network probes (diagnosis snapshot).
func (d *Detector) ReadMailPlus(ctx context.Context, env core.Env) State {
	s := emptyState("")
	if env.DSM != nil {
		d.mailplus(ctx, env.DSM, &s, nil, false)
	}
	return s
}

// ReadAccounts reads one domain's MailPlus accounts (and the facts the same
// pass reads) for the Overview's mailbox sync: the package, the API
// versions, the domain list and that domain's users, with the detection's
// limits. Accounts[domain] stays unknown unless every page was read.
func (d *Detector) ReadAccounts(ctx context.Context, env core.Env, domain string) State {
	domain = NormalizeDomain(domain)
	s := emptyState(domain)
	s.Accounts[domain] = unknown[[]Account](core.CauseUnavailable)
	if env.DSM != nil && validDomain(domain) {
		d.mailplus(ctx, env.DSM, &s, []string{domain}, true)
	}
	return s
}

// mailplus fills the DSM facts. domains selects the domains whose accounts
// and DKIM are read (nil: every configured domain, at most ten). Reads that do
// not depend on each other run concurrently; core keeps the executor's limit.
func (d *Detector) mailplus(ctx context.Context, dsm core.DSM, s *State, domains []string, accounts bool) {
	ctx, cancel := context.WithTimeout(ctx, d.dsmBudget())
	defer cancel()
	// At most two reads at a time, as the executor admits: the pass queues
	// its own reads here (bounded by the pass), so core's slot wait only
	// ever covers other callers. The chain holds one slot (DSMPassBudget).
	side := &lanes{DSM: dsm, slots: make(chan struct{}, core.DSMSlots)}
	chain, release := side.hold()
	defer release()
	// unread gives every fact not yet read the cause of the gate that failed.
	unread := func(cause string) {
		s.SMTP, s.Domains, s.Delivery, s.QueueSize = unknown[SMTP](cause), unknown[[]Domain](cause), unknown[Delivery](cause), unknown[int](cause)
		s.License = unknown[License](cause)
		for _, name := range domains {
			s.Accounts[name] = unknown[[]Account](cause)
			s.Signing[name] = unknown[Signing](cause)
		}
	}
	s.Package = ReadPackage(ctx, chain)
	if !s.Package.IsKnown() {
		unread(s.Package.Detail)
		return
	}
	if !s.Package.Value.Installed || !s.Package.Value.Running || s.Package.Value.Broken {
		return
	}
	type version struct {
		Min int `json:"minVersion"`
		Max int `json:"maxVersion"`
	}
	info := read[map[string]version](ctx, chain, "SYNO.API.Info", "query", 1, map[string]any{"query": "SYNO.MailPlusServer."})
	if !info.IsKnown() {
		unread(info.Detail)
		return
	}
	supports := func(api string, v int) bool {
		a, ok := info.Value[api]
		return ok && a.Min <= v && a.Max >= v
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	set := func(f func()) { mu.Lock(); f(); mu.Unlock() }
	run := func(f func()) { wg.Add(1); go func() { defer wg.Done(); f() }() }

	run(func() {
		if !supports("SYNO.MailPlusServer.Service.SMTP", 1) {
			set(func() { s.SMTP = unknown[SMTP](CauseUnsupported) })
			return
		}
		v := read[struct {
			Enabled *bool `json:"enable_smtp"`
			Port    *int  `json:"smtp_port"`
		}](ctx, side, "SYNO.MailPlusServer.Service.SMTP", "get", 1, map[string]any{})
		set(func() {
			switch {
			case !v.IsKnown():
				s.SMTP = unknown[SMTP](v.Detail)
			case v.Value.Enabled == nil || v.Value.Port == nil:
				s.SMTP = unknown[SMTP](core.CauseUnavailable)
			default:
				s.SMTP = Fact(SMTP{Enabled: *v.Value.Enabled, Port: *v.Value.Port})
			}
		})
	})
	run(func() { d.domains(ctx, chain, release, side, s, domains, accounts, supports, set, run) })
	run(func() { d.delivery(ctx, side, s, supports, set) })
	run(func() {
		l := d.license(ctx, side, supports)
		set(func() { s.License = l })
	})
	run(func() {
		if !supports("SYNO.MailPlusServer.Queue", 1) {
			set(func() { s.QueueSize = unknown[int](CauseUnsupported) })
			return
		}
		v := read[struct {
			Total *int `json:"total"`
		}](ctx, side, "SYNO.MailPlusServer.Queue", "list", 1, map[string]any{"offset": 0, "limit": 1})
		set(func() {
			switch {
			case !v.IsKnown():
				s.QueueSize = unknown[int](v.Detail)
			case v.Value.Total == nil || *v.Value.Total < 0:
				s.QueueSize = unknown[int](core.CauseUnavailable)
			default:
				s.QueueSize = Fact(*v.Value.Total)
			}
		})
	})
	wg.Wait()
}

// domains reads the domain list and then the selected domains' accounts, one
// call after another on the held chain slot, and releases it; the DKIM reads
// go through the shared lanes (side). Detect reads one domain's accounts;
// more would page one after another and could run out of pass.
func (d *Detector) domains(ctx context.Context, chain core.DSM, release func(), side core.DSM, s *State, selected []string, accounts bool, supports func(string, int) bool, set func(func()), run func(func())) {
	released := false
	defer func() {
		if !released {
			release()
		}
	}()
	if !supports("SYNO.MailPlusServer.Domain", 1) {
		set(func() {
			s.Domains = unknown[[]Domain](CauseUnsupported)
			for _, name := range selected {
				s.Accounts[name] = unknown[[]Account](CauseUnsupported)
				s.Signing[name] = unknown[Signing](CauseUnsupported)
			}
		})
		return
	}
	type domain struct {
		ID      *int   `json:"domain_id"`
		Name    string `json:"name"`
		Primary bool   `json:"is_primary"`
		Users   int    `json:"user_num"`
	}
	v := read[struct {
		Domains *[]domain `json:"domains"`
	}](ctx, chain, "SYNO.MailPlusServer.Domain", "list", 1, map[string]any{"offset": 0, "limit": -1})
	cause := v.Detail
	var ds []Domain
	if v.IsKnown() {
		cause = core.CauseUnavailable
		if v.Value.Domains != nil && len(*v.Value.Domains) <= 100 {
			ds = []Domain{}
			for _, v := range *v.Value.Domains {
				if v.ID == nil || !ValidDomain(NormalizeDomain(v.Name)) {
					ds = nil
					break
				}
				ds = append(ds, Domain{ID: *v.ID, Name: NormalizeDomain(v.Name), Primary: v.Primary, Users: v.Users})
			}
		}
	}
	if ds == nil {
		set(func() {
			s.Domains = unknown[[]Domain](cause)
			for _, name := range selected {
				s.Accounts[name] = unknown[[]Account](cause)
				s.Signing[name] = unknown[Signing](cause)
			}
		})
		return
	}
	set(func() { s.Domains = Fact(ds) })
	if !accounts {
		release()
	}
	picked := 0
	picks := []Domain{}
	for _, dm := range ds {
		wanted := selected == nil && picked < 10
		for _, name := range selected {
			wanted = wanted || name == dm.Name
		}
		if !wanted {
			continue
		}
		picked++
		dm := dm
		picks = append(picks, dm)
		run(func() {
			sign := unknown[Signing](CauseUnsupported)
			if supports("SYNO.MailPlusServer.Domain", 2) {
				v := read[struct {
					Enabled   *bool  `json:"enable_dkim_sign"`
					Selector  string `json:"dkim_selector"`
					PublicKey string `json:"dkim_public_key"`
				}](ctx, side, "SYNO.MailPlusServer.Domain", "get_security", 2, map[string]any{"domain_id": dm.ID})
				switch {
				case !v.IsKnown():
					sign = unknown[Signing](v.Detail)
				case v.Value.Enabled == nil:
					sign = unknown[Signing](CauseIncomplete)
				default:
					sign = Fact(Signing{Enabled: *v.Value.Enabled, Selector: v.Value.Selector, PublicKey: v.Value.PublicKey})
				}
			}
			set(func() { s.Signing[dm.Name] = sign })
		})
	}
	if accounts {
		released = true
		run(func() {
			defer release()
			for _, dm := range picks {
				a := d.accounts(ctx, chain, dm, supports)
				set(func() { s.Accounts[dm.Name] = a })
			}
		})
	}
}

// accounts pages through one domain's members (at most 1000, 100 per call).
func (d *Detector) accounts(ctx context.Context, dsm core.DSM, dm Domain, supports func(string, int) bool) Observation[[]Account] {
	if !supports("SYNO.MailPlusServer.Domain.User", 1) {
		return unknown[[]Account](CauseUnsupported)
	}
	out := []Account{}
	for offset := 0; offset < 1000; {
		var page struct {
			Users *[]struct {
				ID      *int   `json:"id"`
				Name    string `json:"name"`
				Active  *bool  `json:"is_activated"`
				Aliases []struct {
					Alias string `json:"alias"`
				} `json:"aliases"`
			} `json:"users"`
			Total *int `json:"total"`
		}
		obs := boundedCause(ctx, 0, func(c context.Context) (struct{}, error) {
			return struct{}{}, dsm.Call(c, "SYNO.MailPlusServer.Domain.User", "list", 1, map[string]any{"domain_id": dm.ID, "offset": offset, "limit": 100, "query": ""}, &page)
		}, dsmCause)
		if !obs.IsKnown() {
			return unknown[[]Account](obs.Detail)
		}
		if page.Users == nil || page.Total == nil {
			return unknown[[]Account](CauseIncomplete)
		}
		if *page.Total > 1000 {
			return unknown[[]Account](CauseTooManyAccounts)
		}
		for _, u := range *page.Users {
			if u.ID == nil || u.Active == nil {
				return unknown[[]Account](CauseIncomplete)
			}
			a := Account{ID: *u.ID, Name: u.Name, Active: *u.Active, Addresses: []string{}}
			for _, alias := range u.Aliases {
				a.Addresses = append(a.Addresses, alias.Alias+"@"+dm.Name)
			}
			out = append(out, a)
		}
		offset += len(*page.Users)
		if offset >= *page.Total {
			return Fact(out)
		}
		if len(*page.Users) == 0 {
			return unknown[[]Account](core.CauseUnavailable)
		}
	}
	return unknown[[]Account](core.CauseUnavailable)
}

// license reads MailPlus Server's own licence counts: the user limit (free
// and added licences) and the number of MailPlus users it counts as active,
// across every domain. Replies verified on a test NAS (MailPlus Server
// 4.1.1-31785): get_user_limit v1 {"limit":5}, get_active_user_num v1
// {"total":4}; versions 2 and 3 of both answer 103. Both are needed: a missing
// or negative field, or either read failing, leaves the fact unknown. The two
// reads take the side lane beside the domain chain.
func (d *Detector) license(ctx context.Context, dsm core.DSM, supports func(string, int) bool) Observation[License] {
	if !supports("SYNO.MailPlusServer.License", 1) {
		return unknown[License](CauseUnsupported)
	}
	var limit Observation[struct {
		Limit *int `json:"limit"`
	}]
	var active Observation[struct {
		Total *int `json:"total"`
	}]
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		limit = read[struct {
			Limit *int `json:"limit"`
		}](ctx, dsm, "SYNO.MailPlusServer.License", "get_user_limit", 1, map[string]any{})
	}()
	go func() {
		defer wg.Done()
		active = read[struct {
			Total *int `json:"total"`
		}](ctx, dsm, "SYNO.MailPlusServer.License", "get_active_user_num", 1, map[string]any{})
	}()
	wg.Wait()
	switch {
	case !limit.IsKnown():
		return unknown[License](limit.Detail)
	case !active.IsKnown():
		return unknown[License](active.Detail)
	case limit.Value.Limit == nil || active.Value.Total == nil || *limit.Value.Limit < 0 || *active.Value.Total < 0:
		return unknown[License](core.CauseUnavailable)
	}
	return Fact(License{Licensed: *limit.Value.Limit, Active: *active.Value.Total})
}

// LicenseShort reports a licence shortfall: MailPlus Server counts more
// active users than it has licences. Only the License API's own two counts
// decide it (never this assistant's account list); an unknown licence is
// never a shortfall.
func LicenseShort(l Observation[License]) bool {
	return l.IsKnown() && l.Value.Active > l.Value.Licensed
}

// delivery reads the delivery type and its three host lists concurrently.
func (d *Detector) delivery(ctx context.Context, dsm core.DSM, s *State, supports func(string, int) bool, set func(func())) {
	if !supports("SYNO.MailPlusServer.SMTP.Delivery", 3) {
		set(func() { s.Delivery = unknown[Delivery](CauseUnsupported) })
		return
	}
	type host struct {
		ID     *int   `json:"id"`
		Server string `json:"server"`
		Port   *int   `json:"port"`
		TLS    *bool  `json:"security_connection"`
		Auth   *bool  `json:"enable_auth"`
	}
	type hosts = Observation[struct {
		Hosts *[]host `json:"host_list"`
	}]
	var typ Observation[struct {
		Type     string `json:"host_type"`
		Fallback *bool  `json:"enable_fallback_relay"`
	}]
	lists := []string{"default", "sender", "recipient"}
	got := make([]hosts, len(lists))
	var wg sync.WaitGroup
	wg.Add(1 + len(lists))
	go func() {
		defer wg.Done()
		typ = read[struct {
			Type     string `json:"host_type"`
			Fallback *bool  `json:"enable_fallback_relay"`
		}](ctx, dsm, "SYNO.MailPlusServer.SMTP.Delivery", "get_type", 3, map[string]any{})
	}()
	for i, list := range lists {
		go func() {
			defer wg.Done()
			got[i] = read[struct {
				Hosts *[]host `json:"host_list"`
			}](ctx, dsm, "SYNO.MailPlusServer.SMTP.Delivery", "get_multiple", 3, map[string]any{"list_type": list})
		}()
	}
	wg.Wait()
	if !typ.IsKnown() {
		set(func() { s.Delivery = unknown[Delivery](typ.Detail) })
		return
	}
	delivery := Delivery{Type: typ.Value.Type}
	if typ.Value.Fallback != nil {
		delivery.Fallback = *typ.Value.Fallback
	}
	cause := ""
	if !(delivery.Type == "none" || delivery.Type == "list") || typ.Value.Fallback == nil {
		cause = core.CauseUnavailable
	}
	for i, list := range lists {
		v := got[i]
		if !v.IsKnown() {
			if cause == "" {
				cause = v.Detail
			}
			continue
		}
		if v.Value.Hosts == nil {
			cause = core.CauseUnavailable
			continue
		}
		hs := []RelayHost{}
		for _, h := range *v.Value.Hosts {
			if h.ID == nil || h.Port == nil || h.TLS == nil || h.Auth == nil {
				cause = core.CauseUnavailable
				continue
			}
			hs = append(hs, RelayHost{ID: *h.ID, Server: h.Server, Port: *h.Port, STARTTLS: *h.TLS, Auth: *h.Auth})
		}
		switch list {
		case "default":
			delivery.Default = hs
		case "sender":
			delivery.Sender = hs
		case "recipient":
			delivery.Recipient = hs
		}
	}
	set(func() {
		if cause != "" {
			s.Delivery = unknown[Delivery](cause)
		} else {
			s.Delivery = Fact(delivery)
		}
	})
}

func (o Observation[T]) cause() (bool, string) { return o.IsKnown(), o.Detail }

// CauseKey maps a fixed cause to its catalog key and parameters:
// mail.setup.cause.{timeout,authority,dsm,tooLarge,accountsTooLarge,unsupported,notChecked,
// noDomain,notInMailPlus,dnsUnknown,ipUnknown,ptrNone,incomplete,badResponse,
// executor,mailplusNotInstalled,mailplusStopped,mailplusApiMissing,unavailable}.
// A DSM error (dsm_<code>) keeps its code in params for the log and the
// folded evidence only: the catalog text never shows it.
func CauseKey(detail string) (string, map[string]string) {
	switch detail {
	case CauseNotChecked:
		return "mail.setup.cause.notChecked", nil
	case CauseNoDomain:
		return "mail.setup.cause.noDomain", nil
	case CauseNotInMailPlus:
		return "mail.setup.cause.notInMailPlus", nil
	case CauseDNSUnknown:
		return "mail.setup.cause.dnsUnknown", nil
	case CauseIPUnknown:
		return "mail.setup.cause.ipUnknown", nil
	case CausePTRNone:
		return "mail.setup.cause.ptrNone", nil
	case core.CauseTimeout:
		return "mail.setup.cause.timeout", nil
	case CauseNotStarted:
		return "mail.setup.cause.notStarted", nil
	case core.CauseAuthority:
		return "mail.setup.cause.authority", nil
	case core.CauseTooLarge:
		return "mail.setup.cause.tooLarge", nil
	case CauseTooManyAccounts:
		return "mail.setup.cause.accountsTooLarge", nil
	case CauseUnsupported:
		return "mail.setup.cause.unsupported", nil
	case CauseIncomplete:
		return "mail.setup.cause.incomplete", nil
	case CauseBadResponse:
		return "mail.setup.cause.badResponse", nil
	case CauseMailPlusNotInstalled:
		return "mail.setup.cause.mailplusNotInstalled", nil
	case CauseMailPlusNotRunning:
		return "mail.setup.cause.mailplusStopped", nil
	case CauseMailPlusAPIMissing:
		return "mail.setup.cause.mailplusApiMissing", nil
	}
	if code, ok := strings.CutPrefix(detail, causeExecutor); ok && refusalCode(code) {
		// The code stays in the log; the page gets plain words only.
		return ExecutorCauseKey(code), nil
	}
	var code int
	if n, err := fmt.Sscanf(detail, "dsm_%d", &code); err == nil && n == 1 && fmt.Sprintf("dsm_%d", code) == detail {
		switch code {
		case 102: // the API does not exist: MailPlus Server stopped or is updating
			return "mail.setup.cause.mailplusApiMissing", nil
		case 105: // permission denied
			return "mail.setup.cause.dsmPermission", nil
		case 106, 107, 119: // the DSM session timed out, was replaced or is invalid
			return "mail.setup.cause.dsmSession", nil
		}
		// The code stays in params (and the log); the text never shows it.
		return "mail.setup.cause.dsm", map[string]string{"code": fmt.Sprint(code)}
	}
	return "mail.setup.cause.unavailable", nil
}
