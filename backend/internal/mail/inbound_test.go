package mail

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"SynoMailPlusSetupAssistant/internal/core"
	"SynoMailPlusSetupAssistant/internal/mail/cloudflare"
	"SynoMailPlusSetupAssistant/internal/mail/detect"
	"SynoMailPlusSetupAssistant/internal/mail/setup"
)

const (
	connectTunnel = "11111111-2222-4333-8444-555555555555"
	otherTunnel   = "66666666-7777-4888-8999-aaaaaaaaaaaa"
)

// inboundCloud is a stateful loopback Cloudflare for the inbound path.
type inboundCloud struct {
	// token is the credential Cloudflare accepts ("" means fixture-value);
	// revoked answers every call with 401 code 1000, as Cloudflare does for
	// a token deleted in its dashboard.
	token    string
	revoked  bool
	zoneName string
	routing  cloudflare.RoutingDomain
	records  []cloudflare.DNSRecord
	rules    []cloudflare.RoutingRule
	// catchAll is the zone's catch-all (nil: Cloudflare's default, disabled
	// with the drop action); catchAllPuts counts its updates.
	catchAll     *cloudflare.RoutingRule
	catchAllPuts int
	tunnels      []cloudflare.Tunnel
	origins      map[string][]string
	services     []cloudflare.VPCService
	workers      []cloudflare.Worker
	workerPuts   int
	puts         int
	enables      []string
	disables     int
	creates      map[string]int
	sent         []map[string]any
	// onSend is called with the Message-ID of a sent check mail.
	onSend func(id, subject string)
	// fail answers a method+path with an HTTP status and Cloudflare code.
	fail map[string][2]int
	// requests is every method and path asked, in order.
	requests []string
	// lockedDNS refuses deleting Email Routing's records (code 1046).
	lockedDNS bool
	// unlocks is every name PATCH /email/routing/dns was asked to unlock;
	// unlockReply, when set, is the name its reply gives instead.
	unlocks     []string
	unlockReply string
	dnsDeletes  []string
	dnsPuts     []string
	nextID      int
}

func (f *inboundCloud) hasRoutingMX(name string) bool {
	for _, r := range f.records {
		if r.Name == name && r.Type == "MX" && r.Meta.EmailRouting {
			return true
		}
	}
	return false
}

func (f *inboundCloud) hasRoutingSPF(name string) bool {
	for _, r := range f.records {
		if r.Name == name && r.Type == "TXT" && cloudflare.RoutingRecord(r) {
			return true
		}
	}
	return false
}

func newInboundCloud() *inboundCloud {
	return &inboundCloud{zoneName: "example.test", creates: map[string]int{},
		routing: cloudflare.RoutingDomain{Name: "example.test", Enabled: true},
		tunnels: []cloudflare.Tunnel{{ID: connectTunnel, Name: "synopkgconnect-nas-1a2b3c4d", Status: "healthy"},
			{ID: otherTunnel, Name: "office", Status: "healthy"}},
		origins: map[string][]string{connectTunnel: {"203.0.113.7", "203.0.113.7"}, otherTunnel: {"198.51.100.9"}}}
}

func (f *inboundCloud) Do(req *http.Request) (*http.Response, error) {
	want := "fixture-value"
	if f.token != "" {
		want = f.token
	}
	p := strings.TrimPrefix(req.URL.Path, "/client/v4")
	zone, acct := "/zones/"+testZone, "/accounts/"+testAccount
	if f.revoked {
		f.requests = append(f.requests, req.Method+" "+p)
		raw, _ := json.Marshal(map[string]any{"success": false, "errors": []map[string]any{{"code": 1000, "message": "Invalid API Token"}}})
		return &http.Response{StatusCode: 401, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(string(raw)))}, nil
	}
	if req.Header.Get("Authorization") != "Bearer "+want {
		return nil, errors.New("unexpected credential")
	}
	f.requests = append(f.requests, req.Method+" "+p)
	if f.fail != nil {
		if sc, ok := f.fail[req.Method+" "+p]; ok {
			raw, _ := json.Marshal(map[string]any{"success": false, "errors": []map[string]any{{"code": sc[1], "message": "refused"}}})
			return &http.Response{StatusCode: sc[0], Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(string(raw)))}, nil
		}
	}
	body := map[string]any{}
	if req.Body != nil && strings.HasPrefix(req.Header.Get("Content-Type"), "application/json") {
		_ = json.NewDecoder(req.Body).Decode(&body)
	}
	var result any
	status := 200
	switch {
	case p == "/user/tokens/verify" && req.Method == "GET":
		result = map[string]string{"id": "token", "status": "active"}
	case p == zone && req.Method == "GET":
		result = map[string]any{"id": testZone, "name": f.zoneName, "account": map[string]string{"id": testAccount}}
	case p == zone+"/dns_records" && req.Method == "GET":
		result = append([]cloudflare.DNSRecord{}, f.records...)
	case p == zone+"/email/routing" && req.Method == "GET":
		result = f.routing
	case p == zone+"/email/routing/dns" && req.Method == "GET":
		check := cloudflare.DNSCheck{}
		if sub := req.URL.Query().Get("subdomain"); sub != "" && !f.hasRoutingMX(sub) {
			check.Errors = []cloudflare.DNSCheckIssue{{Code: "mx.missing"}}
		} else if sub != "" && !f.hasRoutingSPF(sub) {
			check.Errors = []cloudflare.DNSCheckIssue{{Code: "spf.missing"}}
		}
		result = check
	case strings.HasPrefix(p, zone+"/dns_records/"):
		id := strings.TrimPrefix(p, zone+"/dns_records/")
		i := -1
		for j, r := range f.records {
			if r.ID == id {
				i = j
			}
		}
		if i < 0 {
			status, result = 404, nil
			break
		}
		switch req.Method {
		case "GET":
			result = f.records[i]
		case "DELETE":
			if f.lockedDNS && f.records[i].Meta.EmailRouting {
				raw, _ := json.Marshal(map[string]any{"success": false, "errors": []map[string]any{{"code": 1046, "message": "This record is managed by Email Routing"}}})
				return &http.Response{StatusCode: 400, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(string(raw)))}, nil
			}
			f.dnsDeletes = append(f.dnsDeletes, id)
			f.records = append(f.records[:i], f.records[i+1:]...)
			result = map[string]string{"id": id}
		case "PUT":
			f.dnsPuts = append(f.dnsPuts, id)
			raw, _ := json.Marshal(body)
			var fields cloudflare.DNSFields
			_ = json.Unmarshal(raw, &fields)
			f.records[i].DNSFields = fields
			result = f.records[i]
		}
	case p == zone+"/email/routing/dns" && req.Method == "PATCH":
		// Unlock (live 2026-11-25): with a subdomain's name only that
		// name's routing MX lose their lock.
		name, _ := body["name"].(string)
		f.unlocks = append(f.unlocks, name)
		for i := range f.records {
			if f.records[i].Name == name && f.records[i].Type == "MX" {
				f.records[i].Meta.EmailRouting, f.records[i].Meta.ReadOnly = false, false
			}
		}
		reply := name
		if f.unlockReply != "" {
			reply = f.unlockReply
		}
		result = cloudflare.RoutingDomain{Name: reply, Enabled: true, Status: "unlocked"}
	case p == zone+"/email/routing/dns" && req.Method == "DELETE":
		f.disables++
		f.routing.Enabled = false
		result = f.routing
	case p == zone+"/email/routing/dns" && req.Method == "POST":
		name, _ := body["name"].(string)
		f.enables = append(f.enables, name)
		sub := cloudflare.RoutingDomain{Name: name, Enabled: true, Status: "ready"}
		if name == f.zoneName {
			f.routing.Enabled = true
		} else {
			on := false
			for _, s := range f.routing.Subdomains {
				on = on || s.Name == name && s.Enabled
			}
			if !on {
				f.routing.Subdomains = append(f.routing.Subdomains, sub)
			}
			// Cloudflare adds the subdomain's receiving records,
			// those that are missing.
			if !f.hasRoutingMX(name) {
				for i, pr := range []int{50, 69, 41} {
					f.nextID++
					r := cloudflare.DNSRecord{ID: fmt.Sprintf("er%030d", f.nextID), DNSFields: cloudflare.DNSFields{Type: "MX", Name: name,
						Content: fmt.Sprintf("route%d.mx.cloudflare.net", i+1), TTL: 1, Priority: &pr}}
					r.Meta.EmailRouting, r.Meta.ReadOnly = true, true
					f.records = append(f.records, r)
				}
			}
			if !f.hasRoutingSPF(name) {
				f.nextID++
				f.records = append(f.records, cloudflare.DNSRecord{ID: fmt.Sprintf("er%030d", f.nextID),
					DNSFields: cloudflare.DNSFields{Type: "TXT", Name: name, Content: `"` + cloudflare.RoutingSPF + `"`, TTL: 1}})
			}
		}
		result = sub
	case p == zone+"/email/routing/rules" && req.Method == "GET":
		page, _ := strconv.Atoi(req.URL.Query().Get("page"))
		all := append([]cloudflare.RoutingRule{}, f.rules...)
		start := min(max(page-1, 0)*100, len(all))
		result = all[start:min(start+100, len(all))]
	case p == zone+"/email/routing/rules" && req.Method == "POST":
		raw, _ := json.Marshal(body)
		var rule cloudflare.RoutingRule
		_ = json.Unmarshal(raw, &rule)
		f.creates["rule"]++
		rule.ID = "rule" + strconv.Itoa(f.creates["rule"])
		f.rules = append(f.rules, rule)
		result = rule
	case p == zone+"/email/routing/rules/catch_all":
		if f.catchAll == nil {
			f.catchAll = &cloudflare.RoutingRule{ID: "catch", Matchers: []cloudflare.RoutingMatcher{{Type: "all"}},
				Actions: []cloudflare.RoutingAction{{Type: "drop"}}}
		}
		if req.Method == "PUT" {
			raw, _ := json.Marshal(body)
			var updated cloudflare.RoutingRule
			_ = json.Unmarshal(raw, &updated)
			updated.ID = f.catchAll.ID
			f.catchAll = &updated
			f.catchAllPuts++
		}
		result = *f.catchAll
	case strings.HasPrefix(p, zone+"/email/routing/rules/"):
		id := strings.TrimPrefix(p, zone+"/email/routing/rules/")
		for i, rule := range f.rules {
			if rule.ID == id {
				switch req.Method {
				case "DELETE":
					f.rules = append(f.rules[:i], f.rules[i+1:]...)
				case "PUT":
					raw, _ := json.Marshal(body)
					var updated cloudflare.RoutingRule
					_ = json.Unmarshal(raw, &updated)
					updated.ID = id
					f.rules[i] = updated
					f.puts++
					rule = updated
				}
				result = rule
				break
			}
		}
		if result == nil {
			status = 404
		}
	case p == acct+"/cfd_tunnel" && req.Method == "GET":
		result = f.tunnels
	case strings.HasPrefix(p, acct+"/cfd_tunnel/") && strings.HasSuffix(p, "/connections"):
		id := strings.TrimSuffix(strings.TrimPrefix(p, acct+"/cfd_tunnel/"), "/connections")
		conns := []map[string]string{}
		for _, ip := range f.origins[id] {
			conns = append(conns, map[string]string{"origin_ip": ip})
		}
		result = []map[string]any{{"id": "connector", "version": "2026.10.5", "conns": conns}}
	case p == acct+"/connectivity/directory/services" && req.Method == "GET":
		result = append([]cloudflare.VPCService{}, f.services...)
	case p == acct+"/connectivity/directory/services" && req.Method == "POST":
		raw, _ := json.Marshal(body)
		var service cloudflare.VPCService
		_ = json.Unmarshal(raw, &service)
		f.creates["vpc"]++
		service.ServiceID = "service" + strconv.Itoa(f.creates["vpc"])
		f.services = append(f.services, service)
		result = service
	case strings.HasPrefix(p, acct+"/connectivity/directory/services/"):
		id := strings.TrimPrefix(p, acct+"/connectivity/directory/services/")
		for i, s := range f.services {
			if s.ServiceID == id {
				if req.Method == "DELETE" {
					f.services = append(f.services[:i], f.services[i+1:]...)
				}
				result = s
			}
		}
		if result == nil {
			status = 404
		}
	case p == acct+"/workers/scripts" && req.Method == "GET":
		result = append([]cloudflare.Worker{}, f.workers...)
	case strings.HasPrefix(p, acct+"/workers/scripts/") && req.Method == "PUT":
		name := strings.TrimPrefix(p, acct+"/workers/scripts/")
		f.workerPuts++
		if len(f.workers) == 0 {
			f.workers = []cloudflare.Worker{{ID: name, Tags: []string{"syno-home-keeper:" + strings.TrimSuffix(strings.TrimPrefix(name, "syno-home-keeper-"), "-inbound")}}}
		}
		result = f.workers[0]
	case strings.HasPrefix(p, acct+"/workers/scripts/") && req.Method == "DELETE":
		f.workers = nil
		result = map[string]string{}
	case p == zone+"/email/sending/subdomains" && req.Method == "GET":
		result = []any{} // the replacement token's Email Sending read
	case p == acct+"/email/sending/send" && req.Method == "POST":
		f.sent = append(f.sent, body)
		id := "<check-" + strconv.Itoa(len(f.sent)) + "@example.test>"
		if f.onSend != nil {
			f.onSend(id, body["subject"].(string))
		}
		result = map[string]string{"message_id": id}
	default:
		return nil, errors.New("unexpected fixture request " + req.Method + " " + p)
	}
	raw, _ := json.Marshal(map[string]any{"success": status < 300, "result": result, "errors": []any{}})
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(string(raw)))}, nil
}

// inboundDSM answers the two DSM reads of the inbound path.
type inboundDSM struct {
	gatewayIP, gatewayStatus string
	log                      []map[string]any
	migrating                bool
	calls                    []string
	relayNetworks            int  // configured MailPlus relay client networks
	relayUnreadable          bool // RelayControl read fails
}

func (d *inboundDSM) Call(_ context.Context, api, method string, version int, params map[string]any, out any) error {
	d.calls = append(d.calls, api+" "+method+" "+strconv.Itoa(version))
	var v any
	switch api + " " + method {
	case "SYNO.Core.Network get":
		v = map[string]any{"gateway_info": map[string]string{"ip": d.gatewayIP, "status": d.gatewayStatus}}
	case "SYNO.MailPlusServer.Audit.TransactionLog list":
		// Newest first, paged by offset/limit like MailPlus.
		items := append([]map[string]any{}, d.log...)
		sort.SliceStable(items, func(i, j int) bool { return items[i]["timestamp"].(int) > items[j]["timestamp"].(int) })
		offset, limit := params["offset"].(int), params["limit"].(int)
		start := min(offset, len(items))
		v = map[string]any{"is_migrating": d.migrating, "items": items[start:min(start+limit, len(items))], "total": len(items)}
	case "SYNO.MailPlusServer.SMTP.RelayControl get":
		if d.relayUnreadable || params["list_type"] != "network" {
			return errors.New("refused")
		}
		list := []map[string]string{}
		for i := 0; i < d.relayNetworks; i++ {
			list = append(list, map[string]string{"network": "192.168.1.0/24"})
		}
		v = map[string]any{"client_list": list, "total": d.relayNetworks}
	default:
		return errors.New("unexpected DSM call " + api)
	}
	raw, _ := json.Marshal(v)
	return json.Unmarshal(raw, out)
}

func inboundFixture(t *testing.T, cloud *inboundCloud, dsm *inboundDSM) (*cloudflareAdapter, core.Env, setup.PlanRequest) {
	t.Helper()
	adapter, env, request := cfFixture(t, &fakeCloud{})
	adapter.newClient = func(cfg cloudflare.Config) (*cloudflare.Client, error) {
		cfg.HTTPClient = cloud
		return cloudflare.New(cfg)
	}
	env.DSM = dsm
	now := time.Unix(1794306800, 0)
	env.Now = func() time.Time { return now }
	request.SessionID = strings.Repeat("c", 32)
	request.Intent = setup.Receive
	request.Domain = "mail.example.test"
	request.Addresses = []string{"admin@mail.example.test", "info@mail.example.test"}
	request.Decision = setup.Decision{Receive: setup.RoutingReceive, Needs: []string{"cloudflare.inbound"}}
	request.State.Network.EgressIPv4 = detect.Fact("203.0.113.7")
	return adapter, env, request
}

func lanDSM() *inboundDSM { return &inboundDSM{gatewayIP: "172.23.42.201", gatewayStatus: "connected"} }

func TestInboundPlanApplyVerifyRollback(t *testing.T) {
	ctx := context.Background()
	cloud, dsm := newInboundCloud(), lanDSM()
	adapter, env, request := inboundFixture(t, cloud, dsm)
	request.Intent, request.Decision.Send = setup.Both, setup.RelaySend
	cloud.onSend = func(id, subject string) {
		dsm.log = append(dsm.log, delivered(id, subject, "admin@mail.example.test", "172.23.42.201", 1794306801))
	}
	permissions, err := adapter.RequiredPermissions(request)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Zone Settings Write", "Email Routing Rules Write", "Workers Scripts Write", "Connectivity Directory Admin", "Cloudflare Tunnel Read"} {
		found := false
		for _, p := range permissions {
			found = found || p.Name == want && (p.Resource == testZone || p.Resource == testAccount)
		}
		if !found {
			t.Errorf("permission %s missing", want)
		}
	}
	request.Decision.Needs = []string{"cloudflare.inbound"} // inbound only in this plan
	prepared, err := adapter.Plan(ctx, env, request)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	ids := []string{}
	for _, c := range prepared.Changes {
		ids = append(ids, c.ID)
		if strings.Contains(c.After, "fixture-value") || strings.Contains(c.Before, "fixture-value") {
			t.Fatal("credential leaked into the plan")
		}
	}
	// The apex has routing; the subdomain needs it. The Connect tunnel is the
	// only one whose connections all come from the NAS's public IP.
	if strings.Join(ids, ",") != "inbound.routing,inbound.vpc,inbound.worker,inbound.rules" {
		t.Fatalf("changes: %v", ids)
	}
	if !strings.Contains(prepared.Changes[1].After, "172.23.42.201:25 via synopkgconnect-nas-1a2b3c4d") {
		t.Fatalf("vpc change: %s", prepared.Changes[1].After)
	}
	snapshots := map[string]json.RawMessage{}
	for _, c := range prepared.Changes {
		snap, err := adapter.Snapshot(ctx, env, c)
		if err != nil {
			t.Fatalf("snapshot %s: %v", c.ID, err)
		}
		snapshots[c.ID] = snap
		if err := adapter.Apply(ctx, env, c); err != nil {
			t.Fatalf("apply %s: %v", c.ID, err)
		}
		// A lost reply is reconciled: applying again creates nothing new.
		if err := adapter.Apply(ctx, env, c); err != nil {
			t.Fatalf("re-apply %s: %v", c.ID, err)
		}
	}
	if len(cloud.enables) != 1 || cloud.enables[0] != "mail.example.test" {
		t.Fatalf("routing enable: %v", cloud.enables)
	}
	if cloud.creates["vpc"] != 1 || cloud.creates["rule"] != 2 || len(cloud.rules) != 2 {
		t.Fatalf("duplicates: %v rules=%d", cloud.creates, len(cloud.rules))
	}
	if s := cloud.services[0]; s.Host.IPv4 != "172.23.42.201" || s.Host.Network.TunnelID != connectTunnel || s.TCPPort != 25 {
		t.Fatalf("service: %+v", s)
	}
	for _, rule := range cloud.rules {
		rule.Enabled = true
	}
	for i := range cloud.rules {
		cloud.rules[i].Enabled = true
	}
	readback, delivery, findings := adapter.verifyInbound(ctx, env, request, prepared.Changes, 0)
	if !readback || !delivery || len(findings) != 1 || findings[0].TitleKey != "mail.setup.inbound.delivered" {
		t.Fatalf("verify: %v %v %+v", readback, delivery, findings)
	}
	if len(cloud.sent) != 1 || cloud.sent[0]["to"].([]any)[0] != "admin@mail.example.test" {
		t.Fatalf("check mail: %+v", cloud.sent)
	}
	// Checking again never sends a second message.
	if _, _, _ = adapter.verifyInbound(ctx, env, request, prepared.Changes, 0); len(cloud.sent) != 1 {
		t.Fatal("check mail sent twice")
	}
	for i := len(prepared.Changes) - 1; i >= 0; i-- {
		c := prepared.Changes[i]
		if err := adapter.Rollback(ctx, env, c, snapshots[c.ID]); err != nil {
			t.Fatalf("rollback %s: %v", c.ID, err)
		}
	}
	if len(cloud.rules) != 0 || len(cloud.services) != 0 || len(cloud.workers) != 0 {
		t.Fatal("owned resources remain after rollback")
	}
	if len(cloud.routing.Subdomains) != 1 || !cloud.routing.Subdomains[0].Enabled {
		t.Fatal("rollback must keep Email Routing enabled (D5)")
	}
}

func TestInboundRollbackLeavesForeignRules(t *testing.T) {
	ctx := context.Background()
	cloud := newInboundCloud()
	foreign := cloudflare.RoutingRule{ID: "foreign", Name: "operator", Enabled: true,
		Matchers: []cloudflare.RoutingMatcher{{Type: "literal", Field: "to", Value: "sales@example.test"}},
		Actions:  []cloudflare.RoutingAction{{Type: "forward", Value: []string{"someone@example.org"}}}}
	cloud.rules = []cloudflare.RoutingRule{foreign}
	adapter, env, request := inboundFixture(t, cloud, lanDSM())
	prepared, err := adapter.Plan(ctx, env, request)
	if err != nil {
		t.Fatal(err)
	}
	rules := prepared.Changes[len(prepared.Changes)-1]
	snap, _ := adapter.Snapshot(ctx, env, rules)
	if err := adapter.Apply(ctx, env, rules); err != nil {
		t.Fatal(err)
	}
	if err := adapter.Rollback(ctx, env, rules, snap); err != nil {
		t.Fatal(err)
	}
	if len(cloud.rules) != 1 || cloud.rules[0].ID != "foreign" {
		t.Fatalf("foreign rule touched: %+v", cloud.rules)
	}
}

func TestInboundTunnelChoice(t *testing.T) {
	ctx := context.Background()
	t.Run("two tunnels from the NAS's public IP: ask", func(t *testing.T) {
		cloud := newInboundCloud()
		cloud.origins[otherTunnel] = []string{"203.0.113.7"}
		adapter, env, request := inboundFixture(t, cloud, lanDSM())
		_, err := adapter.Plan(ctx, env, request)
		var choice setup.TunnelChoice
		if !errors.As(err, &choice) || len(choice.Options) != 2 || !choice.Options[0].Connect || choice.Options[1].Connect ||
			!choice.Options[0].Match || !choice.Options[1].Match {
			t.Fatalf("choice: %+v %v", choice, err)
		}
		request.Tunnel = otherTunnel
		prepared, err := adapter.Plan(ctx, env, request)
		if err != nil || !strings.Contains(prepared.Changes[1].After, "via office") {
			t.Fatalf("picked tunnel: %v", err)
		}
	})
	t.Run("a connection from elsewhere is not a match", func(t *testing.T) {
		cloud := newInboundCloud()
		cloud.origins[connectTunnel] = []string{"203.0.113.7", "198.51.100.1"}
		adapter, env, request := inboundFixture(t, cloud, lanDSM())
		_, err := adapter.Plan(ctx, env, request)
		var choice setup.TunnelChoice
		if !errors.As(err, &choice) || choice.Options[0].Match {
			t.Fatalf("partial origin matched: %+v %v", choice, err)
		}
	})
	t.Run("public IP unknown: ask", func(t *testing.T) {
		adapter, env, request := inboundFixture(t, newInboundCloud(), lanDSM())
		request.State.Network.EgressIPv4 = detect.Unavailable[string]()
		_, err := adapter.Plan(ctx, env, request)
		var choice setup.TunnelChoice
		if !errors.As(err, &choice) {
			t.Fatalf("unknown egress guessed a tunnel: %v", err)
		}
	})
	t.Run("a pick must be a healthy tunnel", func(t *testing.T) {
		cloud := newInboundCloud()
		cloud.tunnels[1].Status = "down"
		adapter, env, request := inboundFixture(t, cloud, lanDSM())
		request.Tunnel = otherTunnel
		_, err := adapter.Plan(ctx, env, request)
		var choice setup.TunnelChoice
		if !errors.As(err, &choice) || len(choice.Options) != 1 {
			t.Fatalf("down tunnel accepted: %v", err)
		}
	})
	t.Run("no healthy tunnel", func(t *testing.T) {
		cloud := newInboundCloud()
		for i := range cloud.tunnels {
			cloud.tunnels[i].Status = "down"
		}
		adapter, env, request := inboundFixture(t, cloud, lanDSM())
		if _, err := adapter.Plan(ctx, env, request); !errors.Is(err, setup.ErrTunnelRequired) {
			t.Fatalf("got %v", err)
		}
	})
}

func TestInboundLANAddressFromDSM(t *testing.T) {
	for name, dsm := range map[string]*inboundDSM{
		"loopback":     {gatewayIP: "127.0.0.1", gatewayStatus: "connected"},
		"link-local":   {gatewayIP: "169.254.164.178", gatewayStatus: "connected"},
		"public":       {gatewayIP: "203.0.113.7", gatewayStatus: "connected"},
		"disconnected": {gatewayIP: "172.23.42.201", gatewayStatus: "disconnected"},
		"missing":      {},
	} {
		t.Run(name, func(t *testing.T) {
			adapter, env, request := inboundFixture(t, newInboundCloud(), dsm)
			if _, err := adapter.Plan(context.Background(), env, request); !errors.Is(err, setup.ErrLANUnknown) {
				t.Fatalf("got %v", err)
			}
			if dsm.calls[0] != "SYNO.Core.Network get 2" {
				t.Fatalf("DSM read: %v", dsm.calls)
			}
		})
	}
}

func TestInboundPlanRefusals(t *testing.T) {
	ctx := context.Background()
	t.Run("foreign MX on the mail domain", func(t *testing.T) {
		cloud := newInboundCloud()
		mx := cloudflare.DNSRecord{ID: "mx"}
		mx.Name, mx.Type, mx.Content = "mail.example.test", "MX", "mx.operator.test"
		cloud.records = []cloudflare.DNSRecord{mx}
		adapter, env, request := inboundFixture(t, cloud, lanDSM())
		if _, err := adapter.Plan(ctx, env, request); !errors.Is(err, setup.ErrRoutingConflict) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("address already routed elsewhere", func(t *testing.T) {
		cloud := newInboundCloud()
		cloud.rules = []cloudflare.RoutingRule{{ID: "r", Name: "x", Matchers: []cloudflare.RoutingMatcher{{Type: "literal", Field: "to", Value: "Admin@mail.example.test"}}}}
		adapter, env, request := inboundFixture(t, cloud, lanDSM())
		if _, err := adapter.Plan(ctx, env, request); !errors.Is(err, setup.ErrRoutingConflict) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("rule limit", func(t *testing.T) {
		cloud := newInboundCloud()
		for i := 0; i < 199; i++ {
			cloud.rules = append(cloud.rules, cloudflare.RoutingRule{ID: strconv.Itoa(i), Matchers: []cloudflare.RoutingMatcher{{Type: "literal", Field: "to", Value: "u" + strconv.Itoa(i) + "@example.test"}}})
		}
		cloud.rules = append(cloud.rules, cloudflare.RoutingRule{ID: "all", Matchers: []cloudflare.RoutingMatcher{{Type: "all"}}})
		adapter, env, request := inboundFixture(t, cloud, lanDSM())
		if _, err := adapter.Plan(ctx, env, request); !errors.Is(err, setup.ErrRulesLimit) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("apex routing already enabled needs no enable change", func(t *testing.T) {
		adapter, env, request := inboundFixture(t, newInboundCloud(), lanDSM())
		request.Domain = "example.test"
		request.Addresses = []string{"admin@example.test"}
		prepared, err := adapter.Plan(ctx, env, request)
		if err != nil || prepared.Changes[0].ID != "inbound.vpc" {
			t.Fatalf("got %v", err)
		}
	})
}

func TestInboundVerifyWithUserMail(t *testing.T) {
	ctx := context.Background()
	cloud, dsm := newInboundCloud(), lanDSM()
	adapter, env, request := inboundFixture(t, cloud, dsm)
	prepared, err := adapter.Plan(ctx, env, request)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range prepared.Changes {
		if _, err := adapter.Snapshot(ctx, env, c); err != nil {
			t.Fatal(err)
		}
		if err := adapter.Apply(ctx, env, c); err != nil {
			t.Fatal(err)
		}
	}
	for i := range cloud.rules {
		cloud.rules[i].Enabled = true
	}
	code := InboundCheckCode(request.SessionID)
	// An older mail with the code, and a newer one that did not complete,
	// are not evidence.
	processing := delivered("<b@x>", "test "+code, "admin@mail.example.test", "172.23.42.201", 1794306900)
	processing["status"] = "processing"
	dsm.log = []map[string]any{
		delivered("<a@x>", "test "+code, "admin@mail.example.test", "172.23.42.201", 1794306700),
		processing,
	}
	readback, delivery, findings := adapter.verifyInbound(ctx, env, request, prepared.Changes, time.Minute)
	if !readback || delivery || findings[0].TitleKey != "mail.setup.inbound.checkMail" || findings[0].Params["code"] != code || findings[0].Params["address"] != "admin@mail.example.test" {
		t.Fatalf("first check: %v %v %+v", readback, delivery, findings)
	}
	if len(cloud.sent) != 0 {
		t.Fatal("no Email Sending in this flow: nothing may be sent")
	}
	dsm.migrating = true
	if _, delivery, findings = adapter.verifyInbound(ctx, env, request, prepared.Changes, 0); delivery || findings[0].TitleKey != "mail.setup.inbound.logUnknown" {
		t.Fatalf("migrating log: %+v", findings)
	}
	dsm.migrating = false
	dsm.log = append(dsm.log, delivered("<c@x>", "Re: "+code, "ADMIN@mail.example.test", "172.23.42.201", 1794306950))
	if _, delivery, findings = adapter.verifyInbound(ctx, env, request, prepared.Changes, 0); !delivery || findings[0].Severity != core.SeverityOK {
		t.Fatalf("second check: %+v", findings)
	}
	// A deleted rule is a failed read-back, never success.
	cloud.rules = cloud.rules[:1]
	if readback, _, findings = adapter.verifyInbound(ctx, env, request, prepared.Changes, 0); readback || findings[0].TitleKey != "mail.setup.inbound.readbackFailed" {
		t.Fatalf("read-back: %+v", findings)
	}
}

// delivered is one TransactionLog entry as MailPlus writes it.
func delivered(msgID, subject, oriRcpt, srcIP string, at int) map[string]any {
	e := map[string]any{"msgid": msgID, "subject": subject, "rcpt": []string{"admin"}, "status": "complete", "timestamp": at}
	if oriRcpt != "" {
		e["ori_rcpt"] = []string{oriRcpt}
	}
	if srcIP != "" {
		e["src_ip"] = srcIP
	}
	return e
}

func TestArrivedNeedsTheRoutedRecipientAndTheVPCSource(t *testing.T) {
	ctx := context.Background()
	const since, addr, host, code = 1794306800, "admin@mail.example.test", "172.23.42.201", "MPSA-1A2B3C4D"
	for name, entry := range map[string]map[string]any{
		"loopback source":   delivered("<m@x>", "x "+code, addr, "127.0.0.1", since+1),
		"another recipient": delivered("<m@x>", "x "+code, "info@mail.example.test", host, since+1),
		"no source":         delivered("<m@x>", "x "+code, addr, "", since+1),
		"no recipient":      delivered("<m@x>", "x "+code, "", host, since+1),
		"another LAN host":  delivered("<m@x>", "x "+code, addr, "172.23.42.136", since+1),
	} {
		t.Run(name, func(t *testing.T) {
			env := core.Env{DSM: &inboundDSM{log: []map[string]any{entry}}}
			for _, by := range []struct{ msgID, code string }{{"", code}, {"<m@x>", ""}} {
				if ok, err := arrived(ctx, env, since, by.msgID, by.code, addr, host); err != nil || ok {
					t.Fatalf("accepted (%+v): %v %v", by, ok, err)
				}
			}
		})
	}
	env := core.Env{DSM: &inboundDSM{log: []map[string]any{delivered("<m@x>", "x "+code, "<Admin@Mail.Example.Test>", host, since+1)}}}
	for _, by := range []struct{ msgID, code string }{{"", code}, {"m@x", ""}} {
		if ok, err := arrived(ctx, env, since, by.msgID, by.code, addr, host); err != nil || !ok {
			t.Fatalf("matching entry refused (%+v): %v %v", by, ok, err)
		}
	}
}

func TestArrivedPagesBackToSinceOnly(t *testing.T) {
	ctx := context.Background()
	const since, addr, host, code = 1794306800, "admin@mail.example.test", "172.23.42.201", "MPSA-1A2B3C4D"
	log := []map[string]any{delivered("<m@x>", "x "+code, addr, host, since+1)}
	for i := 0; i < 120; i++ { // newer unrelated traffic pushes it to page three
		log = append(log, delivered("<o"+strconv.Itoa(i)+"@x>", "other", "u@mail.example.test", "203.0.113.1", since+10+i))
	}
	dsm := &inboundDSM{log: log}
	if ok, err := arrived(ctx, core.Env{DSM: dsm}, since, "", code, addr, host); err != nil || !ok {
		t.Fatalf("paged entry not found: %v %v", ok, err)
	}
	// Too much traffic since the check: unknown, never "not arrived".
	for i := 0; i < maxLogPages*logPage; i++ {
		log = append(log, delivered("<p"+strconv.Itoa(i)+"@x>", "other", "u@mail.example.test", "203.0.113.1", since+500+i))
	}
	dsm.log = log
	if _, err := arrived(ctx, core.Env{DSM: dsm}, since, "", code, addr, host); !errors.Is(err, setup.ErrUnavailable) {
		t.Fatalf("window overflow: %v", err)
	}
}

func TestInboundApplyRefusesAChangedLANAddress(t *testing.T) {
	ctx := context.Background()
	cloud, dsm := newInboundCloud(), lanDSM()
	adapter, env, request := inboundFixture(t, cloud, dsm)
	prepared, err := adapter.Plan(ctx, env, request)
	if err != nil {
		t.Fatal(err)
	}
	vpc := prepared.Changes[1]
	if _, err := adapter.Snapshot(ctx, env, vpc); err != nil {
		t.Fatal(err)
	}
	dsm.gatewayIP = "172.23.42.77" // DHCP gave the NAS another address
	if err := adapter.Apply(ctx, env, vpc); !errors.Is(err, setup.ErrStale) || len(cloud.services) != 0 {
		t.Fatalf("stale target applied: %v %d", err, len(cloud.services))
	}
	dsm.gatewayIP = "172.23.42.201"
	if err := adapter.Apply(ctx, env, vpc); err != nil {
		t.Fatal(err)
	}
	// Resumed worker step after the address moved: refused as well.
	worker := prepared.Changes[2]
	if _, err := adapter.Snapshot(ctx, env, worker); err != nil {
		t.Fatal(err)
	}
	dsm.gatewayIP = "172.23.42.77"
	if err := adapter.Apply(ctx, env, worker); !errors.Is(err, setup.ErrStale) || len(cloud.workers) != 0 {
		t.Fatalf("worker bound to a stale target: %v", err)
	}
}

func TestInboundTunnelNeverAutoPickedOnUncertainReads(t *testing.T) {
	ctx := context.Background()
	t.Run("a failed connection read", func(t *testing.T) {
		cloud := newInboundCloud()
		cloud.fail = map[string][2]int{"GET /accounts/" + testAccount + "/cfd_tunnel/" + otherTunnel + "/connections": {500, 10001}}
		adapter, env, request := inboundFixture(t, cloud, lanDSM())
		_, err := adapter.Plan(ctx, env, request)
		var choice setup.TunnelChoice
		if !errors.As(err, &choice) || !choice.Options[0].Match {
			t.Fatalf("auto-picked despite an unread tunnel: %v", err)
		}
	})
	t.Run("zero connections never match", func(t *testing.T) {
		cloud := newInboundCloud()
		cloud.origins[connectTunnel] = nil
		cloud.origins[otherTunnel] = nil
		adapter, env, request := inboundFixture(t, cloud, lanDSM())
		_, err := adapter.Plan(ctx, env, request)
		var choice setup.TunnelChoice
		if !errors.As(err, &choice) || choice.Options[0].Match || choice.Options[1].Match {
			t.Fatalf("empty tunnel matched: %+v %v", choice, err)
		}
	})
}

func TestInboundRelayNetworksWarning(t *testing.T) {
	ctx := context.Background()
	for name, c := range map[string]struct {
		dsm  *inboundDSM
		want string
	}{
		"none":       {lanDSM(), ""},
		"configured": {&inboundDSM{gatewayIP: "172.23.42.201", gatewayStatus: "connected", relayNetworks: 2}, "mail.setup.inbound.relayNetworks"},
		"unreadable": {&inboundDSM{gatewayIP: "172.23.42.201", gatewayStatus: "connected", relayUnreadable: true}, "mail.setup.inbound.relayNetworksUnknown"},
	} {
		t.Run(name, func(t *testing.T) {
			adapter, env, request := inboundFixture(t, newInboundCloud(), c.dsm)
			prepared, err := adapter.Plan(ctx, env, request)
			if err != nil {
				t.Fatal(err)
			}
			got := ""
			for _, w := range prepared.Warnings {
				got = w.LabelKey
				if name == "configured" && (w.Value != "mail.setup.inbound.relayNetworksCount" || w.Params["count"] != "2") {
					t.Fatalf("count: %+v", w)
				}
			}
			if got != c.want {
				t.Fatalf("warning %q, want %q", got, c.want)
			}
		})
	}
}

func TestInboundApplyNamesTheRefusedPermission(t *testing.T) {
	ctx := context.Background()
	for name, c := range map[string]struct {
		fail map[string][2]int
		step int
		want error
	}{
		"VPC create refused":       {map[string][2]int{"POST /accounts/" + testAccount + "/connectivity/directory/services": {403, 10000}}, 1, setup.PermissionRefused{Code: setup.PermVPCAdmin}},
		"tunnel read refused":      {map[string][2]int{"GET /accounts/" + testAccount + "/cfd_tunnel": {403, 10000}}, 1, setup.PermissionRefused{Code: setup.PermTunnelRead}},
		"routing enable refused":   {map[string][2]int{"POST /zones/" + testZone + "/email/routing/dns": {403, 10000}}, 0, setup.PermissionRefused{Code: setup.PermZoneSettingsEdit}},
		"product not enabled":      {map[string][2]int{"POST /accounts/" + testAccount + "/connectivity/directory/services": {403, 1002}}, 1, setup.ErrUnavailable},
		"403 without a known code": {map[string][2]int{"POST /zones/" + testZone + "/email/routing/rules": {403, 7000}}, 3, setup.ErrUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			cloud := newInboundCloud()
			adapter, env, request := inboundFixture(t, cloud, lanDSM())
			prepared, err := adapter.Plan(ctx, env, request)
			if err != nil {
				t.Fatal(err)
			}
			for i, ch := range prepared.Changes[:c.step] {
				if _, err := adapter.Snapshot(ctx, env, ch); err != nil {
					t.Fatal(i, err)
				}
				if err := adapter.Apply(ctx, env, ch); err != nil {
					t.Fatal(i, err)
				}
			}
			ch := prepared.Changes[c.step]
			if _, err := adapter.Snapshot(ctx, env, ch); err != nil {
				t.Fatal(err)
			}
			cloud.fail = c.fail
			err = adapter.Apply(ctx, env, ch)
			if err != c.want && !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
		})
	}
}

func routingMX(name, content string, emailRouting bool) cloudflare.DNSRecord {
	r := cloudflare.DNSRecord{ID: "r-" + content}
	r.Name, r.Type, r.Content = name, "MX", content
	r.Meta.EmailRouting, r.Meta.ReadOnly = emailRouting, emailRouting
	return r
}

// A rollback keeps Email Routing and its locked MX/SPF: a new run on the
// domain reuses them; only other MX/SPF, or another rule on an address,
// conflict.
func TestInboundRoutingRecordsAndLeftoverRules(t *testing.T) {
	ctx := context.Background()
	spf := cloudflare.DNSRecord{ID: "spf"}
	spf.Name, spf.Type, spf.Content = "mail.example.test", "TXT", `"v=spf1 include:_spf.mx.cloudflare.net ~all"`
	t.Run("Email Routing records only: no conflict", func(t *testing.T) {
		cloud := newInboundCloud()
		cloud.records = []cloudflare.DNSRecord{routingMX("mail.example.test", "route1.mx.cloudflare.net", true), routingMX("mail.example.test", "route2.mx.cloudflare.net", true), spf}
		adapter, env, request := inboundFixture(t, cloud, lanDSM())
		if _, err := adapter.Plan(ctx, env, request); err != nil {
			t.Fatalf("Routing's own records refused: %v", err)
		}
	})
	t.Run("Routing already enabled with its records: reused, no enable change", func(t *testing.T) {
		cloud := newInboundCloud()
		cloud.routing.Subdomains = []cloudflare.RoutingDomain{{Name: "mail.example.test", Enabled: true}}
		cloud.records = []cloudflare.DNSRecord{routingMX("mail.example.test", "route1.mx.cloudflare.net", true), spf}
		adapter, env, request := inboundFixture(t, cloud, lanDSM())
		prepared, err := adapter.Plan(ctx, env, request)
		if err != nil || prepared.Changes[0].ID != "inbound.vpc" {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("a foreign MX conflicts", func(t *testing.T) {
		cloud := newInboundCloud()
		cloud.records = []cloudflare.DNSRecord{routingMX("mail.example.test", "mx.operator.test", false)}
		adapter, env, request := inboundFixture(t, cloud, lanDSM())
		if _, err := adapter.Plan(ctx, env, request); !errors.Is(err, setup.ErrRoutingConflict) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("a foreign SPF conflicts", func(t *testing.T) {
		cloud := newInboundCloud()
		other := spf
		other.Content = "v=spf1 include:_spf.google.com ~all"
		cloud.records = []cloudflare.DNSRecord{other}
		adapter, env, request := inboundFixture(t, cloud, lanDSM())
		if _, err := adapter.Plan(ctx, env, request); !errors.Is(err, setup.ErrRoutingConflict) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("a foreign rule on an address conflicts", func(t *testing.T) {
		cloud := newInboundCloud()
		cloud.rules = []cloudflare.RoutingRule{{ID: "e2", Name: "msa-exp-e2-admin", Enabled: true,
			Matchers: []cloudflare.RoutingMatcher{{Type: "literal", Field: "to", Value: "admin@mail.example.test"}},
			Actions:  []cloudflare.RoutingAction{{Type: "worker", Value: []string{"msa-exp-e2-inbound"}}}}}
		adapter, env, request := inboundFixture(t, cloud, lanDSM())
		if _, err := adapter.Plan(ctx, env, request); !errors.Is(err, setup.ErrRoutingConflict) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("a leftover rule of this package is taken over, and given back on rollback", func(t *testing.T) {
		cloud := newInboundCloud()
		const earlier = "hk-0123456789abcdef0123456789abcdef"
		left := cloudflare.RoutingRule{ID: "old", Name: "syno-home-keeper:" + earlier, Enabled: true, Priority: 7,
			Matchers: []cloudflare.RoutingMatcher{{Type: "literal", Field: "to", Value: "admin@mail.example.test"}},
			Actions:  []cloudflare.RoutingAction{{Type: "worker", Value: []string{"syno-home-keeper-" + earlier + "-inbound"}}}}
		cloud.rules = []cloudflare.RoutingRule{left}
		adapter, env, request := inboundFixture(t, cloud, lanDSM())
		prepared, err := adapter.Plan(ctx, env, request)
		if err != nil {
			t.Fatal(err)
		}
		rules := prepared.Changes[len(prepared.Changes)-1]
		if !strings.Contains(rules.After, "takes over a leftover rule of this package: admin@mail.example.test") {
			t.Fatalf("preview: %s", rules.After)
		}
		snap, err := adapter.Snapshot(ctx, env, rules)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 2; i++ { // a lost reply is reconciled
			if err := adapter.Apply(ctx, env, rules); err != nil {
				t.Fatal(err)
			}
		}
		owner := inboundOwner(request.SessionID)
		if cloud.creates["rule"] != 1 || cloud.puts != 1 || len(cloud.rules) != 2 {
			t.Fatalf("creates=%d puts=%d rules=%d", cloud.creates["rule"], cloud.puts, len(cloud.rules))
		}
		if r := cloud.rules[0]; r.ID != "old" || r.Name != "syno-home-keeper:"+owner || r.Actions[0].Value[0] != "syno-home-keeper-"+owner+"-inbound" || r.Priority != 7 {
			t.Fatalf("taken over: %+v", r)
		}
		if err := adapter.Rollback(ctx, env, rules, snap); err != nil {
			t.Fatal(err)
		}
		if len(cloud.rules) != 1 || cloud.rules[0].Name != left.Name || cloud.rules[0].Actions[0].Value[0] != left.Actions[0].Value[0] {
			t.Fatalf("not given back: %+v", cloud.rules)
		}
	})
}

const earlierOwner = "hk-0123456789abcdef0123456789abcdef"

func leftoverRule(owner string) cloudflare.RoutingRule {
	return cloudflare.RoutingRule{ID: "old", Name: "syno-home-keeper:" + owner, Enabled: true,
		Matchers: []cloudflare.RoutingMatcher{{Type: "literal", Field: "to", Value: "admin@mail.example.test"}},
		Actions:  []cloudflare.RoutingAction{{Type: "worker", Value: []string{"syno-home-keeper-" + owner + "-inbound"}}}}
}

func earlierService(host, tunnel string) cloudflare.VPCService {
	s := cloudflare.VPCService{ServiceID: "earlier", Name: "syno-home-keeper-" + earlierOwner + "-smtp", Type: "tcp", TCPPort: 25}
	s.Host.IPv4, s.Host.Network.TunnelID = host, tunnel
	return s
}

// Takeover never steals another NAS's live rule.
func TestInboundTakeoverOnlyWithoutALiveOtherSetup(t *testing.T) {
	ctx := context.Background()
	for name, c := range map[string]struct {
		services []cloudflare.VPCService
		adopt    bool
	}{
		"earlier VPC missing":                  {nil, true},
		"earlier VPC to this NAS, same tunnel": {[]cloudflare.VPCService{earlierService("172.23.42.201", connectTunnel)}, true},
		"earlier VPC on another host":          {[]cloudflare.VPCService{earlierService("172.23.42.50", connectTunnel)}, false},
		"earlier VPC over another tunnel":      {[]cloudflare.VPCService{earlierService("172.23.42.201", otherTunnel)}, false},
	} {
		t.Run(name, func(t *testing.T) {
			cloud := newInboundCloud()
			cloud.rules = []cloudflare.RoutingRule{leftoverRule(earlierOwner)}
			cloud.services = c.services
			adapter, env, request := inboundFixture(t, cloud, lanDSM())
			prepared, err := adapter.Plan(ctx, env, request)
			if !c.adopt {
				// Not a plain conflict: the copy says it is this package's
				// leftover and that the administrator removes it.
				if !errors.Is(err, setup.ErrRoutingLeftover) {
					t.Fatalf("got %v", err)
				}
				return
			}
			if err != nil || !strings.Contains(prepared.Changes[len(prepared.Changes)-1].After, "takes over a leftover rule of this package") {
				t.Fatalf("got %v", err)
			}
		})
	}
}

// A leftover rule that changed between the preview and the apply is never
// taken over: stalePlan.
func TestInboundTakeoverRefusesAModifiedRule(t *testing.T) {
	ctx := context.Background()
	for name, modify := range map[string]func(*cloudflare.RoutingRule){
		"address changed":     func(r *cloudflare.RoutingRule) { r.Matchers[0].Value = "info@mail.example.test" },
		"non-literal matcher": func(r *cloudflare.RoutingRule) { r.Matchers = []cloudflare.RoutingMatcher{{Type: "all"}} },
		"another Worker":      func(r *cloudflare.RoutingRule) { r.Actions[0].Value = []string{"someone-else"} },
		"disabled meanwhile":  func(r *cloudflare.RoutingRule) { r.Enabled = false },
		"owner is a third one": func(r *cloudflare.RoutingRule) {
			*r = leftoverRule("hk-fedcba9876543210fedcba9876543210")
		},
	} {
		t.Run(name, func(t *testing.T) {
			cloud := newInboundCloud()
			cloud.rules = []cloudflare.RoutingRule{leftoverRule(earlierOwner)}
			adapter, env, request := inboundFixture(t, cloud, lanDSM())
			prepared, err := adapter.Plan(ctx, env, request)
			if err != nil {
				t.Fatal(err)
			}
			rules := prepared.Changes[len(prepared.Changes)-1]
			if _, err := adapter.Snapshot(ctx, env, rules); err != nil {
				t.Fatal(err)
			}
			id := cloud.rules[0].ID
			modify(&cloud.rules[0])
			cloud.rules[0].ID = id
			if err := adapter.Apply(ctx, env, rules); !errors.Is(err, setup.ErrStale) {
				t.Fatalf("got %v", err)
			}
			if cloud.puts != 0 {
				t.Fatal("a modified rule was written")
			}
		})
	}
}

// A disabled leftover rule is refused at plan time: taken over it would keep
// its state and the address would receive nothing; enabling it would undo an
// administrator's choice. Nothing is planned or written.
func TestInboundDisabledLeftoverIsRefused(t *testing.T) {
	ctx := context.Background()
	for name, services := range map[string][]cloudflare.VPCService{
		"earlier VPC missing":                  nil,
		"earlier VPC to this NAS, same tunnel": {earlierService("172.23.42.201", connectTunnel)},
	} {
		t.Run(name, func(t *testing.T) {
			cloud := newInboundCloud()
			left := leftoverRule(earlierOwner)
			left.Enabled = false
			cloud.rules, cloud.services = []cloudflare.RoutingRule{left}, services
			adapter, env, request := inboundFixture(t, cloud, lanDSM())
			if _, err := adapter.Plan(ctx, env, request); !errors.Is(err, setup.ErrRoutingLeftoverDisabled) {
				t.Fatalf("got %v", err)
			}
			if cloud.puts != 0 || len(cloud.creates) != 0 {
				t.Fatalf("written: puts=%d creates=%v", cloud.puts, cloud.creates)
			}
		})
	}
	// A leftover on another tunnel stays manual cleanup, enabled or not.
	cloud := newInboundCloud()
	left := leftoverRule(earlierOwner)
	left.Enabled = false
	cloud.rules, cloud.services = []cloudflare.RoutingRule{left}, []cloudflare.VPCService{earlierService("172.23.42.201", otherTunnel)}
	adapter, env, request := inboundFixture(t, cloud, lanDSM())
	if _, err := adapter.Plan(ctx, env, request); !errors.Is(err, setup.ErrRoutingLeftover) {
		t.Fatalf("other tunnel, disabled: %v", err)
	}
}

// A2: the plan matches a rule to a requested address only through a literal
// "to" matcher with that address (case-insensitive). A rule on the sender
// field, of another type, or for another address is not about this address;
// a rule of this very owner (a second preview of the same flow) is a conflict
// here, never "taken over" from itself.
func TestInboundRuleMatchIsLiteralTo(t *testing.T) {
	ctx := context.Background()
	rule := func(m cloudflare.RoutingMatcher) cloudflare.RoutingRule {
		return cloudflare.RoutingRule{ID: "x", Name: "other", Enabled: true, Matchers: []cloudflare.RoutingMatcher{m},
			Actions: []cloudflare.RoutingAction{{Type: "forward", Value: []string{"elsewhere@other.test"}}}}
	}
	for name, c := range map[string]struct {
		rule     cloudflare.RoutingRule
		conflict bool
	}{
		"literal to, same address":       {rule(cloudflare.RoutingMatcher{Type: "literal", Field: "to", Value: "admin@mail.example.test"}), true},
		"literal to, other case":         {rule(cloudflare.RoutingMatcher{Type: "literal", Field: "to", Value: "ADMIN@Mail.Example.Test"}), true},
		"literal to, another address":    {rule(cloudflare.RoutingMatcher{Type: "literal", Field: "to", Value: "sales@mail.example.test"}), false},
		"literal from, same address":     {rule(cloudflare.RoutingMatcher{Type: "literal", Field: "from", Value: "admin@mail.example.test"}), false},
		"non-literal type, same address": {rule(cloudflare.RoutingMatcher{Type: "regex", Field: "to", Value: "admin@mail.example.test"}), false},
		"catch-all":                      {rule(cloudflare.RoutingMatcher{Type: "all"}), false},
	} {
		t.Run(name, func(t *testing.T) {
			cloud := newInboundCloud()
			cloud.rules = []cloudflare.RoutingRule{c.rule}
			adapter, env, request := inboundFixture(t, cloud, lanDSM())
			_, err := adapter.Plan(ctx, env, request)
			if c.conflict != errors.Is(err, setup.ErrRoutingConflict) || !c.conflict && err != nil {
				t.Fatalf("got %v", err)
			}
		})
	}
	t.Run("own owner's rule", func(t *testing.T) {
		cloud := newInboundCloud()
		adapter, env, request := inboundFixture(t, cloud, lanDSM())
		cloud.rules = []cloudflare.RoutingRule{leftoverRule(inboundOwner(request.SessionID))}
		if _, err := adapter.Plan(ctx, env, request); !errors.Is(err, setup.ErrRoutingConflict) {
			t.Fatalf("got %v", err)
		}
	})
}

// Setup, a resumed apply and the rollback never ask for the zone's catch-all:
// whatever an operator set there (a forward elsewhere, say) is never read,
// changed or deleted, and rollback removes exactly the rules it created.
func TestInboundNeverTouchesTheCatchAll(t *testing.T) {
	ctx := context.Background()
	cloud := newInboundCloud()
	adapter, env, request := inboundFixture(t, cloud, lanDSM())
	prepared, err := adapter.Plan(ctx, env, request)
	if err != nil {
		t.Fatal(err)
	}
	snapshots := map[string]json.RawMessage{}
	for _, c := range prepared.Changes {
		snap, err := adapter.Snapshot(ctx, env, c)
		if err != nil {
			t.Fatalf("snapshot %s: %v", c.ID, err)
		}
		snapshots[c.ID] = snap
		for range 2 {
			if err := adapter.Apply(ctx, env, c); err != nil {
				t.Fatalf("apply %s: %v", c.ID, err)
			}
		}
	}
	for i := len(prepared.Changes) - 1; i >= 0; i-- {
		c := prepared.Changes[i]
		if err := adapter.Rollback(ctx, env, c, snapshots[c.ID]); err != nil {
			t.Fatalf("rollback %s: %v", c.ID, err)
		}
	}
	for _, r := range cloud.requests {
		if strings.Contains(r, "catch_all") {
			t.Fatalf("catch-all touched: %s", r)
		}
		if strings.HasPrefix(r, "DELETE ") && strings.Contains(r, "/email/routing/rules/") && !strings.Contains(r, "/rules/rule") {
			t.Fatalf("deleted a rule this setup did not create: %s", r)
		}
	}
	if len(cloud.rules) != 0 || len(cloud.services) != 0 || len(cloud.workers) != 0 {
		t.Fatal("owned resources remain after rollback")
	}
	// The client itself refuses the catch-all path for deletion.
	client, err := adapter.client(ctx, env, cloudOperation{Request: request, Owner: inboundOwner(request.SessionID)})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.DeleteRoutingRule(ctx, testZone, "catch_all"); !cloudflare.IsKind(err, cloudflare.ErrOwnership) {
		t.Fatalf("catch-all delete not refused: %v", err)
	}
}
