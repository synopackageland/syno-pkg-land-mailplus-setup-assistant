package mail

import (
	"context"
	"sort"
	"strings"
	"testing"

	"SynoMailPlusSetupAssistant/internal/mail/cloudflare"
	"SynoMailPlusSetupAssistant/internal/mail/setup"
)

// Removing a subdomain's setup also removes the
// receiving DNS records enabling Email Routing there created, by the IDs the
// routing step recorded; records that existed before stay or are restored.

const sub = "mail.example.test"

func mailRecordIDs(cloud *inboundCloud, name string) []string {
	ids := []string{}
	for _, r := range cloud.records {
		if r.Name == name {
			ids = append(ids, r.ID)
		}
	}
	sort.Strings(ids)
	return ids
}

// preexisting puts records this App did not create into the zone: the
// subdomain's DMARC and the apex's own mail records.
func preexisting(cloud *inboundCloud) {
	pr := 10
	cloud.records = append(cloud.records,
		cloudflare.DNSRecord{ID: "pre-dmarc", DNSFields: cloudflare.DNSFields{Type: "TXT", Name: "_dmarc." + sub, Content: "v=DMARC1; p=none", TTL: 1}},
		cloudflare.DNSRecord{ID: "apex-mx", DNSFields: cloudflare.DNSFields{Type: "MX", Name: "example.test", Content: "route1.mx.cloudflare.net", TTL: 1, Priority: &pr}},
		cloudflare.DNSRecord{ID: "apex-spf", DNSFields: cloudflare.DNSFields{Type: "TXT", Name: "example.test", Content: cloudflare.RoutingSPF, TTL: 1}})
}

func TestRemoveDeletesOnlyTheSubdomainRecordsTheSetupCreated(t *testing.T) {
	ctx := context.Background()
	cloud := newInboundCloud()
	preexisting(cloud)
	r := removableAt(t, cloud, sub, setup.ReceiveAddresses, "admin@"+sub)
	created := mailRecordIDs(cloud, sub)
	if len(created) != 4 {
		t.Fatalf("enabling routing on the subdomain: %v", created)
	}
	list, _ := r.s.Status(ctx, r.env)
	if got := strings.Join(list.Setups[0].Removes, ","); !strings.Contains(got, "ui.remove.item.receiveDNS") {
		t.Fatalf("the dialog must list the receiving DNS: %s", got)
	}
	view, err := r.s.Remove(ctx, r.env, r.id, false, false)
	if err != nil || view.Removal.State != "done" || view.Removal.Done != view.Removal.Total {
		t.Fatalf("removal: %+v %v", view.Removal, err)
	}
	if got := mailRecordIDs(cloud, sub); len(got) != 0 {
		t.Fatalf("created records left: %v", got)
	}
	deleted := append([]string{}, cloud.dnsDeletes...)
	sort.Strings(deleted)
	if strings.Join(deleted, ",") != strings.Join(created, ",") {
		t.Fatalf("deleted %v, created %v", deleted, created)
	}
	for _, keep := range []string{"pre-dmarc", "apex-mx", "apex-spf"} {
		found := false
		for _, rec := range cloud.records {
			found = found || rec.ID == keep
		}
		if !found {
			t.Fatalf("pre-existing %s deleted", keep)
		}
	}
	// Routing on the zone is never turned off for a subdomain.
	if cloud.disables != 0 {
		t.Fatal("zone routing disabled")
	}
	if _, found, _ := loadLedger(ctx, r.env, sub); found {
		t.Fatal("ledger not cleared")
	}

	// Setting the subdomain up again enables routing again (it stays enabled
	// on Cloudflare without its records) and the records come back.
	again := removableAt(t, cloud, sub, setup.ReceiveAddresses, "admin@"+sub)
	if got := mailRecordIDs(cloud, sub); len(got) != 4 {
		t.Fatalf("records not added back: %v", got)
	}
	_ = again
}

func TestRemoveLeavesARecordChangedSinceAndRestoresAMergedOne(t *testing.T) {
	ctx := context.Background()
	cloud := newInboundCloud()
	r := removableAt(t, cloud, sub, setup.ReceiveAddresses, "admin@"+sub)
	// Ledger fixture: a pre-existing SPF enabling routing merged into.
	led, found, err := loadLedger(ctx, r.env, sub)
	if err != nil || !found || len(led.Created) != 4 {
		t.Fatalf("ledger: %+v %v %v", led, found, err)
	}
	merged := cloudflare.DNSRecord{ID: "pre-spf", DNSFields: cloudflare.DNSFields{Type: "TXT", Name: sub, Content: "v=spf1 include:_spf.mx.cloudflare.net include:spf.other.test ~all", TTL: 1}}
	before := merged
	before.Content = "v=spf1 include:spf.other.test ~all"
	cloud.records = append(cloud.records, merged)
	led.Changed = []ledgerChange{{Before: before, After: merged}}
	// One created MX the administrator changed since: theirs now.
	for i := range cloud.records {
		if cloud.records[i].ID == led.Created[0].ID {
			cloud.records[i].Content = "mx.elsewhere.test"
		}
	}
	if err := r.env.KV.Put(ctx, "mail.wiring", ledgerKey(sub), led); err != nil {
		t.Fatal(err)
	}
	view, err := r.s.Remove(ctx, r.env, r.id, false, false)
	if err != nil || view.Removal.State != "done" {
		t.Fatalf("removal: %+v %v", view.Removal, err)
	}
	left := map[string]cloudflare.DNSRecord{}
	for _, rec := range cloud.records {
		left[rec.ID] = rec
	}
	if rec, ok := left[led.Created[0].ID]; !ok || rec.Content != "mx.elsewhere.test" {
		t.Fatalf("a record changed since was deleted: %+v", rec)
	}
	if rec, ok := left["pre-spf"]; !ok || rec.Content != before.Content {
		t.Fatalf("merged SPF not restored to its snapshot: %+v", rec)
	}
	if len(cloud.dnsDeletes) != 3 || len(cloud.dnsPuts) != 1 {
		t.Fatalf("deletes %v puts %v", cloud.dnsDeletes, cloud.dnsPuts)
	}
}

// Cloudflare refuses (1046) to delete the routing MX it added to a
// subdomain. The removal unlocks that subdomain's records (PATCH
// email/routing/dns with the subdomain's name, once) and deletes them: no
// locked MX is left, the apex's locked records and every record the setup
// did not create stay, and Email Routing on the zone stays on.
func TestRemoveUnlocksTheSubdomainAndDeletesItsLockedMX(t *testing.T) {
	ctx := context.Background()
	cloud := newInboundCloud()
	preexisting(cloud)
	for i := range cloud.records {
		if cloud.records[i].ID == "apex-mx" {
			cloud.records[i].Meta.EmailRouting, cloud.records[i].Meta.ReadOnly = true, true
		}
	}
	r := removableAt(t, cloud, sub, setup.ReceiveAddresses, "admin@"+sub)
	led, _, _ := loadLedger(ctx, r.env, sub)
	if len(led.Created) != 4 {
		t.Fatalf("ledger: %+v", led)
	}
	created := mailRecordIDs(cloud, sub)
	cloud.lockedDNS = true
	view, err := r.s.Remove(ctx, r.env, r.id, false, false)
	if err != nil || view.Removal == nil || view.Removal.State != "done" || view.Removal.Done != view.Removal.Total {
		t.Fatalf("removal: %+v %v", view.Removal, err)
	}
	if len(view.Removal.Locked) != 0 || view.Removal.AccountID != "" || view.Removal.Zone != "" {
		t.Fatalf("nothing should be left locked: %+v", view.Removal)
	}
	if strings.Join(cloud.unlocks, ",") != sub {
		t.Fatalf("unlocks: %v", cloud.unlocks)
	}
	if got := mailRecordIDs(cloud, sub); len(got) != 0 {
		t.Fatalf("left at the subdomain: %v", got)
	}
	deleted := append([]string{}, cloud.dnsDeletes...)
	sort.Strings(deleted)
	if strings.Join(deleted, ",") != strings.Join(created, ",") {
		t.Fatalf("deleted %v, created %v", deleted, created)
	}
	for _, id := range []string{"pre-dmarc", "apex-mx", "apex-spf"} {
		found := false
		for _, rec := range cloud.records {
			if rec.ID == id {
				found = true
				if id == "apex-mx" && !rec.Meta.EmailRouting {
					t.Fatal("the apex MX was unlocked")
				}
			}
		}
		if !found {
			t.Fatalf("%s was touched", id)
		}
	}
	if cloud.disables != 0 {
		t.Fatal("zone routing disabled")
	}
	if _, found, _ := loadLedger(ctx, r.env, sub); found {
		t.Fatal("ledger left")
	}
}

// When Cloudflare refuses the unlock itself, the removal leaves the locked
// MX, deletes the SPF and everything else, clears the ledger, finishes, and
// lists the MX it left with what the dashboard link needs (the account and
// the zone's name).
func TestRemoveLeavesLockedRecordsWhenTheUnlockIsRefused(t *testing.T) {
	ctx := context.Background()
	cloud := newInboundCloud()
	preexisting(cloud)
	r := removableAt(t, cloud, sub, setup.ReceiveAddresses, "admin@"+sub)
	led, _, _ := loadLedger(ctx, r.env, sub)
	if len(led.Created) != 4 {
		t.Fatalf("ledger: %+v", led)
	}
	cloud.lockedDNS = true
	unlock := "PATCH /zones/" + testZone + "/email/routing/dns"
	cloud.fail = map[string][2]int{unlock: {403, 10000}}
	view, err := r.s.Remove(ctx, r.env, r.id, false, false)
	if err != nil || view.Removal == nil || view.Removal.State != "done" || view.Removal.CauseKey != "" || view.Removal.Done != view.Removal.Total {
		t.Fatalf("locked MX must not stop the removal: %+v %v", view.Removal, err)
	}
	asked := 0
	for _, q := range cloud.requests {
		if q == unlock {
			asked++
		}
	}
	if asked != 1 {
		t.Fatalf("unlock asked %d times", asked)
	}
	got := []string{}
	for _, l := range view.Removal.Locked {
		got = append(got, l.Type+" "+l.Name+" "+l.Content)
	}
	sort.Strings(got)
	want := []string{"MX " + sub + " route1.mx.cloudflare.net", "MX " + sub + " route2.mx.cloudflare.net", "MX " + sub + " route3.mx.cloudflare.net"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("locked: %v", got)
	}
	if view.Removal.AccountID != testAccount || view.Removal.Zone != "example.test" {
		t.Fatalf("dashboard link parts: %q %q", view.Removal.AccountID, view.Removal.Zone)
	}
	// Only the SPF the setup created went; the MX, the subdomain's DMARC and
	// the apex records stay.
	left := strings.Join(mailRecordIDs(cloud, sub), ",")
	if len(cloud.dnsDeletes) != 1 || strings.Contains(left, cloud.dnsDeletes[0]) || len(mailRecordIDs(cloud, sub)) != 3 {
		t.Fatalf("deleted %v, left %s", cloud.dnsDeletes, left)
	}
	for _, id := range []string{"pre-dmarc", "apex-mx", "apex-spf"} {
		found := false
		for _, rec := range cloud.records {
			found = found || rec.ID == id
		}
		if !found {
			t.Fatalf("%s was touched", id)
		}
	}
	// The ledger and the kept record are cleared: nothing waits for the MX.
	if _, found, _ := loadLedger(ctx, r.env, sub); found {
		t.Fatal("ledger left")
	}
	if rec := r.record(t); rec.ID != "" || rec.TokenRef != "" {
		t.Fatalf("record left: %+v", rec)
	}
}

// An unlock whose reply names another domain (the zone apex) is not trusted:
// the removal stops before deleting any locked record and keeps them in the
// ledger; pressing again after a good unlock finishes.
func TestRemoveStopsWhenTheUnlockNamesAnotherDomain(t *testing.T) {
	ctx := context.Background()
	cloud := newInboundCloud()
	r := removableAt(t, cloud, sub, setup.ReceiveAddresses, "admin@"+sub)
	cloud.lockedDNS = true
	cloud.unlockReply = "example.test"
	view, err := r.s.Remove(ctx, r.env, r.id, false, false)
	if err != nil || view.Removal.State != "failed" {
		t.Fatalf("an unlock elsewhere must stop: %+v %v", view.Removal, err)
	}
	if len(cloud.dnsDeletes) != 0 || len(mailRecordIDs(cloud, sub)) != 4 {
		t.Fatalf("deleted %v", cloud.dnsDeletes)
	}
	if led, found, _ := loadLedger(ctx, r.env, sub); !found || len(led.Created) != 4 {
		t.Fatalf("ledger: %+v %v", led, found)
	}
	cloud.unlockReply = ""
	view, err = r.s.Remove(ctx, r.env, r.id, false, false)
	if err != nil || view.Removal.State != "done" || len(mailRecordIDs(cloud, sub)) != 0 || len(view.Removal.Locked) != 0 {
		t.Fatalf("again: %+v %v %v", view.Removal, err, mailRecordIDs(cloud, sub))
	}
}

// Without a lock nothing is listed, and the dashboard link has no parts.
func TestRemoveListsNothingWhenNothingIsLocked(t *testing.T) {
	ctx := context.Background()
	cloud := newInboundCloud()
	r := removableAt(t, cloud, sub, setup.ReceiveAddresses, "admin@"+sub)
	view, err := r.s.Remove(ctx, r.env, r.id, false, false)
	if err != nil || view.Removal.State != "done" || len(view.Removal.Locked) != 0 || view.Removal.AccountID != "" || view.Removal.Zone != "" {
		t.Fatalf("removal: %+v %v", view.Removal, err)
	}
}

// Any other refusal still stops, and pressing again goes on where it stopped.
func TestRemoveStopsOnOtherDNSRefusalsAndGoesOnAfterwards(t *testing.T) {
	ctx := context.Background()
	cloud := newInboundCloud()
	r := removableAt(t, cloud, sub, setup.ReceiveAddresses, "admin@"+sub)
	led, _, _ := loadLedger(ctx, r.env, sub)
	cloud.fail = map[string][2]int{"DELETE /zones/" + testZone + "/dns_records/" + led.Created[0].ID: {403, 10000}}
	view, err := r.s.Remove(ctx, r.env, r.id, false, false)
	if err != nil || view.Removal.State != "failed" || view.Removal.CauseKey != "mail.inbound.cause.token" {
		t.Fatalf("refused: %+v %v", view.Removal, err)
	}
	cloud.fail = nil
	view, err = r.s.Remove(ctx, r.env, r.id, false, false)
	if err != nil || view.Removal.State != "done" || len(mailRecordIDs(cloud, sub)) != 0 {
		t.Fatalf("again: %+v %v %v", view.Removal, err, mailRecordIDs(cloud, sub))
	}
}

func TestRemoveDeletesRecordsAnEarlierRolledBackSetupCreated(t *testing.T) {
	ctx := context.Background()
	cloud := newInboundCloud()
	// A first setup enabled routing on the subdomain, then was rolled back:
	// routing and its records stay (D5), so the next setup has no routing step.
	adapter, env, request := inboundFixture(t, cloud, lanDSM())
	request.Domain, request.Addresses = sub, []string{"admin@" + sub}
	rollbackAll(t, adapter, env, applyAll(t, adapter, env, request))
	created := mailRecordIDs(cloud, sub)
	if len(created) != 4 {
		t.Fatalf("records: %v", created)
	}
	r := removableAt(t, cloud, sub, setup.ReceiveAddresses, "admin@"+sub)
	_ = env
	// removableAt uses its own store: carry the first setup's ledger over, as
	// both run in one package store on the NAS.
	led, found, _ := loadLedger(ctx, env, sub)
	if !found {
		t.Fatal("rollback dropped the ledger")
	}
	if err := r.env.KV.Put(ctx, "mail.wiring", ledgerKey(sub), led); err != nil {
		t.Fatal(err)
	}
	if got := mailRecordIDs(cloud, sub); strings.Join(got, ",") != strings.Join(created, ",") {
		t.Fatalf("second setup added records: %v", got)
	}
	rec := r.record(t)
	rec.RoutingDNS = true // Kept saw no ledger in its own store
	if err := r.env.KV.Put(ctx, keptModule, keptKey(r.id), rec); err != nil {
		t.Fatal(err)
	}
	view, err := r.s.Remove(ctx, r.env, r.id, false, false)
	if err != nil || view.Removal.State != "done" || len(mailRecordIDs(cloud, sub)) != 0 {
		t.Fatalf("removal: %+v %v %v", view.Removal, err, mailRecordIDs(cloud, sub))
	}
}

// live on a test NAS: Cloudflare refuses (1046) to delete a subdomain's
// routing MX but deletes its SPF. With the MX left and the SPF gone, the next
// setup enables routing again, which adds back the SPF; the ledger records
// that SPF as created and the MX as there before, so the removal deletes
// the SPF and leaves the MX, without stopping.
func TestSetupAfterLockedMXRecordsTheSPFItAddsBack(t *testing.T) {
	ctx := context.Background()
	cloud := newInboundCloud()
	pr := []int{50, 69, 41}
	for i := range pr {
		r := cloudflare.DNSRecord{ID: "left-mx-" + string(rune('1'+i)), DNSFields: cloudflare.DNSFields{Type: "MX", Name: sub,
			Content: "route" + string(rune('1'+i)) + ".mx.cloudflare.net", TTL: 1, Priority: &pr[i]}}
		r.Meta.EmailRouting, r.Meta.ReadOnly = true, true
		cloud.records = append(cloud.records, r)
	}
	cloud.routing.Subdomains = append(cloud.routing.Subdomains, cloudflare.RoutingDomain{Name: sub, Enabled: true, Status: "ready"})
	cloud.lockedDNS = true
	r := removableAt(t, cloud, sub, setup.ReceiveAddresses, "admin@"+sub)
	if len(cloud.enables) != 1 || cloud.enables[0] != sub {
		t.Fatalf("routing was not enabled again: %v", cloud.enables)
	}
	led, found, err := loadLedger(ctx, r.env, sub)
	if err != nil || !found || len(led.Created) != 1 || led.Created[0].Type != "TXT" || len(led.Before) != 3 {
		t.Fatalf("ledger: %+v %v %v", led, found, err)
	}
	if !r.record(t).RoutingDNS {
		t.Fatal("the kept setup does not know its ledger")
	}
	view, err := r.s.Remove(ctx, r.env, r.id, false, false)
	if err != nil || view.Removal.State != "done" {
		t.Fatalf("removal: %+v %v", view.Removal, err)
	}
	if got := strings.Join(mailRecordIDs(cloud, sub), ","); got != "left-mx-1,left-mx-2,left-mx-3" {
		t.Fatalf("left at the subdomain: %s", got)
	}
	if len(cloud.dnsDeletes) != 1 || cloud.dnsDeletes[0] != led.Created[0].ID {
		t.Fatalf("deleted: %v", cloud.dnsDeletes)
	}
}
