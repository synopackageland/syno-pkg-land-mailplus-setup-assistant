package cloudflare

import (
	"context"
	"net/http"
	"reflect"
	"testing"
)

func ownedDNS(id, content string) DNSRecord {
	return DNSRecord{ID: id, DNSFields: DNSFields{
		Type: "TXT", Name: "mail.example.test", Content: content, TTL: 300,
		Comment: "syno-home-keeper:fixture", Tags: []string{"purpose:mail"},
	}}
}

func TestDNSCRUDAndTagging(t *testing.T) {
	record := ownedDNS("record", "v=spf1 -all")
	create := post("/zones/zone/dns_records", record)
	create.check = bodyIs(record.DNSFields)
	next := record
	next.Content = "v=spf1 include:example.test -all"
	update := exchange{method: "PUT", path: "/zones/zone/dns_records/record", result: next, check: bodyIs(next.DNSFields)}
	c := fixture(t,
		get("/zones/zone/dns_records", []DNSRecord{}), create,
		get("/zones/zone/dns_records/record", record), update,
		get("/zones/zone/dns_records/record", next), del("/zones/zone/dns_records/record"))
	ctx := context.Background()
	input := record.DNSFields
	input.Comment = ""
	created, err := c.CreateDNSRecord(ctx, "zone", input)
	if err != nil || created.Comment != c.marker() {
		t.Fatalf("create/tag: %+v %v", created, err)
	}
	updated, err := c.UpdateDNSRecord(ctx, "zone", created.ID, next.DNSFields)
	if err != nil || updated.Content != next.Content {
		t.Fatalf("update: %+v %v", updated, err)
	}
	if err := c.DeleteDNSRecord(ctx, "zone", created.ID); err != nil {
		t.Fatal(err)
	}
}

func TestDNSRefusesForeignLockedAndIdentityChanges(t *testing.T) {
	for _, variant := range []string{"foreign", "lookalike", "locked", "managed", "identity"} {
		for _, operation := range []string{"update", "delete"} {
			if variant == "identity" && operation == "delete" {
				continue
			}
			t.Run(variant+"/"+operation, func(t *testing.T) {
				record := ownedDNS("record", "old")
				want := ErrOwnership
				switch variant {
				case "foreign":
					record.Comment = "someone else"
				case "lookalike":
					record.Comment += "-other"
				case "locked":
					record.Meta.ReadOnly = true
					want = ErrManagedDNS
				case "managed":
					record.Meta.EmailRouting = true
					want = ErrManagedDNS
				case "identity":
					want = ErrConflict
				}
				c := fixture(t, get("/zones/zone/dns_records/record", record))
				fields := ownedDNS("record", "new").DNSFields
				if variant == "identity" {
					fields.Name = "other.example.test"
				}
				var err error
				if operation == "update" {
					_, err = c.UpdateDNSRecord(context.Background(), "zone", "record", fields)
				} else {
					err = c.DeleteDNSRecord(context.Background(), "zone", "record")
				}
				requireKind(t, err, want)
			})
		}
	}
}

func TestDNSCreateConflictDoesNotAdopt(t *testing.T) {
	existing := ownedDNS("foreign", "v=spf1 ip4:192.0.2.1 -all")
	existing.Comment = ""
	c := fixture(t, get("/zones/zone/dns_records", []DNSRecord{existing}))
	_, err := c.CreateDNSRecord(context.Background(), "zone", ownedDNS("", "v=spf1 -all").DNSFields)
	requireKind(t, err, ErrConflict)
}

func TestDNSRollbackPreservesOtherOwners(t *testing.T) {
	ctx := context.Background()
	before := ownedDNS("old", "before")
	changed := ownedDNS("old", "changed")
	created := ownedDNS("new", "created")
	foreign := ownedDNS("foreign", "foreign")
	foreign.Comment = "operator owned"
	restore := exchange{method: "PUT", path: "/zones/zone/dns_records/old", result: before, check: bodyIs(before.DNSFields)}
	c := fixture(t,
		get("/zones/zone/dns_records", []DNSRecord{before, foreign}),
		get("/zones/zone/dns_records", []DNSRecord{changed, created, foreign}),
		get("/zones/zone/dns_records/old", changed), restore,
		get("/zones/zone/dns_records/new", created), del("/zones/zone/dns_records/new"))
	snapshot, err := c.SnapshotDNS(ctx, "zone")
	if err != nil || len(snapshot.Records) != 1 || snapshot.Records[0].ID != "old" {
		t.Fatalf("snapshot selected foreign records: %+v %v", snapshot, err)
	}
	restored, err := c.RestoreDNS(ctx, snapshot)
	if err != nil || !reflect.DeepEqual(restored.Records[0], before) {
		t.Fatalf("restore failed: %+v %v", restored, err)
	}
}

func TestDNSRollbackRecreationAndOwnershipDrift(t *testing.T) {
	t.Run("new ID returned", func(t *testing.T) {
		old := ownedDNS("old", "before")
		recreated := old
		recreated.ID = "recreated"
		c := fixture(t, get("/zones/zone/dns_records", []DNSRecord{}),
			get("/zones/zone/dns_records", []DNSRecord{}),
			post("/zones/zone/dns_records", recreated))
		result, err := c.RestoreDNS(context.Background(), DNSSnapshot{ZoneID: "zone", OwnerID: "fixture", Records: []DNSRecord{old}})
		if err != nil || result.Records[0].ID != "recreated" {
			t.Fatalf("lost new rollback ID: %+v %v", result, err)
		}
	})
	t.Run("changed owner refuses all writes", func(t *testing.T) {
		old := ownedDNS("old", "before")
		drifted := old
		drifted.Comment = "new owner"
		c := fixture(t, get("/zones/zone/dns_records", []DNSRecord{drifted}))
		_, err := c.RestoreDNS(context.Background(), DNSSnapshot{ZoneID: "zone", OwnerID: "fixture", Records: []DNSRecord{old}})
		requireKind(t, err, ErrOwnership)
	})
	t.Run("wrong snapshot namespace", func(t *testing.T) {
		c := fixture(t)
		_, err := c.RestoreDNS(context.Background(), DNSSnapshot{ZoneID: "zone", OwnerID: "someone-else"})
		requireKind(t, err, ErrOwnership)
	})
}

func TestDNSDeleteAlreadyAbsent(t *testing.T) {
	c := fixture(t, exchange{method: http.MethodGet, path: "/zones/zone/dns_records/gone", status: 404})
	if err := c.DeleteDNSRecord(context.Background(), "zone", "gone"); err != nil {
		t.Fatal(err)
	}
}
