package cloudflare

import (
	"context"
	"net/http"
	"strings"
)

// Email Routing on a subdomain. Enabling it (EnableRouting with a
// subdomain: POST /zones/{zone}/email/routing/dns {"name": subdomain})
// makes Cloudflare add the subdomain's receiving records: three MX
// (route1–3.mx.cloudflare.net, flagged meta.email_routing and read_only) and
// one SPF TXT "v=spf1 include:_spf.mx.cloudflare.net ~all". Cloudflare documents no call that disables
// routing for one subdomain: DELETE /zones/{zone}/email/routing/dns takes no
// name and disables the whole zone. So the setup records, by ID, the records
// that appeared at the name when it enabled routing there, and removal
// deletes exactly those through the DNS records API, after
// UnlockSubdomainRouting when Email Routing's lock refuses an MX.

// MailRecordsAt lists the MX and SPF TXT records at name (read-only, every
// owner).
func (c *Client) MailRecordsAt(ctx context.Context, zoneID, name string) ([]DNSRecord, error) {
	all, err := c.ListDNSRecords(ctx, zoneID)
	if err != nil {
		return nil, err
	}
	out := []DNSRecord{}
	for _, r := range all {
		if strings.EqualFold(strings.TrimSuffix(r.Name, "."), strings.TrimSuffix(name, ".")) && (r.Type == "MX" || r.Type == "TXT" && isSPF(r.Content)) {
			out = append(out, r)
		}
	}
	return out, nil
}

// SameRecord reports whether a record still has the shape recorded: type,
// name, content and MX priority.
func SameRecord(a, b DNSRecord) bool {
	pa, pb := -1, -1
	if a.Priority != nil {
		pa = *a.Priority
	}
	if b.Priority != nil {
		pb = *b.Priority
	}
	return a.ID == b.ID && a.Type == b.Type && strings.EqualFold(strings.TrimSuffix(a.Name, "."), strings.TrimSuffix(b.Name, ".")) &&
		strings.Trim(a.Content, `"`) == strings.Trim(b.Content, `"`) && pa == pb
}

// DeleteRecordedDNS deletes one record the setup recorded creating, by its
// ID, only while it still has the recorded shape. A record already gone, or
// one somebody changed since (theirs now), is left: deleted reports whether
// a delete was sent. Cloudflare's lock on Email Routing's records is not
// lifted here (the caller unlocks the subdomain and calls again): a refusal
// (code 1046, "managed by Email Routing") is returned as ErrManagedDNS.
func (c *Client) DeleteRecordedDNS(ctx context.Context, zoneID string, want DNSRecord) (deleted bool, err error) {
	if !identifier.MatchString(want.ID) {
		return false, invalid("DNS record ID")
	}
	current, err := c.getDNS(ctx, zoneID, want.ID)
	if IsKind(err, ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !SameRecord(current, want) {
		return false, nil
	}
	p, _ := dnsPath(zoneID, want.ID)
	if _, err := c.request(ctx, http.MethodDelete, p, nil, nil, nil, PermissionDNSWrite); err != nil {
		if IsKind(err, ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// RestoreRecordedDNS puts back the content a record had before the setup
// (a record enabling routing changed), only while it still has the content
// the setup left; gone or changed since, it is left as it is.
func (c *Client) RestoreRecordedDNS(ctx context.Context, zoneID string, before, after DNSRecord) (restored bool, err error) {
	if !identifier.MatchString(before.ID) || before.ID != after.ID {
		return false, invalid("DNS record ID")
	}
	current, err := c.getDNS(ctx, zoneID, before.ID)
	if IsKind(err, ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !SameRecord(current, after) || SameRecord(current, before) {
		return false, nil
	}
	fields := before.DNSFields
	if fields.Tags == nil {
		fields.Tags = []string{}
	}
	p, _ := dnsPath(zoneID, before.ID)
	_, err = c.request(ctx, http.MethodPut, p, nil, fields, nil, PermissionDNSWrite)
	return err == nil, err
}
