package cloudflare

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"reflect"
	"strings"
)

type DNSFields struct {
	Type     string          `json:"type"`
	Name     string          `json:"name"`
	Content  string          `json:"content,omitempty"`
	TTL      int             `json:"ttl"`
	Priority *int            `json:"priority,omitempty"`
	Proxied  *bool           `json:"proxied,omitempty"`
	Comment  string          `json:"comment"`
	Tags     []string        `json:"tags"` // [] clears tags on restore
	Data     json.RawMessage `json:"data,omitempty"`
	Settings json.RawMessage `json:"settings,omitempty"`
}

type DNSRecord struct {
	DNSFields
	ID   string `json:"id"`
	Meta struct {
		ReadOnly     bool `json:"read_only"`
		EmailRouting bool `json:"email_routing"`
	} `json:"meta"`
}

// DNSSnapshot is a single owner's full zone record set, not a zone-wide backup.
// Keep it in private wizard state. Restore requires exclusive use of OwnerID.
type DNSSnapshot struct {
	ZoneID  string      `json:"zoneId"`
	OwnerID string      `json:"ownerId"`
	Records []DNSRecord `json:"records"`
}

func dnsPath(zoneID string, suffix ...string) (string, error) {
	return path(append([]string{"zones", zoneID, "dns_records"}, suffix...)...)
}

// ListDNSRecords is read-only and includes other owners for diagnostics and
// conflict previews. Only ListOwnedDNSRecords can be used as a change set.
func (c *Client) ListDNSRecords(ctx context.Context, zoneID string) ([]DNSRecord, error) {
	p, err := dnsPath(zoneID)
	if err != nil {
		return nil, err
	}
	return list[DNSRecord](ctx, c, p, nil, PermissionDNSRead, PermissionDNSWrite)
}

// ListNSRecords lists the zone's NS records only (the apex's and any
// delegation of a name under it). Read-only, every owner.
func (c *Client) ListNSRecords(ctx context.Context, zoneID string) ([]DNSRecord, error) {
	p, err := dnsPath(zoneID)
	if err != nil {
		return nil, err
	}
	return list[DNSRecord](ctx, c, p, url.Values{"type": {"NS"}}, PermissionDNSRead, PermissionDNSWrite)
}

func (c *Client) ListOwnedDNSRecords(ctx context.Context, zoneID string) ([]DNSRecord, error) {
	items, err := c.ListDNSRecords(ctx, zoneID)
	if err != nil {
		return nil, err
	}
	var owned []DNSRecord
	for _, record := range items {
		if record.Comment == c.marker() {
			owned = append(owned, record)
		}
	}
	return owned, nil
}

func (c *Client) getDNS(ctx context.Context, zoneID, id string) (DNSRecord, error) {
	p, err := dnsPath(zoneID, id)
	if err != nil {
		return DNSRecord{}, err
	}
	var record DNSRecord
	_, err = c.request(ctx, http.MethodGet, p, nil, nil, &record, PermissionDNSRead, PermissionDNSWrite)
	if err == nil && record.ID != id {
		err = &Error{Kind: ErrProtocol, Operation: "DNS record ID"}
	}
	return record, err
}

func (c *Client) editableDNS(record DNSRecord) error {
	if record.Comment != c.marker() {
		return ownership("DNS record")
	}
	if record.Meta.ReadOnly || record.Meta.EmailRouting {
		return &Error{Kind: ErrManagedDNS, Operation: "DNS record"}
	}
	return nil
}

func (c *Client) dnsFields(fields DNSFields) (DNSFields, error) {
	// Restrict the mutable surface to mail DNS; unsupported structured records
	// are readable but not rewritten with a lossy payload.
	switch fields.Type {
	case "A", "AAAA", "CNAME", "MX", "TXT":
	default:
		return fields, invalid("mail DNS type")
	}
	name := strings.ToLower(strings.TrimSuffix(fields.Name, "."))
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			return fields, invalid("DNS name")
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '_') {
				return fields, invalid("DNS name (use IDNA ASCII form)")
			}
		}
	}
	if len(name) > 253 || fields.Content == "" || fields.TTL < 1 ||
		(fields.Type == "MX" && (fields.Priority == nil || *fields.Priority < 0 || *fields.Priority > 65535)) ||
		(fields.Proxied != nil && *fields.Proxied) {
		return fields, invalid("mail DNS fields")
	}
	if fields.Comment != "" && fields.Comment != c.marker() {
		return fields, ownership("DNS comment")
	}
	fields.Name, fields.Comment = name, c.marker()
	if fields.Tags == nil {
		fields.Tags = []string{}
	}
	return fields, nil
}

func (c *Client) CreateDNSRecord(ctx context.Context, zoneID string, fields DNSFields) (DNSRecord, error) {
	fields, err := c.dnsFields(fields)
	if err != nil {
		return DNSRecord{}, err
	}
	p, err := dnsPath(zoneID)
	if err != nil {
		return DNSRecord{}, err
	}
	// Do not silently adopt a matching existing record. Same-type MX siblings
	// are fine; CNAME conflicts or duplicate SPF are refused before a write.
	existing, err := list[DNSRecord](ctx, c, p, url.Values{"name": {fields.Name}}, PermissionDNSRead, PermissionDNSWrite)
	if err != nil {
		return DNSRecord{}, err
	}
	for _, old := range existing {
		if !strings.EqualFold(strings.TrimSuffix(old.Name, "."), fields.Name) {
			continue
		}
		if old.Type == "CNAME" || fields.Type == "CNAME" ||
			old.Type == fields.Type && (old.Content == fields.Content ||
				fields.Type != "MX" && fields.Type != "TXT" ||
				fields.Type == "TXT" && isSPF(old.Content) && isSPF(fields.Content)) {
			return DNSRecord{}, conflict("existing DNS record")
		}
	}
	var record DNSRecord
	_, err = c.request(ctx, http.MethodPost, p, nil, fields, &record, PermissionDNSWrite)
	return record, err
}

func isSPF(content string) bool { return strings.HasPrefix(strings.Trim(content, "\" "), "v=spf1 ") }

func (c *Client) UpdateDNSRecord(ctx context.Context, zoneID, id string, fields DNSFields) (DNSRecord, error) {
	fields, err := c.dnsFields(fields)
	if err != nil {
		return DNSRecord{}, err
	}
	current, err := c.getDNS(ctx, zoneID, id)
	if err != nil {
		return DNSRecord{}, err
	}
	if err := c.editableDNS(current); err != nil {
		return DNSRecord{}, err
	}
	// Changing a record's identity could collide with someone else's records.
	if current.Type != fields.Type || !strings.EqualFold(strings.TrimSuffix(current.Name, "."), fields.Name) {
		return DNSRecord{}, conflict("DNS identity change")
	}
	p, _ := dnsPath(zoneID, id)
	var updated DNSRecord
	_, err = c.request(ctx, http.MethodPut, p, nil, fields, &updated, PermissionDNSWrite)
	return updated, err
}

func (c *Client) DeleteDNSRecord(ctx context.Context, zoneID, id string) error {
	record, err := c.getDNS(ctx, zoneID, id)
	if IsKind(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := c.editableDNS(record); err != nil {
		return err
	}
	p, _ := dnsPath(zoneID, id)
	_, err = c.request(ctx, http.MethodDelete, p, nil, nil, nil, PermissionDNSWrite)
	return err
}

func (c *Client) SnapshotDNS(ctx context.Context, zoneID string) (DNSSnapshot, error) {
	items, err := c.ListOwnedDNSRecords(ctx, zoneID)
	if err != nil {
		return DNSSnapshot{}, err
	}
	for _, item := range items {
		if err := c.editableDNS(item); err != nil {
			return DNSSnapshot{}, err
		}
		if _, err := c.dnsFields(item.DNSFields); err != nil {
			return DNSSnapshot{}, err
		}
	}
	return DNSSnapshot{ZoneID: zoneID, OwnerID: c.owner, Records: items}, nil
}

// RestoreDNS returns a refreshed snapshot because recreated record IDs change.
// Persist the returned snapshot even on error before trying rollback again.
// Ownership is re-read immediately before each mutation; Cloudflare offers no
// atomic comment compare-and-swap, so the wizard must serialize its own writes.
func (c *Client) RestoreDNS(ctx context.Context, snapshot DNSSnapshot) (DNSSnapshot, error) {
	if snapshot.OwnerID != c.owner {
		return snapshot, ownership("DNS snapshot")
	}
	if _, err := dnsPath(snapshot.ZoneID); err != nil {
		return snapshot, err
	}
	snapshot.Records = append([]DNSRecord(nil), snapshot.Records...)
	wanted := map[string]bool{}
	for _, item := range snapshot.Records {
		if wanted[item.ID] || !identifier.MatchString(item.ID) {
			return snapshot, invalid("DNS snapshot IDs")
		}
		if err := c.editableDNS(item); err != nil {
			return snapshot, err
		}
		if _, err := c.dnsFields(item.DNSFields); err != nil {
			return snapshot, err
		}
		wanted[item.ID] = true
	}
	current, err := c.ListDNSRecords(ctx, snapshot.ZoneID)
	if err != nil {
		return snapshot, err
	}
	byID := map[string]DNSRecord{}
	for _, item := range current {
		byID[item.ID] = item
		if wanted[item.ID] || item.Comment == c.marker() {
			if err := c.editableDNS(item); err != nil {
				return snapshot, err
			}
		}
	}
	// Restore old records first; refuse drift instead of deleting unrelated IDs.
	for i, old := range snapshot.Records {
		if now, exists := byID[old.ID]; exists {
			if reflect.DeepEqual(old.DNSFields, now.DNSFields) {
				continue
			}
			restored, err := c.UpdateDNSRecord(ctx, snapshot.ZoneID, old.ID, old.DNSFields)
			if err != nil {
				return snapshot, err
			}
			snapshot.Records[i] = restored
		} else {
			restored, err := c.CreateDNSRecord(ctx, snapshot.ZoneID, old.DNSFields)
			if err != nil {
				return snapshot, err
			}
			snapshot.Records[i] = restored
		}
	}
	for _, item := range current {
		if item.Comment == c.marker() && !wanted[item.ID] {
			if err := c.DeleteDNSRecord(ctx, snapshot.ZoneID, item.ID); err != nil {
				return snapshot, err
			}
		}
	}
	return snapshot, nil
}
