package cloudflare

import (
	"context"
	"net/http"
	"strings"
	"time"
)

type SendingDomain struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	Enabled          bool   `json:"enabled"`
	ReturnPathDomain string `json:"return_path_domain"`
	DKIMSelector     string `json:"dkim_selector"`
}

type DNSCheckIssue struct {
	Code    string     `json:"code"`
	Missing *DNSFields `json:"missing,omitempty"`
}

type DNSCheck struct {
	Records []DNSFields     `json:"records"`
	Errors  []DNSCheckIssue `json:"errors"`
	Status  string          `json:"status,omitempty"`
}

// SendingReceipt is creation evidence, stored by the caller with its snapshot.
// It must only originate from OnboardSendingDomain, never from user input.
// Cloudflare's locked cf-bounce records cannot carry our ownership comment.
type SendingReceipt struct {
	OwnerID string        `json:"ownerId"`
	ZoneID  string        `json:"zoneId"`
	Domain  SendingDomain `json:"domain"`
	// DMARC is set only when the name had no _dmarc record of any type just
	// before onboarding and the preview said Email Sending adds one.
	// nil (a receipt from before build 52, or a _dmarc that already existed)
	// keeps every _dmarc record on rollback.
	DMARC *SendingDMARC `json:"dmarc,omitempty"`
}

// SendingDMARC is the _dmarc TXT record Email Sending adds when it enables a
// name ("v=DMARC1; p=reject;"). Cloudflare does not delete it with the
// sender, and it carries no ownership marker: the rollback deletes it only
// while it is still the one record at that name with this exact content.
type SendingDMARC struct {
	Name    string `json:"name"`
	Content string `json:"content"`
}

func sendingPath(zoneID string, suffix ...string) (string, error) {
	return path(append([]string{"zones", zoneID, "email", "sending", "subdomains"}, suffix...)...)
}

func (c *Client) ListSendingDomains(ctx context.Context, zoneID string) ([]SendingDomain, error) {
	p, err := sendingPath(zoneID)
	if err != nil {
		return nil, err
	}
	return list[SendingDomain](ctx, c, p, nil, PermissionSendingRead, PermissionSendingWrite)
}

func (c *Client) GetSendingDomain(ctx context.Context, zoneID, id string) (SendingDomain, error) {
	p, err := sendingPath(zoneID, id)
	if err != nil {
		return SendingDomain{}, err
	}
	var result SendingDomain
	_, err = c.request(ctx, http.MethodGet, p, nil, nil, &result, PermissionSendingRead, PermissionSendingWrite)
	return result, err
}

func (c *Client) PreviewSendingDomain(ctx context.Context, zoneID, domain string) (DNSCheck, error) {
	name, err := domainName(domain)
	if err != nil {
		return DNSCheck{}, err
	}
	p, err := sendingPath(zoneID, "preview")
	if err != nil {
		return DNSCheck{}, err
	}
	var result DNSCheck
	_, err = c.request(ctx, http.MethodPost, p, nil, map[string]string{"name": name}, &result, PermissionSendingRead, PermissionSendingWrite)
	return result, err
}

// OnboardSendingDomain creates a new sending domain only. Existing (including
// disabled) senders are refused, since create would otherwise re-enable them.
// Cloudflare creates its locked DNS itself; this client never PATCHes those.
func (c *Client) OnboardSendingDomain(ctx context.Context, zoneID, domain string) (SendingReceipt, error) {
	name, err := domainName(domain)
	if err != nil {
		return SendingReceipt{}, err
	}
	zone, err := c.GetZone(ctx, zoneID)
	if err != nil {
		return SendingReceipt{}, err
	}
	if !inZone(name, zone.Name) {
		return SendingReceipt{}, invalid("sending domain outside zone")
	}
	existing, err := c.ListSendingDomains(ctx, zoneID)
	if err != nil {
		return SendingReceipt{}, err
	}
	for _, item := range existing {
		if strings.EqualFold(item.Name, name) {
			return SendingReceipt{}, conflict("existing sending domain")
		}
	}
	preview, err := c.PreviewSendingDomain(ctx, zoneID, name)
	if err != nil {
		return SendingReceipt{}, err
	}
	for _, issue := range preview.Errors {
		if !strings.HasSuffix(issue.Code, ".missing") {
			return SendingReceipt{}, conflict("sending DNS preview")
		}
	}
	records, err := c.ListDNSRecords(ctx, zoneID)
	if err != nil {
		return SendingReceipt{}, err
	}
	var dmarc *SendingDMARC
	for _, need := range preview.Records {
		// DMARC is advisory and the service preserves an existing policy (E1).
		if strings.HasPrefix(need.Name, "_dmarc.") {
			if dnsName(need.Name) == "_dmarc."+name && need.Type == "TXT" && dmarcText(need.Content) != "" && !hasName(records, need.Name) {
				dmarc = &SendingDMARC{Name: "_dmarc." + name, Content: need.Content}
			}
			continue
		}
		for _, old := range records {
			if old.Type == need.Type && strings.EqualFold(strings.TrimSuffix(old.Name, "."), strings.TrimSuffix(need.Name, ".")) {
				return SendingReceipt{}, conflict("existing sending DNS")
			}
		}
	}
	p, _ := sendingPath(zoneID)
	var result SendingDomain
	_, err = c.request(ctx, http.MethodPost, p, nil, map[string]string{"name": name}, &result, PermissionSendingWrite)
	if err != nil {
		return SendingReceipt{}, err
	}
	if !identifier.MatchString(result.ID) || result.Name != name {
		return SendingReceipt{}, &Error{Kind: ErrProtocol, Operation: "created sending domain"}
	}
	return SendingReceipt{OwnerID: c.owner, ZoneID: zoneID, Domain: result, DMARC: dmarc}, nil
}

// dnsName is a DNS name compared case-insensitively, without the root dot.
func dnsName(n string) string { return strings.ToLower(strings.TrimSuffix(n, ".")) }

func hasName(records []DNSRecord, name string) bool {
	for _, r := range records {
		if dnsName(r.Name) == dnsName(name) {
			return true
		}
	}
	return false
}

// dmarcText is a TXT content as compared: without surrounding whitespace and
// the quotes Cloudflare may wrap it in.
func dmarcText(content string) string {
	t := strings.TrimSpace(content)
	if len(t) >= 2 && t[0] == '"' && t[len(t)-1] == '"' {
		t = strings.TrimSpace(t[1 : len(t)-1])
	}
	return t
}

func (c *Client) SendingDNS(ctx context.Context, zoneID, id string) ([]DNSFields, error) {
	p, err := sendingPath(zoneID, id, "dns")
	if err != nil {
		return nil, err
	}
	var records []DNSFields
	_, err = c.request(ctx, http.MethodGet, p, nil, nil, &records, PermissionSendingRead, PermissionSendingWrite)
	return records, err
}

func (c *Client) SendingDNSStatus(ctx context.Context, zoneID, id string) (DNSCheck, error) {
	p, err := sendingPath(zoneID, id, "dns", "status")
	if err != nil {
		return DNSCheck{}, err
	}
	var result DNSCheck
	_, err = c.request(ctx, http.MethodGet, p, nil, nil, &result, PermissionSendingRead, PermissionSendingWrite)
	return result, err
}

// PollSendingVerification performs at most attempts reads and respects context
// cancellation. The wizard can instead call SendingDNSStatus once per UI poll.
// A non-ready result after the budget is exhausted is returned without error;
// callers must inspect Status == "ready" AND len(Errors) == 0.
func (c *Client) PollSendingVerification(ctx context.Context, zoneID, id string, interval time.Duration, attempts int) (DNSCheck, error) {
	if attempts < 1 || attempts > 60 || interval < time.Millisecond || interval > 30*time.Second {
		return DNSCheck{}, invalid("verification poll budget")
	}
	var result DNSCheck
	for i := 0; i < attempts; i++ {
		if i > 0 {
			timer := time.NewTimer(interval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return result, ctx.Err()
			case <-timer.C:
			}
		}
		var err error
		result, err = c.SendingDNSStatus(ctx, zoneID, id)
		if err != nil {
			return result, err
		}
		if result.Status == "ready" && len(result.Errors) == 0 {
			return result, nil
		}
	}
	return result, nil
}

func (c *Client) RollbackSendingDomain(ctx context.Context, receipt SendingReceipt) error {
	if receipt.OwnerID != c.owner || receipt.Domain.ID == "" || receipt.Domain.Name == "" {
		return ownership("sending receipt")
	}
	current, err := c.GetSendingDomain(ctx, receipt.ZoneID, receipt.Domain.ID)
	if IsKind(err, ErrNotFound) {
		// Gone already (or deleted by an earlier attempt): the DMARC record
		// it left may still be there.
		return c.removeSendingDMARC(ctx, receipt)
	}
	if err != nil {
		return err
	}
	if current.ID != receipt.Domain.ID || current.Name != receipt.Domain.Name {
		return ownership("sending domain")
	}
	p, _ := sendingPath(receipt.ZoneID, receipt.Domain.ID)
	if _, err = c.request(ctx, http.MethodDelete, p, nil, nil, nil, PermissionSendingWrite); err != nil {
		return err
	}
	return c.removeSendingDMARC(ctx, receipt)
}

// removeSendingDMARC deletes the _dmarc record Email Sending added when the
// sender was enabled, only when the receipt says no _dmarc record
// existed before and the name now holds exactly one record, a TXT whose
// content is unchanged. Anything else (another record, an edited policy, a
// locked record, an older receipt) is kept. A record already gone is done.
func (c *Client) removeSendingDMARC(ctx context.Context, receipt SendingReceipt) error {
	d := receipt.DMARC
	if d == nil || d.Name == "" || dmarcText(d.Content) == "" {
		return nil
	}
	records, err := c.ListDNSRecords(ctx, receipt.ZoneID)
	if err != nil {
		return err
	}
	var found []DNSRecord
	for _, r := range records {
		if dnsName(r.Name) == dnsName(d.Name) {
			found = append(found, r)
		}
	}
	if len(found) != 1 {
		return nil
	}
	r := found[0]
	if r.Type != "TXT" || dmarcText(r.Content) != dmarcText(d.Content) || r.Meta.ReadOnly || r.Meta.EmailRouting || !identifier.MatchString(r.ID) {
		return nil
	}
	p, err := dnsPath(receipt.ZoneID, r.ID)
	if err != nil {
		return err
	}
	_, err = c.request(ctx, http.MethodDelete, p, nil, nil, nil, PermissionDNSWrite)
	if IsKind(err, ErrNotFound) {
		return nil
	}
	return err
}

// SendMessage sends one plain-text message through Email Sending (account
// API). Setup uses it only for the inbound delivery check, from an onboarded
// sender on the mail domain to one routed address.
// It returns the Message-ID Cloudflare assigned.
func (c *Client) SendMessage(ctx context.Context, accountID, from, to, subject, text string) (string, error) {
	from, err := exactAddress(from)
	if err != nil {
		return "", err
	}
	to, err = exactAddress(to)
	if err != nil {
		return "", err
	}
	if subject == "" || len(subject) > 200 || strings.ContainsAny(subject, "\r\n") || len(text) > 4096 {
		return "", invalid("message")
	}
	p, err := path("accounts", accountID, "email", "sending", "send")
	if err != nil {
		return "", err
	}
	body := map[string]any{"from": from, "to": []string{to}, "subject": subject, "text": text}
	var result struct {
		MessageID string `json:"message_id"`
	}
	if _, err = c.request(ctx, http.MethodPost, p, nil, body, &result, PermissionSendingWrite); err != nil {
		return "", err
	}
	if result.MessageID == "" || len(result.MessageID) > 998 || strings.ContainsAny(result.MessageID, "\r\n") {
		return "", &Error{Kind: ErrProtocol, Operation: "send message"}
	}
	return result.MessageID, nil
}
