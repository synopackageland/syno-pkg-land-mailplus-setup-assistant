package cloudflare

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"mime/multipart"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"slices"
	"strings"
)

//go:embed inbound-worker.mjs
var inboundWorker string

// InboundWorkerSource is the exact source sent in the multipart upload.
func InboundWorkerSource() string { return inboundWorker }

type Tunnel struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Status    string `json:"status"`
	ConfigSrc string `json:"config_src"`
}

// Connector is one cloudflared process of a tunnel and its edge connections.
type Connector struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	Conns   []struct {
		OriginIP string `json:"origin_ip"`
	} `json:"conns"`
}

// ConnectPrefix names tunnels created by Syno Connect. They are discovered and
// may carry the VPC Service, but nothing here changes any tunnel.
const ConnectPrefix = "synopkgconnect-"

// ListTunnels lists the account's tunnels that are not deleted. There is
// deliberately no tunnel create, configure, route, credential or delete API.
func (c *Client) ListTunnels(ctx context.Context, accountID string) ([]Tunnel, error) {
	p, err := path("accounts", accountID, "cfd_tunnel")
	if err != nil {
		return nil, err
	}
	return list[Tunnel](ctx, c, p, url.Values{"is_deleted": {"false"}}, PermissionTunnelRead)
}

// TunnelConnectors reads which public IPs a tunnel's connectors come from.
func (c *Client) TunnelConnectors(ctx context.Context, accountID, tunnelID string) ([]Connector, error) {
	if !identifier.MatchString(tunnelID) {
		return nil, invalid("tunnel")
	}
	p, err := path("accounts", accountID, "cfd_tunnel", tunnelID, "connections")
	if err != nil {
		return nil, err
	}
	var result []Connector
	_, err = c.request(ctx, http.MethodGet, p, nil, nil, &result, PermissionTunnelRead)
	return result, err
}

// healthyTunnel refuses a tunnel that is absent or not healthy now.
func (c *Client) healthyTunnel(ctx context.Context, accountID, tunnelID string) error {
	items, err := c.ListTunnels(ctx, accountID)
	if err != nil {
		return err
	}
	for _, item := range items {
		if item.ID == tunnelID {
			if item.Status != "healthy" {
				return conflict("tunnel not healthy")
			}
			return nil
		}
	}
	return &Error{Kind: ErrNotFound, Operation: "tunnel"}
}

// PrivateIPv4 accepts only an RFC 1918 unicast IPv4 address. Loopback is
// refused on purpose: MailPlus's Postfix trusts 127.0.0.0/8 and would relay
// anything the Worker hands it. Link-local, public, CGNAT and
// IPv6 targets are refused too.
func PrivateIPv4(host string) (string, bool) {
	ip := net.ParseIP(host)
	if ip == nil || ip.To4() == nil || strings.Contains(host, ":") {
		return "", false
	}
	ip = ip.To4()
	if !ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip[3] == 0 || ip[3] == 255 {
		return "", false
	}
	return ip.String(), true
}

type VPCService struct {
	ServiceID string `json:"service_id"`
	Name      string `json:"name"`
	Type      string `json:"type"`
	TCPPort   int    `json:"tcp_port"`
	Host      struct {
		IPv4    string `json:"ipv4,omitempty"`
		IPv6    string `json:"ipv6,omitempty"`
		Network struct {
			TunnelID string `json:"tunnel_id"`
		} `json:"network"`
	} `json:"host"`
}

func vpcPath(accountID string, suffix ...string) (string, error) {
	return path(append([]string{"accounts", accountID, "connectivity", "directory", "services"}, suffix...)...)
}

func (c *Client) VPCServiceName() string { return c.resourceName() + "-smtp" }

func (c *Client) ListVPCServices(ctx context.Context, accountID string) ([]VPCService, error) {
	p, err := vpcPath(accountID)
	if err != nil {
		return nil, err
	}
	return list[VPCService](ctx, c, p, nil, PermissionVPCRead, PermissionVPCWrite)
}

func (c *Client) GetVPCService(ctx context.Context, accountID, id string) (VPCService, error) {
	p, err := vpcPath(accountID, id)
	if err != nil {
		return VPCService{}, err
	}
	var result VPCService
	_, err = c.request(ctx, http.MethodGet, p, nil, nil, &result, PermissionVPCRead, PermissionVPCWrite)
	return result, err
}

// owned is this owner's SMTP service: name, TCP 25, a private IPv4 host.
func (c *Client) owned(s VPCService) bool {
	_, private := PrivateIPv4(s.Host.IPv4)
	return s.Name == c.VPCServiceName() && s.Type == "tcp" && s.TCPPort == 25 && private && s.Host.IPv6 == ""
}

// FindVPCService returns this owner's service, if any (for reconciliation
// after a lost reply).
func (c *Client) FindVPCService(ctx context.Context, accountID string) (VPCService, bool, error) {
	items, err := c.ListVPCServices(ctx, accountID)
	if err != nil {
		return VPCService{}, false, err
	}
	for _, item := range items {
		if item.Name == c.VPCServiceName() {
			if !c.owned(item) {
				return VPCService{}, false, ownership("VPC service")
			}
			return item, true, nil
		}
	}
	return VPCService{}, false, nil
}

// CreateVPCService registers SMTP TCP 25 on host (a private NAS IPv4) through
// a healthy tunnel. It never changes the tunnel itself.
func (c *Client) CreateVPCService(ctx context.Context, accountID, tunnelID, host string) (VPCService, error) {
	ipv4, ok := PrivateIPv4(host)
	if !ok || !identifier.MatchString(tunnelID) {
		return VPCService{}, invalid("VPC SMTP host or tunnel")
	}
	if err := c.healthyTunnel(ctx, accountID, tunnelID); err != nil {
		return VPCService{}, err
	}
	if _, found, err := c.FindVPCService(ctx, accountID); err != nil {
		return VPCService{}, err
	} else if found {
		return VPCService{}, conflict("existing VPC service")
	}
	host4 := map[string]any{"ipv4": ipv4, "network": map[string]string{"tunnel_id": tunnelID}}
	body := map[string]any{"name": c.VPCServiceName(), "type": "tcp", "tcp_port": 25, "host": host4}
	p, _ := vpcPath(accountID)
	var result VPCService
	_, err := c.request(ctx, http.MethodPost, p, nil, body, &result, PermissionVPCWrite)
	return result, err
}

func (c *Client) DeleteVPCService(ctx context.Context, accountID, id string) error {
	current, err := c.GetVPCService(ctx, accountID, id)
	if IsKind(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if current.ServiceID != id || !c.owned(current) {
		return ownership("VPC service")
	}
	p, _ := vpcPath(accountID, id)
	_, err = c.request(ctx, http.MethodDelete, p, nil, nil, nil, PermissionVPCWrite)
	return err
}

type WorkerBinding struct {
	Type      string `json:"type"`
	Name      string `json:"name"`
	ServiceID string `json:"service_id,omitempty"`
	// JSON is the binding's value as JSON (an object here), never a string:
	// a string would reach the Worker as a string (build 27 on a test NAS:
	// env.CONFIG.recipients was undefined and every message threw).
	JSON json.RawMessage `json:"json,omitempty"`
}

type Worker struct {
	ID   string   `json:"id"`
	Tags []string `json:"tags"`
}

// WorkerConfig delivers straight to MailPlus through one owned VPC Service.
// There is no spool: a failure before MailPlus's final 250 makes Cloudflare
// answer the sender with a temporary error, and the sender retries.
type WorkerConfig struct {
	ServiceID  string
	EHLODomain string
	// Domain is the relay guard: the Worker hands on only recipients whose
	// domain is exactly this one (a plain local part, no "%" or "!"), and
	// MailPlus, final destination for it, decides whether the user exists.
	Domain   string
	MaxBytes int // 1..25 MiB; MailPlus's advertised SIZE when lower
}

func (c *Client) WorkerName() string { return c.resourceName() + "-inbound" }

func (c *Client) ListWorkers(ctx context.Context, accountID string) ([]Worker, error) {
	p, err := path("accounts", accountID, "workers", "scripts")
	if err != nil {
		return nil, err
	}
	return list[Worker](ctx, c, p, nil, PermissionWorkersRead, PermissionWorkersWrite)
}

// FindWorker reports whether this owner's tagged Worker exists.
func (c *Client) FindWorker(ctx context.Context, accountID string) (bool, error) {
	workers, err := c.ListWorkers(ctx, accountID)
	if err != nil {
		return false, err
	}
	for _, worker := range workers {
		if worker.ID == c.WorkerName() {
			if !slices.Contains(worker.Tags, c.marker()) {
				return false, ownership("Worker")
			}
			return true, nil
		}
	}
	return false, nil
}

func (c *Client) workerBindings(ctx context.Context, accountID string, cfg WorkerConfig) ([]WorkerBinding, error) {
	if !identifier.MatchString(cfg.ServiceID) || cfg.MaxBytes < 1 || cfg.MaxBytes > 25<<20 {
		return nil, invalid("worker bindings")
	}
	ehlo, err := domainName(cfg.EHLODomain)
	if err != nil {
		return nil, err
	}
	domain, err := domainName(cfg.Domain)
	if err != nil {
		return nil, err
	}
	service, err := c.GetVPCService(ctx, accountID, cfg.ServiceID)
	if err != nil {
		return nil, err
	}
	if service.ServiceID != cfg.ServiceID || !c.owned(service) {
		return nil, ownership("worker VPC service")
	}
	config, err := json.Marshal(struct {
		EHLO     string `json:"ehlo"`
		Domain   string `json:"domain"`
		MaxBytes int    `json:"maxBytes"`
	}{ehlo, domain, cfg.MaxBytes})
	if err != nil {
		return nil, invalid("worker configuration")
	}
	return []WorkerBinding{
		{Type: "vpc_service", Name: "NAS", ServiceID: cfg.ServiceID},
		{Type: "json", Name: "CONFIG", JSON: config},
	}, nil
}

// UploadWorker only creates or updates this owner's named, tagged Worker.
// It does not enable workers.dev or expose an HTTP endpoint.
func (c *Client) UploadWorker(ctx context.Context, accountID string, cfg WorkerConfig) (Worker, error) {
	bindings, err := c.workerBindings(ctx, accountID, cfg)
	if err != nil {
		return Worker{}, err
	}
	if _, err := c.FindWorker(ctx, accountID); err != nil {
		return Worker{}, err
	}
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	metadata, _ := json.Marshal(struct {
		MainModule        string          `json:"main_module"`
		CompatibilityDate string          `json:"compatibility_date"`
		Bindings          []WorkerBinding `json:"bindings"`
		Tags              []string        `json:"tags"`
	}{"inbound-worker.mjs", "2026-11-06", bindings, []string{c.marker()}})
	if err := writer.WriteField("metadata", string(metadata)); err != nil {
		return Worker{}, invalid("worker metadata")
	}
	headers := textproto.MIMEHeader{}
	headers.Set("Content-Disposition", `form-data; name="inbound-worker.mjs"; filename="inbound-worker.mjs"`)
	headers.Set("Content-Type", "application/javascript+module")
	part, err := writer.CreatePart(headers)
	if err != nil {
		return Worker{}, invalid("worker multipart")
	}
	if _, err = part.Write([]byte(inboundWorker)); err != nil {
		return Worker{}, invalid("worker source")
	}
	if err := writer.Close(); err != nil {
		return Worker{}, invalid("worker multipart")
	}
	p, err := path("accounts", accountID, "workers", "scripts", c.WorkerName())
	if err != nil {
		return Worker{}, err
	}
	var result Worker
	_, err = c.send(ctx, http.MethodPut, p, nil, &body, writer.FormDataContentType(), &result, PermissionWorkersWrite, PermissionVPCWrite)
	return result, err
}

func (c *Client) DeleteWorker(ctx context.Context, accountID string) error {
	found, err := c.FindWorker(ctx, accountID)
	if err != nil || !found {
		return err
	}
	p, _ := path("accounts", accountID, "workers", "scripts", c.WorkerName())
	_, err = c.request(ctx, http.MethodDelete, p, nil, nil, nil, PermissionWorkersWrite)
	return err
}
