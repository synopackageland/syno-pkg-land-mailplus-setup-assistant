package cloudflare

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func healthy(name string) Tunnel { return Tunnel{ID: "tunnel", Name: name, Status: "healthy"} }

func smtpService() VPCService {
	v := VPCService{ServiceID: "service", Name: "syno-home-keeper-fixture-smtp", Type: "tcp", TCPPort: 25}
	v.Host.IPv4 = "192.168.1.20"
	v.Host.Network.TunnelID = "tunnel"
	return v
}

func workerConfig() WorkerConfig {
	return WorkerConfig{ServiceID: "service", EHLODomain: "mail.example.test",
		Domain: "mail.example.test", MaxBytes: 10 << 20}
}

func TestPrivateIPv4(t *testing.T) {
	for host, want := range map[string]bool{
		"192.168.1.20": true, "172.23.42.201": true, "172.16.0.5": true,
		"127.0.0.1": false, "169.254.1.1": false, "8.8.8.8": false, "100.64.0.1": false,
		"192.168.1.0": false, "192.168.1.255": false, "::1": false, "fd00::1": false, "::ffff:10.0.0.1": false, "": false, "nas": false,
	} {
		if _, ok := PrivateIPv4(host); ok != want {
			t.Errorf("%q: got %v want %v", host, ok, want)
		}
	}
}

func TestTunnelDiscovery(t *testing.T) {
	list := get("/accounts/acct/cfd_tunnel", []Tunnel{healthy(ConnectPrefix + "nas-1")})
	list.check = func(t *testing.T, r *http.Request) {
		if r.URL.Query().Get("is_deleted") != "false" {
			t.Error("deleted tunnels must not be listed")
		}
	}
	conns := get("/accounts/acct/cfd_tunnel/tunnel/connections", []map[string]any{{"id": "c", "version": "2026.10.5", "conns": []map[string]string{{"origin_ip": "203.0.113.7"}}}})
	c := fixture(t, list, conns)
	tunnels, err := c.ListTunnels(context.Background(), "acct")
	if err != nil || len(tunnels) != 1 {
		t.Fatal(err)
	}
	got, err := c.TunnelConnectors(context.Background(), "acct", "tunnel")
	if err != nil || len(got) != 1 || got[0].Conns[0].OriginIP != "203.0.113.7" || got[0].Version != "2026.10.5" {
		t.Fatalf("connectors: %+v %v", got, err)
	}
}

func TestVPCServiceOnConnectTunnelAndDelete(t *testing.T) {
	service := smtpService()
	create := post("/accounts/acct/connectivity/directory/services", service)
	create.check = bodyIs(map[string]any{"name": service.Name, "type": "tcp", "tcp_port": 25,
		"host": map[string]any{"ipv4": "192.168.1.20", "network": map[string]string{"tunnel_id": "tunnel"}}})
	// A Connect tunnel carries the service; the tunnel itself is never changed.
	c := fixture(t, get("/accounts/acct/cfd_tunnel", []Tunnel{healthy(ConnectPrefix + "nas-1")}),
		get("/accounts/acct/connectivity/directory/services", []VPCService{}), create,
		get("/accounts/acct/connectivity/directory/services/service", service),
		del("/accounts/acct/connectivity/directory/services/service"))
	created, err := c.CreateVPCService(context.Background(), "acct", "tunnel", "192.168.1.20")
	if err != nil || created.ServiceID != "service" {
		t.Fatalf("VPC service create: %+v %v", created, err)
	}
	if err := c.DeleteVPCService(context.Background(), "acct", "service"); err != nil {
		t.Fatal(err)
	}
}

func TestVPCServiceRefusals(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "169.254.10.2", "203.0.113.9", "fd00::25"} {
		t.Run("target "+host, func(t *testing.T) {
			_, err := fixture(t).CreateVPCService(context.Background(), "acct", "tunnel", host)
			requireKind(t, err, ErrInvalid)
		})
	}
	t.Run("unhealthy tunnel", func(t *testing.T) {
		down := healthy("own")
		down.Status = "down"
		c := fixture(t, get("/accounts/acct/cfd_tunnel", []Tunnel{down}))
		_, err := c.CreateVPCService(context.Background(), "acct", "tunnel", "192.168.1.20")
		requireKind(t, err, ErrConflict)
	})
	t.Run("existing owned service is not duplicated", func(t *testing.T) {
		c := fixture(t, get("/accounts/acct/cfd_tunnel", []Tunnel{healthy("own")}),
			get("/accounts/acct/connectivity/directory/services", []VPCService{smtpService()}))
		_, err := c.CreateVPCService(context.Background(), "acct", "tunnel", "192.168.1.20")
		requireKind(t, err, ErrConflict)
	})
	for _, name := range []string{"foreign", "wrong port", "loopback host"} {
		t.Run("delete "+name, func(t *testing.T) {
			service := smtpService()
			switch name {
			case "foreign":
				service.Name = "operator-service"
			case "wrong port":
				service.TCPPort = 22
			default:
				service.Host.IPv4 = "127.0.0.1"
			}
			c := fixture(t, get("/accounts/acct/connectivity/directory/services/service", service))
			requireKind(t, c.DeleteVPCService(context.Background(), "acct", "service"), ErrOwnership)
		})
	}
}

func TestWorkerMultipartAndRollback(t *testing.T) {
	worker := Worker{ID: "syno-home-keeper-fixture-inbound", Tags: []string{"syno-home-keeper:fixture"}}
	upload := exchange{method: "PUT", path: "/accounts/acct/workers/scripts/" + worker.ID, result: worker}
	upload.check = func(t *testing.T, r *http.Request) {
		reader, err := r.MultipartReader()
		if err != nil {
			t.Fatal(err)
		}
		parts, types := map[string]string{}, map[string]string{}
		for {
			part, err := reader.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			data, _ := io.ReadAll(part)
			parts[part.FormName()], types[part.FormName()] = string(data), part.Header.Get("Content-Type")
		}
		var metadata struct {
			MainModule string          `json:"main_module"`
			Bindings   []WorkerBinding `json:"bindings"`
			Tags       []string        `json:"tags"`
		}
		if err := json.Unmarshal([]byte(parts["metadata"]), &metadata); err != nil {
			t.Fatal(err)
		}
		if metadata.MainModule != "inbound-worker.mjs" || len(metadata.Bindings) != 2 ||
			metadata.Bindings[0].Type != "vpc_service" || metadata.Bindings[0].ServiceID != "service" ||
			metadata.Bindings[1].Type != "json" || len(metadata.Tags) != 1 || metadata.Tags[0] != worker.Tags[0] {
			t.Fatalf("wrong metadata: %+v", metadata)
		}
		// The exact metadata Cloudflare receives: the json binding's value
		// must be an object (a string reaches the Worker as a string).
		var raw map[string]any
		if err := json.Unmarshal([]byte(parts["metadata"]), &raw); err != nil {
			t.Fatal(err)
		}
		config, ok := raw["bindings"].([]any)[1].(map[string]any)["json"].(map[string]any)
		if !ok || config["maxBytes"] != float64(10<<20) || config["ehlo"] != "mail.example.test" ||
			config["domain"] != "mail.example.test" {
			t.Fatalf("CONFIG must be a JSON object: %s", parts["metadata"])
		}
		want := map[string]any{"main_module": "inbound-worker.mjs", "compatibility_date": "2026-11-06",
			"tags": []any{"syno-home-keeper:fixture"},
			"bindings": []any{
				map[string]any{"type": "vpc_service", "name": "NAS", "service_id": "service"},
				map[string]any{"type": "json", "name": "CONFIG", "json": map[string]any{
					"ehlo": "mail.example.test", "domain": "mail.example.test", "maxBytes": float64(10 << 20)}},
			}}
		if !reflect.DeepEqual(raw, want) {
			t.Fatalf("metadata:\n%s", parts["metadata"])
		}
		// The Worker harness (frontend/test/inbound-worker.test.ts) builds its
		// env from this exact metadata, the way the platform does.
		golden := filepath.Join("testdata", "inbound-upload-metadata.json")
		if os.Getenv("UPDATE_GOLDEN") != "" {
			_ = os.MkdirAll("testdata", 0o755)
			if err := os.WriteFile(golden, []byte(parts["metadata"]+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		saved, err := os.ReadFile(golden)
		var savedJSON any
		if err != nil || json.Unmarshal(saved, &savedJSON) != nil || !reflect.DeepEqual(savedJSON, any(raw)) {
			t.Fatalf("golden %s differs from the upload (UPDATE_GOLDEN=1 to refresh): %v", golden, err)
		}
		src := parts["inbound-worker.mjs"]
		if src != InboundWorkerSource() || types["inbound-worker.mjs"] != "application/javascript+module" {
			t.Fatal("source or module MIME mismatch")
		}
		// A VPC Service connect() without an argument throws.
		if !strings.Contains(src, `env.NAS.connect("nas:25")`) || strings.Contains(src, "env.NAS.connect()") {
			t.Error("connect() must pass an address")
		}
		for _, forbidden := range []string{"sample-nas", "example.org", "DIAGNOSTIC_TOKEN", "async fetch(", "console.log(", "SPOOL", "RETRY", "queue("} {
			if strings.Contains(src, forbidden) {
				t.Errorf("unexpected code remains: %s", forbidden)
			}
		}
	}
	c := fixture(t, get("/accounts/acct/connectivity/directory/services/service", smtpService()),
		get("/accounts/acct/workers/scripts", []Worker{}), upload,
		get("/accounts/acct/workers/scripts", []Worker{worker}),
		del("/accounts/acct/workers/scripts/"+worker.ID))
	if _, err := c.UploadWorker(context.Background(), "acct", workerConfig()); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteWorker(context.Background(), "acct"); err != nil {
		t.Fatal(err)
	}
}

func TestWorkerOwnership(t *testing.T) {
	t.Run("foreign VPC service cannot be bound", func(t *testing.T) {
		foreign := smtpService()
		foreign.Name = "operator-service"
		c := fixture(t, get("/accounts/acct/connectivity/directory/services/service", foreign))
		_, err := c.UploadWorker(context.Background(), "acct", workerConfig())
		requireKind(t, err, ErrOwnership)
	})
	t.Run("foreign Worker cannot be replaced", func(t *testing.T) {
		c := fixture(t, get("/accounts/acct/connectivity/directory/services/service", smtpService()),
			get("/accounts/acct/workers/scripts", []Worker{{ID: "syno-home-keeper-fixture-inbound"}}))
		_, err := c.UploadWorker(context.Background(), "acct", workerConfig())
		requireKind(t, err, ErrOwnership)
	})
	t.Run("foreign Worker cannot be deleted", func(t *testing.T) {
		c := fixture(t, get("/accounts/acct/workers/scripts", []Worker{{ID: "syno-home-keeper-fixture-inbound"}}))
		requireKind(t, c.DeleteWorker(context.Background(), "acct"), ErrOwnership)
	})
}

func TestSendMessage(t *testing.T) {
	send := post("/accounts/acct/email/sending/send", map[string]string{"message_id": "<id@example.test>"})
	send.check = bodyIs(map[string]any{"from": "postmaster@mail.example.test", "to": []string{"admin@mail.example.test"}, "subject": "check MPSA-1", "text": "x"})
	c := fixture(t, send)
	id, err := c.SendMessage(context.Background(), "acct", "postmaster@mail.example.test", "admin@mail.example.test", "check MPSA-1", "x")
	if err != nil || id != "<id@example.test>" {
		t.Fatalf("send: %q %v", id, err)
	}
	_, err = fixture(t).SendMessage(context.Background(), "acct", "a@b.test", "c@d.test", "bad\r\nsubject", "")
	requireKind(t, err, ErrInvalid)
}
