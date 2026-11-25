package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

const fakeToken = "fixture-bearer-do-not-echo"

type exchange struct {
	method string
	path   string
	result any
	check  func(*testing.T, *http.Request)
	status int
	issues []apiIssue
	info   *resultInfo
	raw    string
	header http.Header
}

func fixture(t *testing.T, exchanges ...exchange) *Client {
	t.Helper()
	var mu sync.Mutex
	next := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if next >= len(exchanges) {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(500)
			return
		}
		e := exchanges[next]
		next++
		if r.Method != e.method || r.URL.Path != "/client/v4"+e.path {
			t.Errorf("request %d: got %s %s; want %s %s", next, r.Method, r.URL.Path, e.method, e.path)
		}
		if r.Header.Get("Authorization") != "Bearer "+fakeToken {
			t.Error("missing expected authorization")
		}
		if e.check != nil {
			e.check(t, r)
		}
		for key, values := range e.header {
			w.Header()[key] = values
		}
		w.Header().Set("Content-Type", "application/json")
		status := e.status
		if status == 0 {
			status = 200
		}
		w.WriteHeader(status)
		if e.raw != "" {
			_, _ = io.WriteString(w, e.raw)
			return
		}
		if status == 204 {
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": status < 300 && len(e.issues) == 0,
			"result":  e.result, "errors": e.issues, "result_info": e.info,
		})
	}))
	t.Cleanup(func() {
		server.Close()
		mu.Lock()
		defer mu.Unlock()
		if next != len(exchanges) {
			t.Errorf("used %d of %d expected requests", next, len(exchanges))
		}
	})
	client, err := New(Config{Token: fakeToken, OwnerID: "fixture", BaseURL: server.URL + "/client/v4", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func get(path string, result any) exchange {
	return exchange{method: "GET", path: path, result: result}
}
func post(path string, result any) exchange {
	return exchange{method: "POST", path: path, result: result}
}
func del(path string) exchange { return exchange{method: "DELETE", path: path, status: 204} }
func denied(path string) exchange {
	return exchange{method: "GET", path: path, status: 403, issues: []apiIssue{{Code: 10000, Message: "Permission denied " + fakeToken}}}
}

func bodyIs(want any) func(*testing.T, *http.Request) {
	return func(t *testing.T, r *http.Request) {
		t.Helper()
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		var actual, expected any
		if err := json.Unmarshal(b, &actual); err != nil {
			t.Fatal(err)
		}
		data, _ := json.Marshal(want)
		_ = json.Unmarshal(data, &expected)
		if !reflect.DeepEqual(actual, expected) {
			t.Errorf("request body differs: got %s; want %s", b, data)
		}
	}
}

func requireKind(t *testing.T, err error, kind ErrorKind) *Error {
	t.Helper()
	var typed *Error
	if !errors.As(err, &typed) || typed.Kind != kind {
		t.Fatalf("got error %v; want kind %s", err, kind)
	}
	return typed
}

func TestTokenPoliciesAndUnknownScopes(t *testing.T) {
	ctx := context.Background()
	t.Run("actual policies", func(t *testing.T) {
		token := Token{ID: "token", Status: "active", Policies: []TokenPolicy{{
			Effect: "allow", Resources: map[string]any{"com.cloudflare.api.account.acct": "*"},
			PermissionGroups: []PermissionGroup{{ID: "sending", Name: PermissionSendingWrite}},
		}}}
		c := fixture(t, get("/user/tokens/verify", Token{ID: "token", Status: "active"}),
			get("/user/tokens/token", token), get("/zones", []Zone{{ID: "zone", Name: "example.test"}}))
		access, err := c.InspectToken(ctx)
		if err != nil || !access.PoliciesKnown || len(access.Zones) != 1 ||
			access.PermissionState(PermissionSendingWrite) != "present" || access.PermissionState(PermissionDNSWrite) != "missing" {
			t.Fatalf("wrong policy inventory: %+v, %v", access, err)
		}
		if access.Token.Policies[0].Resources["com.cloudflare.api.account.acct"] != "*" {
			t.Fatal("lost resource scopes")
		}
	})
	t.Run("least privilege remains unknown", func(t *testing.T) {
		c := fixture(t, get("/user/tokens/verify", Token{ID: "token", Status: "active"}),
			denied("/user/tokens/token"), denied("/zones"))
		access, err := c.InspectToken(ctx)
		if err != nil || access.PoliciesKnown || access.PermissionState(PermissionDNSWrite) != "unknown" || access.ZonesError == nil {
			t.Fatalf("fabricated policy result: %+v, %v", access, err)
		}
		if strings.Contains(fmt.Sprintf("%+v %#v", access, access), fakeToken) {
			t.Fatal("upstream secret leaked through diagnostic data")
		}
	})
	t.Run("account token", func(t *testing.T) {
		c := fixture(t, get("/accounts/acct/tokens/verify", Token{ID: "token", Status: "active"}))
		c.tokenAccountID = "acct"
		if _, err := c.VerifyToken(ctx); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("inactive token", func(t *testing.T) {
		c := fixture(t, get("/user/tokens/verify", Token{ID: "token", Status: "expired"}))
		_, err := c.VerifyToken(ctx)
		requireKind(t, err, ErrAuth)
	})
}

func TestZonePaginationAndLongestSuffix(t *testing.T) {
	first := get("/zones", []Zone{{ID: "other", Name: "other.test"}})
	first.info = &resultInfo{TotalPages: 2}
	second := get("/zones", []Zone{{ID: "zone", Name: "example.co.uk"}})
	second.info = &resultInfo{TotalPages: 2}
	second.check = func(t *testing.T, r *http.Request) {
		if r.URL.Query().Get("page") != "2" {
			t.Error("did not advance page")
		}
	}
	c := fixture(t, first, second)
	zones, err := c.ListZones(context.Background())
	if err != nil || len(zones) != 2 {
		t.Fatalf("pagination: %v %v", zones, err)
	}
	for _, domain := range []string{"mail.example.co.uk", "MAIL.EXAMPLE.CO.UK."} {
		t.Run(domain, func(t *testing.T) {
			a := get("/zones", []Zone{})
			a.check = func(t *testing.T, r *http.Request) {
				if r.URL.Query().Get("name") != "mail.example.co.uk" {
					t.Error("wrong most-specific query")
				}
			}
			b := get("/zones", []Zone{{ID: "zone", Name: "example.co.uk"}})
			b.check = func(t *testing.T, r *http.Request) {
				if r.URL.Query().Get("name") != "example.co.uk" {
					t.Error("wrong parent query")
				}
			}
			c := fixture(t, a, b)
			zone, err := c.FindZone(context.Background(), domain)
			if err != nil || zone.ID != "zone" {
				t.Fatalf("find zone: %+v %v", zone, err)
			}
		})
	}
}

func TestTypedErrorsAndNoCredentialExposure(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		code    int
		message string
		want    ErrorKind
	}{
		{"auth", 401, 10000, "invalid token", ErrAuth},
		{"permission", 403, 10000, "missing permission", ErrPermission},
		{"not found", 404, 0, "not found", ErrNotFound},
		{"rate", 429, 0, "slow down", ErrRateLimit},
		{"plan", 403, 0, "Workers Paid entitlement required", ErrPlanLimit},
		{"managed", 400, 1046, "managed by Email Routing", ErrManagedDNS},
		{"conflict", 409, 0, "exists", ErrConflict},
		{"API", 500, 0, "failure", ErrAPI},
		{"success false", 200, 999, "failure", ErrAPI},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := fixture(t, exchange{method: "GET", path: "/zones", status: test.status,
				issues: []apiIssue{{Code: test.code, Message: test.message + " " + fakeToken}},
				header: http.Header{"Retry-After": {"7"}}})
			_, err := c.ListZones(context.Background())
			e := requireKind(t, err, test.want)
			if e.RetryAfter != 7*time.Second {
				t.Error("lost retry hint")
			}
			if test.want == ErrPermission && !reflect.DeepEqual(e.RequiredPermissions, []string{PermissionZoneRead}) {
				t.Error("lost operation permission")
			}
			b, _ := json.Marshal(e)
			if strings.Contains(string(b)+fmt.Sprintf("%v %+v %#v %#v", e, e, e, c), fakeToken) {
				t.Fatal("credential leak")
			}
		})
	}
}

func TestProtocolAndRedirectBoundaries(t *testing.T) {
	for _, raw := range []string{"not JSON " + fakeToken, `{"result":[]}`, `{"success":true,"result":null}`} {
		t.Run(raw[:min(len(raw), 16)], func(t *testing.T) {
			c := fixture(t, exchange{method: "GET", path: "/zones", raw: raw})
			_, err := c.ListZones(context.Background())
			requireKind(t, err, ErrProtocol)
		})
	}
	t.Run("no redirect follow", func(t *testing.T) {
		c := fixture(t, exchange{method: "GET", path: "/zones", status: 302,
			header: http.Header{"Location": {"/must-not-follow"}}})
		_, err := c.ListZones(context.Background())
		requireKind(t, err, ErrAPI)
	})
	t.Run("bad input makes no requests", func(t *testing.T) {
		c := fixture(t)
		_, err := c.GetZone(context.Background(), "../tokens")
		requireKind(t, err, ErrInvalid)
		_, err = c.FindZone(context.Background(), "bad.test/path")
		requireKind(t, err, ErrInvalid)
	})
	t.Run("transport drops unsafe error", func(t *testing.T) {
		c := fixture(t)
		c.http = doerFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New(fakeToken) })
		_, err := c.ListZones(context.Background())
		requireKind(t, err, ErrTransport)
		if strings.Contains(err.Error(), fakeToken) {
			t.Fatal("transport leaked secret")
		}
	})
}

type doerFunc func(*http.Request) (*http.Response, error)

func (f doerFunc) Do(r *http.Request) (*http.Response, error) { return f(r) }
