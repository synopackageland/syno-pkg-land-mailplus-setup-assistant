// Package cloudflare implements the mail wizard's Cloudflare API v4 boundary.
// It never logs credentials or responses, retries mutations, or configures tunnels.
package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const apiURL = "https://api.cloudflare.com/client/v4"
const maxResponse = 8 << 20
const maxPages = 1000

// HTTPDoer lets callers and tests replace all external requests.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// Config must come from the encrypted secret store, not wizard session JSON.
// OwnerID is a stable, nonsecret installation/wizard resource namespace.
// Use a distinct OwnerID for independently rolled-back DNS change sets.
type Config struct {
	Token          string
	OwnerID        string
	TokenAccountID string // set only for account-owned tokens
	BaseURL        string // empty in production; loopback HTTP allowed for fakes
	HTTPClient     HTTPDoer
}

type Client struct {
	token          string
	owner          string
	tokenAccountID string
	base           string
	http           HTTPDoer
}

var identifier = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
var ownerID = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)

func New(cfg Config) (*Client, error) {
	if strings.TrimSpace(cfg.Token) == "" || strings.ContainsAny(cfg.Token, "\r\n") {
		return nil, invalid("token")
	}
	if !ownerID.MatchString(cfg.OwnerID) {
		return nil, invalid("owner ID")
	}
	if cfg.TokenAccountID != "" && !identifier.MatchString(cfg.TokenAccountID) {
		return nil, invalid("token account ID")
	}
	base := strings.TrimRight(cfg.BaseURL, "/")
	if base == "" {
		base = apiURL
	}
	u, err := url.Parse(base)
	if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		u.Host == "" || (u.Scheme != "https" && !(u.Scheme == "http" &&
		(u.Hostname() == "127.0.0.1" || u.Hostname() == "::1" || u.Hostname() == "localhost"))) {
		return nil, invalid("API URL")
	}
	doer := cfg.HTTPClient
	if doer == nil {
		doer = &http.Client{Timeout: 30 * time.Second}
	}
	// Also disable redirects on caller-supplied standard clients. Redirects must
	// never replay a bearer token or transform a mutation into another request.
	if h, ok := doer.(*http.Client); ok {
		copy := *h
		copy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		if copy.Timeout == 0 {
			copy.Timeout = 30 * time.Second
		}
		doer = &copy
	}
	return &Client{token: cfg.Token, owner: cfg.OwnerID, tokenAccountID: cfg.TokenAccountID, base: base, http: doer}, nil
}

// String and GoString keep fmt/slog from exposing the private bearer token.
func (*Client) String() string   { return "cloudflare.Client{credentials:redacted}" }
func (*Client) GoString() string { return "cloudflare.Client{credentials:redacted}" }

func (c *Client) marker() string       { return "syno-home-keeper:" + c.owner }
func (c *Client) resourceName() string { return "syno-home-keeper-" + c.owner }

type resultInfo struct {
	Page       int    `json:"page"`
	PerPage    int    `json:"per_page"`
	TotalPages int    `json:"total_pages"`
	TotalCount int    `json:"total_count"`
	Cursor     string `json:"cursor"`
}

type envelope struct {
	Success    *bool           `json:"success"`
	Errors     []apiIssue      `json:"errors"`
	Result     json.RawMessage `json:"result"`
	ResultInfo resultInfo      `json:"result_info"`
}

// apiIssue is deliberately private: upstream messages may echo secrets.
type apiIssue struct {
	Code    int        `json:"code"`
	Message string     `json:"message"`
	Chain   []apiIssue `json:"error_chain"`
}

func (c *Client) request(ctx context.Context, method, path string, query url.Values, in, out any, permissions ...string) (resultInfo, error) {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return resultInfo{}, invalid("request")
		}
		body = bytes.NewReader(b)
	}
	return c.send(ctx, method, path, query, body, "application/json", out, permissions...)
}

func (c *Client) send(ctx context.Context, method, path string, query url.Values, body io.Reader, contentType string, out any, permissions ...string) (resultInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	target := c.base + path
	if len(query) != 0 {
		target += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return resultInfo{}, invalid("request")
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "SynoMailPlusSetupAssistant")
	if body != nil {
		req.Header.Set("Content-Type", contentType)
	}
	res, err := c.http.Do(req)
	if err != nil {
		// Do not wrap a transport error: custom transports can include headers.
		if ctx.Err() != nil {
			return resultInfo{}, ctx.Err()
		}
		return resultInfo{}, &Error{Kind: ErrTransport, Operation: method + " " + path}
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, maxResponse+1))
	if err != nil || len(b) > maxResponse {
		return resultInfo{}, &Error{Kind: ErrProtocol, Operation: method + " " + path, Status: res.StatusCode}
	}
	var env envelope
	decodeErr := json.Unmarshal(b, &env)
	if res.StatusCode < 200 || res.StatusCode >= 300 || (decodeErr == nil && (len(env.Errors) != 0 || (env.Success != nil && !*env.Success))) {
		e := classify(res.StatusCode, env.Errors)
		e.Operation = method + " " + path
		e.RetryAfter = retryAfter(res.Header.Get("Retry-After"), time.Now())
		if e.Kind == ErrPermission {
			e.RequiredPermissions = append([]string(nil), permissions...)
		}
		return resultInfo{}, e
	}
	if out == nil && (res.StatusCode == http.StatusNoContent || len(bytes.TrimSpace(b)) == 0) {
		return resultInfo{}, nil
	}
	if decodeErr != nil || env.Success == nil || !*env.Success {
		return resultInfo{}, &Error{Kind: ErrProtocol, Operation: method + " " + path, Status: res.StatusCode}
	}
	if out != nil && (len(env.Result) == 0 || bytes.Equal(bytes.TrimSpace(env.Result), []byte("null")) || json.Unmarshal(env.Result, out) != nil) {
		return resultInfo{}, &Error{Kind: ErrProtocol, Operation: method + " " + path, Status: res.StatusCode}
	}
	return env.ResultInfo, nil
}

// list handles both ordinary page and Workers cursor pagination. A failed page
// returns no partial list so callers cannot mistake incomplete state for absence.
func list[T any](ctx context.Context, c *Client, path string, query url.Values, permissions ...string) ([]T, error) {
	if query == nil {
		query = make(url.Values)
	} else {
		query = maps.Clone(query)
	}
	query.Set("per_page", "100")
	var all []T
	for page := 1; page <= maxPages; page++ {
		query.Set("page", strconv.Itoa(page))
		var items []T
		info, err := c.request(ctx, http.MethodGet, path, query, nil, &items, permissions...)
		if err != nil {
			return nil, err
		}
		all = append(all, items...)
		if info.Cursor != "" {
			if info.Cursor == query.Get("cursor") {
				return nil, &Error{Kind: ErrProtocol, Operation: "pagination"}
			}
			query.Set("cursor", info.Cursor)
		} else if info.TotalPages > 0 {
			if page >= info.TotalPages {
				return all, nil
			}
		} else if info.TotalCount > 0 {
			if len(all) >= info.TotalCount {
				return all, nil
			}
		} else if len(items) < 100 {
			return all, nil
		}
	}
	return nil, &Error{Kind: ErrProtocol, Operation: "pagination limit"}
}

func path(parts ...string) (string, error) {
	for _, p := range parts {
		if !identifier.MatchString(p) {
			return "", invalid("resource identifier")
		}
	}
	return "/" + strings.Join(parts, "/"), nil
}

func invalid(field string) *Error { return &Error{Kind: ErrInvalid, Operation: field} }
func conflict(op string) *Error   { return &Error{Kind: ErrConflict, Operation: op} }
func ownership(op string) *Error  { return &Error{Kind: ErrOwnership, Operation: op} }

func domainName(s string) (string, error) {
	s = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
	if len(s) == 0 || len(s) > 253 {
		return "", invalid("domain")
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", invalid("domain")
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
				return "", invalid("domain (use IDNA ASCII form)")
			}
		}
	}
	return s, nil
}

func inZone(name, zone string) bool { return name == zone || strings.HasSuffix(name, "."+zone) }

// IsKind works with errors wrapped by the wizard.
func IsKind(err error, kind ErrorKind) bool {
	var e *Error
	return errors.As(err, &e) && e.Kind == kind
}

var _ fmt.Stringer = (*Client)(nil)
