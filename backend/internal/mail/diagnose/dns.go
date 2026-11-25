// This preflight does not evaluate SPF sender authorization or prove delivery.
package diagnose

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"
)

type ProbeResult struct {
	Status string   `json:"status"`
	Values []string `json:"values,omitempty"`
	Detail string   `json:"detail,omitempty"`
}
type Egress struct {
	Family      string        `json:"family"`
	ProbeResult ProbeResult   `json:"result"`
	Sources     []ProbeResult `json:"sources"`
}
type Port struct {
	Family   string `json:"family"`
	Endpoint string `json:"endpoint"`
	Status   string `json:"status"`
	Detail   string `json:"detail"`
}
type BL struct {
	Provider string      `json:"provider"`
	Mode     string      `json:"mode"`
	Status   string      `json:"status"`
	Codes    []string    `json:"codes,omitempty"`
	Lists    []string    `json:"lists,omitempty"`
	Detail   string      `json:"detail,omitempty"`
	Control  ProbeResult `json:"control"`
}
type Reverse struct {
	Name    string      `json:"name"`
	Forward ProbeResult `json:"forward"`
	Generic bool        `json:"generic_isp_pattern"`
}
type IPReport struct {
	IP      string      `json:"ip"`
	Source  string      `json:"source"`
	PTR     ProbeResult `json:"ptr"`
	Reverse []Reverse   `json:"reverse"`
	FCrDNS  string      `json:"fcrdns"`
	DNSBL   []BL        `json:"dnsbl"`
}
type SPFNode struct {
	Domain string   `json:"domain"`
	Record string   `json:"record"`
	Terms  []string `json:"terms"`
}
type SPF struct {
	Status        string      `json:"status"`
	Records       ProbeResult `json:"records"`
	Nodes         []SPFNode   `json:"nodes"`
	LookupTerms   int         `json:"lookup_terms_expanded"`
	Includes      []string    `json:"includes"`
	Issues        []string    `json:"issues"`
	Authorization string      `json:"sender_authorization"`
}
type DKIM struct {
	Selector string      `json:"selector"`
	Records  ProbeResult `json:"records"`
	Status   string      `json:"status"`
	Detail   string      `json:"detail"`
}
type Domain struct {
	Name      string            `json:"domain"`
	MX        ProbeResult       `json:"mx"`
	SPF       SPF               `json:"spf"`
	DKIM      []DKIM            `json:"dkim"`
	DMARC     ProbeResult       `json:"dmarc"`
	DMARCTags map[string]string `json:"dmarc_tags,omitempty"`
	MTASTS    ProbeResult       `json:"mta_sts_txt"`
	TLSRPT    ProbeResult       `json:"tls_rpt_txt"`
}
type checker struct {
	ctx              context.Context
	r                Resolver
	timeout          time.Duration
	key              string
	enabledProviders []string
	txtCache         map[string]ProbeResult
	controls         map[string]ProbeResult
}

// Never include DNSError.Name: it may contain the confidential DQS key.
func safeError(err error) string {
	var de *net.DNSError
	if errors.As(err, &de) {
		if de.IsNotFound {
			return "DNS name or record not found"
		}
		if de.IsTimeout {
			return "DNS timeout"
		}
		return "DNS resolver returned an error"
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "network timeout"
	}
	return "network connection or lookup failed"
}
func dnsResult(v []string, err error) ProbeResult {
	if err != nil {
		status := "unknown"
		var de *net.DNSError
		if errors.As(err, &de) && de.IsNotFound {
			status = "missing"
		}
		return ProbeResult{Status: status, Detail: safeError(err)}
	}
	sort.Strings(v)
	if len(v) == 0 {
		return ProbeResult{Status: "missing", Detail: "no answers"}
	}
	return ProbeResult{Status: "present", Values: v}
}
func (c *checker) txt(name string) ProbeResult {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if v, ok := c.txtCache[name]; ok {
		return v
	}
	ctx, cancel := context.WithTimeout(c.ctx, c.timeout)
	defer cancel()
	v, err := c.r.LookupTXT(ctx, name+".")
	result := dnsResult(v, err)
	c.txtCache[name] = result
	return result
}
func (c *checker) ips(name string) ProbeResult {
	ctx, cancel := context.WithTimeout(c.ctx, c.timeout)
	defer cancel()
	v, err := c.r.LookupHost(ctx, strings.TrimSuffix(name, ".")+".")
	return dnsResult(v, err)
}
func (c *checker) a(name string) ProbeResult {
	ctx, cancel := context.WithTimeout(c.ctx, c.timeout)
	defer cancel()
	v, err := c.r.LookupIP(ctx, "ip4", name+".")
	ss := []string{}
	for _, ip := range v {
		ss = append(ss, ip.String())
	}
	return dnsResult(ss, err)
}

var genericPTR = regexp.MustCompile(`(?i)(^|[.-])(dynamic|dyn|dsl|adsl|vdsl|pool|dhcp|broadband|pppoe)([.-]|$)|(^|[.])ip[-.][0-9]+[-.][0-9]+[-.][0-9]+[-.][0-9]+|[0-9]+-[0-9]+-[0-9]+-[0-9]+`)

func reverseIP(ip netip.Addr) string {
	if ip.Is4() {
		b := ip.As4()
		return fmt.Sprintf("%d.%d.%d.%d", b[3], b[2], b[1], b[0])
	}
	b := ip.As16()
	hex := fmt.Sprintf("%032x", b)
	out := []string{}
	for i := len(hex) - 1; i >= 0; i-- {
		out = append(out, string(hex[i]))
	}
	return strings.Join(out, ".")
}

type provider struct {
	name, zone, mode string
	ipv6             bool
	codes            map[string]string
}

func (c *checker) providers() []provider {
	zone, mode := "zen.spamhaus.org", "public"
	if c.key != "" {
		zone = c.key + ".zen.dq.spamhaus.net"
		mode = "DQS"
	}
	all := []provider{
		{"Spamhaus ZEN", zone, mode, true, map[string]string{"127.0.0.2": "SBL", "127.0.0.3": "SBL CSS", "127.0.0.4": "XBL", "127.0.0.9": "SBL DROP", "127.0.0.10": "PBL (ISP maintained)", "127.0.0.11": "PBL (Spamhaus maintained)"}},
		{"Barracuda", "b.barracudacentral.org", "public (registration may be required)", false, map[string]string{"127.0.0.2": "BRBL"}},
		{"SpamCop", "bl.spamcop.net", "public", false, map[string]string{"127.0.0.2": "SCBL"}},
		{"PSBL", "psbl.surriel.com", "public", false, map[string]string{"127.0.0.2": "PSBL"}},
	}
	selected := []provider{}
	for _, p := range all {
		for _, name := range c.enabledProviders {
			if name == p.name {
				selected = append(selected, p)
				break
			}
		}
	}
	return selected
}
func classifyBL(p provider, v ProbeResult) (string, []string, string) {
	if v.Status == "missing" {
		return "not_listed", nil, "NXDOMAIN / no A record"
	}
	if v.Status != "present" {
		return "unknown", nil, v.Detail
	}
	lists := []string{}
	for _, code := range v.Values {
		if strings.HasPrefix(code, "127.255.255.") {
			return "unknown", nil, "provider query error / resolver blocked / rate or key restriction"
		}
		list, ok := p.codes[code]
		if !ok {
			return "unknown", nil, "unrecognized DNSBL answer (not treated as listing)"
		}
		lists = append(lists, list)
	}
	return "listed", lists, "provider returned a documented listing code"
}
func (c *checker) bl(ip netip.Addr, p provider) BL {
	result := BL{Provider: p.name, Mode: p.mode, Status: "unknown", Control: ProbeResult{Status: "unknown"}}
	if ip.Is6() && !p.ipv6 {
		result.Detail = "IPv6 queries not supported by this adapter"
		return result
	}
	if control, ok := c.controls[p.name]; ok {
		result.Control = control
	} else {
		positive := c.a("2.0.0.127." + p.zone)
		ps, _, pd := classifyBL(p, positive)
		negative := c.a("1.0.0.127." + p.zone)
		ns, _, nd := classifyBL(p, negative)
		result.Control = ProbeResult{Status: "unknown", Detail: "positive: " + ps + " (" + pd + "); negative: " + ns + " (" + nd + ")"}
		result.Control.Values = append(result.Control.Values, positive.Values...)
		result.Control.Values = append(result.Control.Values, negative.Values...)
		if ps == "listed" && ns == "not_listed" {
			result.Control.Status = "pass"
		}
		c.controls[p.name] = result.Control
	}
	v := c.a(reverseIP(ip) + "." + p.zone)
	result.Codes = v.Values
	result.Status, result.Lists, result.Detail = classifyBL(p, v)
	if result.Control.Status != "pass" {
		result.Status = "unknown"
		result.Detail = "DNSBL positive/negative controls failed; " + result.Detail
	}
	return result
}
func (c *checker) ipReport(ip netip.Addr, source string) IPReport {
	out := IPReport{IP: ip.String(), Source: source, FCrDNS: "unknown", Reverse: []Reverse{}, DNSBL: []BL{}}
	ctx, cancel := context.WithTimeout(c.ctx, c.timeout)
	names, err := c.r.LookupAddr(ctx, ip.String())
	cancel()
	out.PTR = dnsResult(names, err)
	unknown := out.PTR.Status == "unknown"
	match := false
	for _, name := range out.PTR.Values {
		f := c.ips(name)
		out.Reverse = append(out.Reverse, Reverse{name, f, genericPTR.MatchString(name)})
		if f.Status == "unknown" {
			unknown = true
		}
		for _, s := range f.Values {
			a, e := netip.ParseAddr(s)
			if e == nil && a.Unmap() == ip.Unmap() {
				match = true
			}
		}
	}
	if match {
		out.FCrDNS = "pass"
	} else if !unknown {
		out.FCrDNS = "fail"
	}
	for _, p := range c.providers() {
		out.DNSBL = append(out.DNSBL, c.bl(ip, p))
	}
	return out
}
func matching(v ProbeResult, prefix string) ProbeResult {
	if v.Status == "unknown" {
		return v
	}
	out := ProbeResult{Status: "missing", Values: []string{}}
	for _, s := range v.Values {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(s)), strings.ToLower(prefix)) {
			out.Values = append(out.Values, s)
		}
	}
	if len(out.Values) > 0 {
		out.Status = "present"
	}
	return out
}
func spfRecords(v ProbeResult) ProbeResult {
	out := matching(v, "v=spf1")
	vv := out.Values[:0]
	for _, s := range out.Values {
		f := strings.Fields(s)
		if len(f) > 0 && strings.EqualFold(f[0], "v=spf1") {
			vv = append(vv, s)
		}
	}
	out.Values = vv
	if len(vv) == 0 && out.Status != "unknown" {
		out.Status = "missing"
	}
	return out
}
func spfIssue(s *SPF, status, msg string) {
	s.Issues = append(s.Issues, msg)
	if s.Status != "fail" || status == "fail" {
		s.Status = status
	}
}

// This expands the maximum syntactic include/redirect tree, not SPF evaluation
// for a message. Branch short-circuiting and macros require an actual evaluator.
func (c *checker) spf(domain string) SPF {
	s := SPF{Status: "pass", Records: spfRecords(c.txt(domain)), Nodes: []SPFNode{}, Includes: []string{}, Issues: []string{}, Authorization: "unknown: static preflight does not evaluate MAIL FROM / HELO / sender IP"}
	c.spfWalk(domain, &s, map[string]bool{}, 0)
	return s
}
func (c *checker) spfWalk(domain string, s *SPF, stack map[string]bool, depth int) {
	if s.LookupTerms > 10 {
		return
	}
	if depth > 12 {
		spfIssue(s, "unknown", "expansion depth reached")
		return
	}
	if stack[domain] {
		spfIssue(s, "unknown", "include/redirect cycle: "+domain)
		return
	}
	v := spfRecords(c.txt(domain))
	if v.Status == "unknown" {
		spfIssue(s, "unknown", domain+": DNS unavailable")
		return
	}
	if len(v.Values) != 1 {
		spfIssue(s, "fail", domain+": expected exactly one SPF record")
		return
	}
	stack[domain] = true
	defer delete(stack, domain)
	terms := strings.Fields(v.Values[0])[1:]
	s.Nodes = append(s.Nodes, SPFNode{domain, v.Values[0], terms})
	redirect := ""
	hasAll := false
	termsUnknown := false
	for _, term := range terms {
		if s.LookupTerms > 10 {
			return
		}
		t := term
		if strings.ContainsAny(t[:1], "+-~?") {
			t = t[1:]
		}
		if t == "" {
			spfIssue(s, "fail", domain+": empty mechanism")
			continue
		}
		if strings.Contains(t, "=") {
			k, val, _ := strings.Cut(t, "=")
			k = strings.ToLower(k)
			if k == "redirect" {
				if redirect != "" {
					spfIssue(s, "fail", "duplicate redirect")
				}
				redirect = val
				if val == "" {
					spfIssue(s, "fail", "empty redirect")
				}
			} else if k == "exp" && val == "" {
				spfIssue(s, "fail", "empty exp")
			}
			continue
		}
		base, arg, hasArg := strings.Cut(t, ":")
		base = strings.ToLower(strings.Split(base, "/")[0])
		switch base {
		case "all":
			if !strings.EqualFold(t, "all") {
				spfIssue(s, "fail", "invalid all mechanism")
			}
			hasAll = true
		case "ip4", "ip6":
			a := arg
			if !strings.Contains(a, "/") {
				if base == "ip4" {
					a += "/32"
				} else {
					a += "/128"
				}
			}
			p, e := netip.ParsePrefix(a)
			if e != nil || (base == "ip4") != p.Addr().Is4() {
				spfIssue(s, "fail", "invalid "+base+" network")
			}
		case "a", "mx", "include", "exists", "ptr":
			s.LookupTerms++
			if s.LookupTerms > 10 {
				spfIssue(s, "unknown", "expanded DNS lookup terms exceed 10; an evaluated path may exceed RFC 7208 budget")
				return
			}
			if base == "include" || base == "exists" {
				if !hasArg || arg == "" {
					spfIssue(s, "fail", "missing "+base+" domain")
					continue
				}
			}
			if base == "ptr" {
				spfIssue(s, "unknown", "ptr mechanism is deprecated; runtime evaluation needed")
			}
			if base == "mx" || base == "a" || base == "exists" {
				termsUnknown = true
			}
			if strings.Contains(t, "%") {
				spfIssue(s, "unknown", "SPF macro needs runtime context")
				continue
			}
			if base == "include" {
				s.Includes = append(s.Includes, arg)
				c.spfWalk(strings.ToLower(strings.TrimSuffix(arg, ".")), s, stack, depth+1)
			}
		default:
			spfIssue(s, "fail", "unknown SPF mechanism: "+base)
		}
		if hasAll {
			break
		} // remaining mechanisms and redirect cannot be evaluated
	}
	if s.LookupTerms > 10 {
		return
	}
	if redirect != "" && !hasAll {
		s.LookupTerms++
		if s.LookupTerms > 10 {
			spfIssue(s, "unknown", "redirect exceeds expanded 10-term budget")
			return
		}
		if strings.Contains(redirect, "%") {
			spfIssue(s, "unknown", "redirect macro needs runtime context")
		} else {
			c.spfWalk(strings.ToLower(strings.TrimSuffix(redirect, ".")), s, stack, depth+1)
		}
	}
	if termsUnknown {
		spfIssue(s, "unknown", "a/mx/exists: address expansion, void lookup and matching-path budgets require runtime evaluation")
	}
}
func tags(s string) (map[string]string, bool) {
	m := map[string]string{}
	for _, part := range strings.Split(s, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, "=")
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		if !ok || k == "" {
			return m, false
		}
		if _, ok := m[k]; ok {
			return m, false
		}
		m[k] = v
	}
	return m, true
}
func dkimCheck(selector string, v ProbeResult) DKIM {
	d := DKIM{Selector: selector, Records: v, Status: v.Status, Detail: "only this supplied selector was checked"}
	if v.Status != "present" {
		return d
	}
	if len(v.Values) != 1 {
		d.Status = "fail"
		d.Detail = "multiple selector TXT records"
		return d
	}
	t, ok := tags(v.Values[0])
	if !ok || (t["v"] != "" && t["v"] != "DKIM1") {
		d.Status = "fail"
		d.Detail = "invalid DKIM tags"
		return d
	}
	key, ok := t["p"]
	if !ok {
		d.Status = "fail"
		d.Detail = "missing p= key"
		return d
	}
	key = strings.Join(strings.Fields(key), "")
	if key == "" {
		d.Status = "fail"
		d.Detail = "p= is empty: key revoked"
		return d
	}
	b, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		d.Status = "fail"
		d.Detail = "invalid base64 key"
		return d
	}
	kind := t["k"]
	if kind == "" {
		kind = "rsa"
	}
	switch kind {
	case "rsa":
		key, parseErr := x509.ParsePKIXPublicKey(b)
		if parseErr == nil {
			if _, ok := key.(*rsa.PublicKey); !ok {
				d.Status = "fail"
				d.Detail = "public key is not RSA"
				return d
			}
		} else if _, e := x509.ParsePKCS1PublicKey(b); e != nil {
			d.Status = "fail"
			d.Detail = "invalid RSA public key"
			return d
		}
	case "ed25519":
		if len(b) != 32 {
			d.Status = "fail"
			d.Detail = "invalid Ed25519 key length"
			return d
		}
	default:
		d.Status = "unknown"
		d.Detail = "unsupported key algorithm"
		return d
	}
	d.Status = "present"
	d.Detail = "public key parses; signing and alignment require a delivered message"
	return d
}
func (c *checker) domain(name string, selectors []string) Domain {
	d := Domain{Name: name, DKIM: []DKIM{}}
	ctx, cancel := context.WithTimeout(c.ctx, c.timeout)
	mx, err := c.r.LookupMX(ctx, name+".")
	cancel()
	mxs := []string{}
	for _, m := range mx {
		mxs = append(mxs, fmt.Sprintf("%d %s", m.Pref, m.Host))
	}
	d.MX = dnsResult(mxs, err)
	if len(mx) == 1 && mx[0].Host == "." {
		d.MX.Status = "null_mx"
		d.MX.Detail = "domain explicitly accepts no mail"
	}
	if d.MX.Status == "missing" {
		d.MX.Detail = "no explicit MX; SMTP may fall back to A/AAAA (not validated)"
	}
	d.SPF = c.spf(name)
	for _, s := range selectors {
		d.DKIM = append(d.DKIM, dkimCheck(s, c.txt(s+"._domainkey."+name)))
	}
	d.DMARC = matching(c.txt("_dmarc."+name), "v=DMARC1")
	if len(d.DMARC.Values) == 1 {
		t, ok := tags(d.DMARC.Values[0])
		d.DMARCTags = t
		if !ok || t["v"] != "DMARC1" || (t["p"] != "none" && t["p"] != "quarantine" && t["p"] != "reject") {
			d.DMARC.Status = "fail"
			d.DMARC.Detail = "invalid DMARC policy/tags"
		}
	} else if len(d.DMARC.Values) > 1 {
		d.DMARC.Status = "fail"
		d.DMARC.Detail = "multiple DMARC policies"
	}
	if d.DMARC.Status == "missing" {
		d.DMARC.Detail = "no exact-domain DMARC; organizational-domain fallback not evaluated"
	}
	d.MTASTS = matching(c.txt("_mta-sts."+name), "v=STSv1")
	d.MTASTS.Detail = "TXT presence only; HTTPS policy, certificate, MX coverage and mode not verified"
	if d.MTASTS.Status == "present" {
		t, ok := tags(d.MTASTS.Values[0])
		if len(d.MTASTS.Values) != 1 || !ok || t["v"] != "STSv1" || t["id"] == "" {
			d.MTASTS.Status = "fail"
			d.MTASTS.Detail = "invalid MTA-STS TXT tags or multiple records"
		}
	}
	d.TLSRPT = matching(c.txt("_smtp._tls."+name), "v=TLSRPTv1")
	d.TLSRPT.Detail = "TXT presence only; report URI authorization and delivery not verified"
	if d.TLSRPT.Status == "present" {
		t, ok := tags(d.TLSRPT.Values[0])
		if len(d.TLSRPT.Values) != 1 || !ok || t["v"] != "TLSRPTv1" || t["rua"] == "" {
			d.TLSRPT.Status = "fail"
			d.TLSRPT.Detail = "invalid TLS-RPT TXT tags or multiple records"
		}
	}
	return d
}
func validDomain(s string) bool {
	if len(s) > 253 || !strings.Contains(s, ".") {
		return false
	}
	for _, l := range strings.Split(s, ".") {
		if len(l) == 0 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, r := range l {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}
