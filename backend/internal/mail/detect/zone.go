package detect

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"
)

// Domain existence and the zone that holds it.
//
// Go's lookups follow CNAMEs and never check the owner name of an answer, and
// LookupNS on a name with records but no NS of its own (any subdomain) fails
// with IsNotFound. So:
//
//   - The name exists when any lookup of it returns records: NS, A/AAAA
//     (LookupHost), MX, TXT, or a CNAME (LookupCNAME naming another name; a
//     dangling alias exists too). When every lookup is not found, Go cannot
//     tell NXDOMAIN from NODATA (an empty non-terminal exists without
//     records), so the RCodeResolver probe decides: NXDOMAIN without answers
//     is missing, NXDOMAIN with an answer (a dangling alias) exists; NOERROR
//     without answers is unknown (compact denial, RFC 9824, answers a name
//     that does not exist that way too), as is anything else or no probe. A
//     timeout or resolver failure with no records elsewhere is unknown.
//   - The zone is the first name with NS records of its own, walking up one
//     label at a time. A name that is an alias is never a zone: its NS answer
//     is the alias target's, so the walk goes on to its parent. NS records
//     with an unknown alias check, or a failed NS lookup, leave the zone (and
//     the Cloudflare decision) unknown.
//   - There is no public-suffix list in this build. The walk stops at two
//     labels: it never asks a single-label name (a TLD such as me or uk), but
//     it does ask a two-label name, which can be a registry's public suffix
//     (x.co.uk without NS walks up to co.uk). A zone found that way at a
//     two-label name that may be a public suffix (a common second-level label
//     under a two-letter TLD, such as co.uk or com.tw) is unknown: records
//     served by the registry say nothing about who hosts the domain. Public
//     suffixes outside that pattern are not recognized.

// lookupKind is one lookup's answer: records, a not-found answer, or no
// usable answer.
type lookupKind int

const (
	lookupFound lookupKind = iota
	lookupNotFound
	lookupUnknown
)

func classify(n int, err error) lookupKind {
	if err != nil {
		var de *net.DNSError
		if errors.As(err, &de) && de.IsNotFound && !de.IsTimeout && !de.IsTemporary {
			return lookupNotFound
		}
		return lookupUnknown
	}
	if n == 0 {
		return lookupNotFound
	}
	return lookupFound
}

// NoZoneFound is the NS check's detail when the walk found no name with NS
// records down to two labels: DNS names no zone at all.
const NoZoneFound = "no zone found"

// minZoneLabels is where the zone walk stops (see the comment above).
const minZoneLabels = 2

// suffixLabels are second-level labels registries commonly use under a
// two-letter TLD (co.uk, com.tw, ne.jp). A two-label name made of one of these
// and a two-letter TLD may be a public suffix.
var suffixLabels = map[string]bool{
	"ac": true, "ad": true, "biz": true, "co": true, "com": true, "ed": true, "edu": true, "gen": true,
	"go": true, "gob": true, "gov": true, "gr": true, "idv": true, "info": true, "int": true, "lg": true,
	"ltd": true, "me": true, "med": true, "mil": true, "ne": true, "net": true, "nom": true, "or": true,
	"org": true, "plc": true, "res": true, "sch": true,
}

func possiblePublicSuffix(name string) bool {
	l := strings.Split(name, ".")
	return len(l) == 2 && len(l[1]) == 2 && suffixLabels[l[0]]
}

type answer struct {
	kind  lookupKind
	hosts []string
}

// aliasOf reads a LookupCNAME answer for name: lookupFound when name is an
// alias of another name, lookupNotFound when it is not, lookupUnknown when
// the lookup gave no usable answer.
func aliasOf(name string, cname string, err error) lookupKind {
	switch classify(1, err) {
	case lookupUnknown:
		return lookupUnknown
	case lookupNotFound:
		return lookupNotFound
	}
	if NormalizeDomain(cname) != name {
		return lookupFound
	}
	return lookupNotFound
}

// domainDNS reports whether domain exists, and the zone holding it with its
// NS records (zone "" when not found).
func (d *Detector) domainDNS(ctx context.Context, domain string, t time.Duration) (exists Check, zone string, ns Check) {
	lookup := func(fn func(context.Context) ([]string, error)) answer {
		o := bounded(ctx, t, func(c context.Context) (answer, error) {
			v, e := fn(c)
			return answer{classify(len(v), e), v}, nil
		})
		if !o.IsKnown() {
			return answer{kind: lookupUnknown}
		}
		return o.Value
	}
	nsOf := func(name string) func(context.Context) ([]string, error) {
		return func(c context.Context) ([]string, error) {
			v, e := d.Resolver.LookupNS(c, name+".")
			out := []string{}
			for _, n := range v {
				out = append(out, n.Host)
			}
			return out, e
		}
	}
	aliasLookup := func(name string) func(context.Context) ([]string, error) {
		return func(c context.Context) ([]string, error) {
			v, e := d.Resolver.LookupCNAME(c, name+".")
			switch aliasOf(name, v, e) {
			case lookupFound:
				return []string{v}, nil
			case lookupNotFound:
				return nil, nil
			}
			return nil, e
		}
	}
	all := func(fns ...func(context.Context) ([]string, error)) []answer {
		out := make([]answer, len(fns))
		done := make(chan struct{}, len(fns))
		for i, fn := range fns {
			go func() { out[i] = lookup(fn); done <- struct{}{} }()
		}
		for range fns {
			<-done
		}
		return out
	}
	fqdn := domain + "."
	answers := all(
		nsOf(domain),
		aliasLookup(domain),
		func(c context.Context) ([]string, error) { return d.Resolver.LookupHost(c, fqdn) },
		func(c context.Context) ([]string, error) {
			v, e := d.Resolver.LookupMX(c, fqdn)
			out := []string{}
			for _, m := range v {
				out = append(out, m.Host)
			}
			return out, e
		},
		func(c context.Context) ([]string, error) { return d.Resolver.LookupTXT(c, fqdn) },
	)
	found, unsure := false, false
	for _, a := range answers {
		switch a.kind {
		case lookupFound:
			found = true
		case lookupUnknown:
			unsure = true
		}
	}
	unknownCheck := Check{Status: "unknown", Detail: "DNS gave no usable answer"}
	switch {
	case found:
		exists = Check{Status: "present"}
	case unsure:
		exists = unknownCheck
	default:
		// Every lookup not found: NXDOMAIN or NODATA, which only the reply
		// code tells apart.
		exists = unknownCheck
		if rr, ok := d.Resolver.(RCodeResolver); ok {
			o := bounded(ctx, t, func(c context.Context) ([2]int, error) {
				rcode, n, err := rr.LookupRCode(c, fqdn)
				return [2]int{rcode, n}, err
			})
			switch {
			case !o.IsKnown():
			case o.Value[0] == rcodeNXDomain && o.Value[1] == 0:
				missing := Check{Status: "missing", Detail: "DNS name not found"}
				return missing, "", missing
			case o.Value[0] == rcodeNXDomain:
				// NXDOMAIN with an answer: an alias whose target does not
				// exist.
				exists = Check{Status: "present"}
			}
			// NOERROR without answers stays unknown: an empty non-terminal
			// answers so, but so do Cloudflare (RFC 9824 compact denial), NS1
			// and Route 53 for names that do not exist.
		}
	}
	// The zone: the name itself, else its parents down to two labels.
	own, alias := answers[0], answers[1]
	name := domain
	for {
		switch {
		case alias.kind == lookupFound:
			// An alias is never a zone; its NS answer is the target's.
		case own.kind == lookupFound && alias.kind == lookupUnknown:
			return exists, "", unknownCheck
		case own.kind == lookupFound:
			if name != domain && possiblePublicSuffix(name) {
				return exists, "", Check{Status: "unknown", Detail: "possible public suffix"}
			}
			return exists, name, dnsResult(own.hosts, nil)
		case own.kind == lookupUnknown:
			return exists, "", unknownCheck
		}
		labels := strings.Split(name, ".")
		if len(labels) <= minZoneLabels {
			return exists, "", Check{Status: "missing", Detail: NoZoneFound}
		}
		name = strings.Join(labels[1:], ".")
		next := all(nsOf(name), aliasLookup(name))
		own, alias = next[0], next[1]
	}
}
