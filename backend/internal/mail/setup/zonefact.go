package setup

import (
	"context"

	"SynoMailPlusSetupAssistant/internal/core"
	"SynoMailPlusSetupAssistant/internal/mail/detect"
)

// The zone fact (Cloudflare source): who hosts the mail domain's DNS, from
// Cloudflare's own zone API instead of DNS.
//
// A DNS lookup can time out (a cold resolver), which leaves "DNS hosted by
// Cloudflare" unknown. The signed-in token can say it deterministically:
//
//   - The zone is the longest label-boundary suffix of the mail domain among
//     the account's zones, read again at detection. Only a full setup
//     (type "full") with status "active" counts: Cloudflare has seen the
//     registrar's NS records point at it and serves the zone. Any other
//     status (pending, moved, deactivated…) or type (partial: DNS stays
//     elsewhere; secondary), a refused or failed read, or no token: no zone
//     fact, and the DNS lookup decides with its unknown rules.
//     The limit: "active" means Cloudflare last saw the registrar's NS
//     point at it. After a registrar change the zone becomes "moved" only
//     after a while, and until then it still reads "active"; a definite DNS
//     answer that differs still wins (below).
//   - The zone's NS records are always read (the apex included). Cloudflare
//     answers for the apex with its own name servers and lists no apex NS
//     record for them; an NS record named the apex is multi-provider DNS
//     (the registrar may also list another provider's servers), so the
//     zone is no proof: no zone fact.
//   - A name under the zone apex could be delegated away (a child zone,
//     elsewhere or on Cloudflare). The parent zone's servers only hand out
//     such a delegation from NS records in the zone itself: an NS record at
//     the mail domain or at any name between it and the apex means the
//     parent being active is no proof, and no zone fact is taken.
//   - DNS keeps its answer whenever it is definite and differs: Cloudflare
//     known false from the NS records, a zone DNS found that is another name
//     (a delegation DNS sees), or no zone at all down to two labels. Only an
//     unknown DNS answer, or one that agrees, takes the zone fact.

// ZoneDelegations is an optional part of CloudDirectory: the names of a
// zone's NS records (normalized), any at the apex included. An error means
// unknown, never "none".
type ZoneDelegations interface {
	NSNames(ctx context.Context, env core.Env, tokenRef, zoneID string) ([]string, error)
}

// zoneFact returns the name of the active, fully set up Cloudflare zone that
// hosts domain, or "" when the token cannot say so.
func (w *Wizard) zoneFact(ctx context.Context, env core.Env, tokenRef, accountID, domain string) string {
	if w.options.Directory == nil || tokenRef == "" || accountID == "" {
		return ""
	}
	zones, missing, err := w.options.Directory.Zones(ctx, env, tokenRef, accountID)
	if err != nil || len(missing) > 0 {
		return ""
	}
	if zones, err = cleanZones(zones); err != nil {
		return ""
	}
	id := matchZone(domain, zones)
	z, ok := (&cloudLink{Zones: zones}).zone(id)
	if !ok || z.Status != "active" || z.Type != "full" {
		return ""
	}
	src, ok := w.options.Directory.(ZoneDelegations)
	if !ok {
		return ""
	}
	names, err := src.NSNames(ctx, env, tokenRef, z.ID)
	if err != nil {
		return ""
	}
	for _, n := range names {
		n = detect.NormalizeDomain(n)
		if n == z.Name {
			return "" // multi-provider DNS: another provider may answer too
		}
		if inZone(n, z.Name) && inZone(domain, n) {
			return "" // delegated below the apex
		}
	}
	return z.Name
}

// applyZoneFact takes "hosted by Cloudflare" from the zone fact unless DNS
// gave a definite answer that differs.
func applyZoneFact(s *detect.State, zone string) {
	if zone == "" {
		return
	}
	dns := s.DNS
	switch {
	case dns.Cloudflare.IsKnown() && !dns.Cloudflare.Value:
		return
	case dns.Zone != "" && dns.Zone != zone:
		return
	case dns.NS.Status == "missing" && dns.NS.Detail == detect.NoZoneFound:
		return
	}
	s.DNS.Cloudflare = detect.Fact(true)
	s.DNS.CloudflareSource, s.DNS.CloudflareZone = detect.SourceZone, zone
}
