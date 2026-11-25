// Package detect provides read-only, partial mail setup facts for setup and diagnose.
package detect

import (
	"context"
	"time"

	"SynoMailPlusSetupAssistant/internal/core"
)

type Status string

const (
	Unknown Status = "unknown"
	Known   Status = "known"
)

// Observation never treats a missing/failed probe as a zero-valued fact.
// Detail is a fixed public explanation, never an underlying transport error.
type Observation[T any] struct {
	Status Status `json:"status"`
	Value  T      `json:"value"`
	Detail string `json:"detail,omitempty"`
}

func Fact[T any](v T) Observation[T] { return Observation[T]{Status: Known, Value: v} }
func Unavailable[T any]() Observation[T] {
	return Observation[T]{Status: Unknown, Detail: "probe_unavailable"}
}
func (o Observation[T]) IsKnown() bool { return o.Status == Known }

type Package struct {
	Installed bool   `json:"installed"`
	Running   bool   `json:"running"`
	Broken    bool   `json:"broken"`
	Version   string `json:"version,omitempty"`
}
type SMTP struct {
	Enabled bool `json:"enabled"`
	Port    int  `json:"port"`
}
type Domain struct {
	ID      int    `json:"id"`
	Name    string `json:"name"`
	Primary bool   `json:"primary"`
	Users   int    `json:"users"`
}
type Account struct {
	ID        int      `json:"id"`
	Name      string   `json:"name"`
	Addresses []string `json:"addresses"`
	Active    bool     `json:"active"`
}

// License is MailPlus Server's own count (SYNO.MailPlusServer.License v1):
// Licensed is get_user_limit's limit, Active is get_active_user_num's total
// (MailPlus users across every domain), not this assistant's account list.
type License struct {
	Licensed int `json:"licensed"`
	Active   int `json:"active"`
}
type RelayHost struct {
	ID       int    `json:"id"`
	Server   string `json:"server"`
	Port     int    `json:"port"`
	STARTTLS bool   `json:"starttls"`
	Auth     bool   `json:"auth"`
	// Credentials and full rule payloads must not enter public detection state.
}
type Delivery struct {
	Type      string      `json:"type"`
	Fallback  bool        `json:"fallback"`
	Default   []RelayHost `json:"default"`
	Sender    []RelayHost `json:"sender"`
	Recipient []RelayHost `json:"recipient"`
}
type Signing struct {
	Enabled   bool   `json:"enabled"`
	Selector  string `json:"selector"`
	PublicKey string `json:"publicKey"`
}
type Addressing string

const (
	AddressUnknown Addressing = "unknown"
	Fixed          Addressing = "fixed"
	Changing       Addressing = "changing"
)

type DNSBL struct {
	Provider string   `json:"provider"`
	Status   string   `json:"status"` // listed, not_listed, unknown
	Codes    []string `json:"codes,omitempty"`
}
type Network struct {
	EgressIPv4 Observation[string]     `json:"egressIPv4"`
	Addressing Observation[Addressing] `json:"addressing"`
	PTR        Observation[[]string]   `json:"ptr"`
	FCrDNS     Observation[bool]       `json:"fcrdns"`
	Outbound25 Observation[bool]       `json:"outbound25"`
	Inbound25  Observation[bool]       `json:"inbound25"`
	DNSBL      []DNSBL                 `json:"dnsbl"`
	Tunnel     Observation[Tunnel]     `json:"tunnel"`
}
type Tunnel struct {
	ID       string `json:"id"`
	Ready    bool   `json:"ready"`
	SMTPHost string `json:"smtpHost"` // fixed private target, no credentials
}
type DNS struct {
	Cloudflare Observation[bool] `json:"cloudflare"`
	// CloudflareSource is the evidence for a known Cloudflare: "dns" (the
	// zone's NS records) or "zone" (the signed-in token read the zone that
	// holds the domain as active, see setup's zone fact). CloudflareZone
	// names that zone for "zone".
	CloudflareSource string `json:"cloudflareSource,omitempty"`
	CloudflareZone   string `json:"cloudflareZone,omitempty"`
	NS               Check  `json:"ns"`
	MX               Check  `json:"mx"`
	SPF              Check  `json:"spf"`
	DKIM             []DKIM `json:"dkim"`
	DMARC            Check  `json:"dmarc"`
	// ParentDMARC (only when the name has no DMARC record of its own): the
	// first valid DMARC policy of a parent domain, up to the zone (or two
	// labels when the zone is unknown), which receivers apply to the name.
	// Present: Values holds the record, Detail the domain it is on.
	ParentDMARC Check `json:"parentDmarc"`
	// Independently evaluated record requirements, not inferred from TXT presence.
	SendRecords    Observation[bool] `json:"sendRecords"`
	ReceiveRecords Observation[bool] `json:"receiveRecords"`
	// Exists: does the domain have any records (NS, A/AAAA, MX or TXT); see
	// zone.go. Zone is the closest name at or above the domain with NS
	// records ("" if not found), and NS holds that zone's name servers.
	Exists Check  `json:"exists"`
	Zone   string `json:"zone,omitempty"`
}
type State struct {
	At           time.Time                         `json:"at"`
	Domain       string                            `json:"domain"`
	Package      Observation[Package]              `json:"package"`
	SMTP         Observation[SMTP]                 `json:"smtp"`
	Domains      Observation[[]Domain]             `json:"domains"`
	Accounts     map[string]Observation[[]Account] `json:"accounts"`
	License      Observation[License]              `json:"license"`
	Delivery     Observation[Delivery]             `json:"delivery"`
	Signing      map[string]Observation[Signing]   `json:"signing"`
	QueueSize    Observation[int]                  `json:"queueSize"`
	Network      Network                           `json:"network"`
	DNS          DNS                               `json:"dns"`
	SendReady    Observation[bool]                 `json:"sendReady"`
	ReceiveReady Observation[bool]                 `json:"receiveReady"`
}
type Request struct {
	Domain    string   `json:"domain"`
	Receive   bool     `json:"receive"`
	Selectors []string `json:"selectors,omitempty"`
}
type Source interface {
	Detect(context.Context, core.Env, Request) State
}

// Extensions use supported external contracts supplied by the coordinator.
// Implementations must honor cancellation and must not return credentials.
type Extensions interface {
	Addressing(context.Context, string) (Addressing, error)
	Inbound25(context.Context, string) (bool, error) // must be an external probe
	Tunnel(context.Context) (Tunnel, error)
	Readiness(context.Context, string) (send, receive bool, err error)
	DNSReadiness(context.Context, string) (send, receive bool, err error)
}
