package detect

import (
	"context"
	"errors"

	"SynoMailPlusSetupAssistant/internal/core"
)

// CauseNotStarted: a DSM read was never sent (no executor slot within the
// slot wait). Distinct from core.CauseTimeout, which only a call that was
// sent and did not answer in time gives.
const CauseNotStarted = "probe_not_started"

// errDomainList: MailPlus Server's domain list could not be used (missing,
// too long, or a name that is not a valid domain). Unknown, never "none".
var errDomainList = errors.New("mail.detect.domainList")

// MailDomains checks the MailPlus Server precondition (one SYNO.Core.Package
// list v2 read), then reads MailPlus Server's mail domains with one DSM call
// (SYNO.MailPlusServer.Domain list v1, mail-read; the same read and the same
// limits as the detection pass) and returns their normalized names. MailPlus
// Server not installed or not running is MailPlusUnavailable, and the domain
// list is never asked for.
func (d *Detector) MailDomains(ctx context.Context, env core.Env) ([]string, error) {
	if env.DSM == nil {
		return nil, errDomainList
	}
	var pkg struct {
		Packages *[]mailPlusPackage `json:"packages"`
	}
	if err := env.DSM.Call(ctx, "SYNO.Core.Package", "list", 2, packageListParams, &pkg); err != nil {
		return nil, err
	}
	if err := StatusOf(packageOf(pkg.Packages)).Err(); err != nil {
		return nil, err
	}
	var out struct {
		Domains *[]struct {
			Name string `json:"name"`
		} `json:"domains"`
	}
	if err := env.DSM.Call(ctx, "SYNO.MailPlusServer.Domain", "list", 1, map[string]any{"offset": 0, "limit": -1}, &out); err != nil {
		return nil, err
	}
	if out.Domains == nil || len(*out.Domains) > 100 {
		return nil, errDomainList
	}
	names := []string{}
	for _, v := range *out.Domains {
		name := NormalizeDomain(v.Name)
		if !ValidDomain(name) {
			return nil, errDomainList
		}
		names = append(names, name)
	}
	return names, nil
}
