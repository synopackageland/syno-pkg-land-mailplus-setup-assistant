package detect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"SynoMailPlusSetupAssistant/internal/core"
)

type domainDSM struct {
	reply string
	err   error
	call  string
	// packages answers the precondition read (default: MailPlus Server runs).
	packages string
}

func (d *domainDSM) Call(_ context.Context, api, method string, version int, params map[string]any, out any) error {
	d.call = api + " " + method
	if api == "SYNO.Core.Package" {
		pkgs := d.packages
		if pkgs == "" {
			pkgs = `[{"id":"MailPlus-Server","additional":{"status":"running"}}]`
		}
		return json.Unmarshal([]byte(`{"packages":`+pkgs+`}`), out)
	}
	if d.err != nil {
		return d.err
	}
	return json.Unmarshal([]byte(d.reply), out)
}

func TestMailDomainsReadsMailPlusDomainList(t *testing.T) {
	ctx := context.Background()
	dsm := &domainDSM{reply: `{"domains":[{"domain_id":1,"name":"MX.Example.ORG."},{"domain_id":2,"name":"sample-nas.test"}]}`}
	names, err := New().MailDomains(ctx, core.Env{DSM: dsm})
	if err != nil || dsm.call != "SYNO.MailPlusServer.Domain list" || len(names) != 2 || names[0] != "mx.example.org" {
		t.Fatalf("%v %v %s", names, err, dsm.call)
	}
	many := `{"domains":[`
	for i := 0; i < 101; i++ {
		if i > 0 {
			many += ","
		}
		many += fmt.Sprintf(`{"domain_id":%d,"name":"d%d.example.test"}`, i+1, i)
	}
	many += `]}`
	for name, d := range map[string]*domainDSM{
		"more than 100": {reply: many},
		"no list":       {reply: `{}`},
		"bad name":      {reply: `{"domains":[{"name":"not a domain"}]}`},
		"read failed":   {err: errors.New("dsm")},
	} {
		if _, err := New().MailDomains(ctx, core.Env{DSM: d}); err == nil {
			t.Fatalf("%s: unknown taken as a list", name)
		}
	}
	if _, err := New().MailDomains(ctx, core.Env{}); err == nil {
		t.Fatal("no DSM")
	}
}

// Not installed or not running: the domain list is never asked for and the
// refusal is the typed precondition.
func TestMailDomainsChecksMailPlusFirst(t *testing.T) {
	for name, tc := range map[string]struct {
		packages string
		state    MailPlusState
	}{
		"not installed": {`[]`, MailPlusNotInstalled},
		"stopped":       {`[{"id":"MailPlus-Server","additional":{"status":"stop"}}]`, MailPlusStopped},
		"broken":        {`[{"id":"MailPlus-Server","additional":{"status":"running","installed_info":{"is_brick":true}}}]`, MailPlusStopped},
		"unknown":       {`[{"id":"MailPlus-Server","additional":{}}]`, MailPlusUnknown},
	} {
		dsm := &domainDSM{packages: tc.packages, reply: `{"domains":[]}`}
		_, err := New().MailDomains(context.Background(), core.Env{DSM: dsm})
		var refused MailPlusUnavailable
		if !errors.As(err, &refused) || refused.State != tc.state || dsm.call != "SYNO.Core.Package list" {
			t.Fatalf("%s: %v %s", name, err, dsm.call)
		}
	}
}
