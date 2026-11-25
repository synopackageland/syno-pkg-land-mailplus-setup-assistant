// Package dsmauthority is the profile inventory and grant reference contract.
// It imports no worker handlers or store into the CGI.
package dsmauthority

import "github.com/synopackageland/syno-pkg-land-sdk/delegate"

// WebAPIProfile pins exact API/method/version tuples, never wildcard dispatch.
// Keep these in step with capabilities.webapi in dsm-package.yaml.
type WebAPIProfile struct {
	Purpose string                      `json:"purpose"`
	APIs    map[string]map[string][]int `json:"apis"`
}

// Profiles are the two MailPlus profiles carried over unchanged from Syno Home
// Keeper (tuples verified against DSM).
func Profiles() map[string]WebAPIProfile {
	return map[string]WebAPIProfile{
		"mail-read": {Purpose: "Read MailPlus configuration and diagnostic evidence", APIs: map[string]map[string][]int{
			"SYNO.API.Info":                            {"query": {1}},
			"SYNO.Core.Package":                        {"list": {2}},
			"SYNO.Core.Certificate.CRT":                {"list": {1}},
			"SYNO.Core.Network":                        {"get": {2}},
			"SYNO.MailPlusServer.Service.SMTP":         {"get": {1}},
			"SYNO.MailPlusServer.Domain":               {"list": {1}, "get_security": {2}},
			"SYNO.MailPlusServer.Domain.User":          {"list": {1}},
			"SYNO.MailPlusServer.License":              {"get_user_limit": {1}, "get_active_user_num": {1}},
			"SYNO.MailPlusServer.SMTP.Delivery":        {"get_type": {3}, "get_multiple": {3}},
			"SYNO.MailPlusServer.SMTP.RelayControl":    {"get": {1}},
			"SYNO.MailPlusServer.Queue":                {"list": {1}},
			"SYNO.MailPlusServer.Audit.TransactionLog": {"list": {1}},
			"SYNO.MailPlusServer.Util":                 {"initial_check": {2}},
		}},
		"mail-write": {Purpose: "Apply and restore previewed MailPlus SMTP, DKIM, default relay and mail domain changes", APIs: map[string]map[string][]int{
			"SYNO.MailPlusServer.Service.SMTP":  {"set": {1}},
			"SYNO.MailPlusServer.Domain":        {"set_security": {2}, "create": {1}, "delete": {1}},
			"SYNO.MailPlusServer.SMTP.Delivery": {"set_type": {3}, "set_multiple": {3}},
		}},
	}
}

// Binding is the stored reference to an administrator's executor grant.
type Binding struct {
	Grant delegate.Grant `json:"grant"`
	State string         `json:"state"`
}
