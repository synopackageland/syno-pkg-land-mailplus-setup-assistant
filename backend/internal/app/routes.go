// Package app holds the business handlers. Declare each operation once in
// operations.json; ctl generate writes the policy and SDK runtime registry.
//
//line SynoMailPlusSetupAssistant/internal/app/routes.go:1
package app

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/synopackageland/syno-pkg-land-sdk/api"
	"github.com/synopackageland/syno-pkg-land-sdk/delegate"
)

// Config is fixed at build time and startup, never taken from a request.
type Config struct {
	ExecutorDigest, PolicyDigest string
	PackageID                    string
	Version                      string
	// DataDir is the package's persistent, package-owned directory
	// (/var/packages/<package>/var). It survives upgrades.
	DataDir string
	// WebAPIExecutor is a trusted assembly/test dependency, never request data.
	WebAPIExecutor delegate.ExecutorClient
	coreTransport  func(context.Context, api.Caller, string, json.RawMessage) (any, error)
}

func Routes(cfg Config) []api.Route {
	routes := []api.Route{
		api.Handle("app.status", cfg.status),
	}
	routes = append(routes, cfg.assistantRoutes()...)
	routes = append(routes, cfg.authorityRoutes()...)
	return append(routes, cfg.rootRoutes()...)
}

func (cfg Config) status(_ context.Context, caller api.Caller, _ json.RawMessage) (any, error) {
	return map[string]any{
		"package":    cfg.PackageID,
		"version":    cfg.Version,
		"user":       caller.User(),
		"admin":      caller.Admin(),
		"lang":       "",
		"locale":     "",
		"process":    map[string]int{"uid": os.Getuid(), "gid": os.Getgid()},
		"go_version": runtime.Version(),
		"platform":   runtime.GOOS + "/" + runtime.GOARCH,
		"time":       time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// decodeParams decodes params strictly: unknown fields are an error.
func decodeParams(params json.RawMessage, into any) error {
	if len(params) == 0 {
		params = json.RawMessage(`{}`)
	}
	dec := json.NewDecoder(bytes.NewReader(params))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return api.BadRequest("invalid params: " + err.Error())
	}
	return nil
}

// writeFileAtomic replaces path in one rename, so readers never see half a file.
func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
