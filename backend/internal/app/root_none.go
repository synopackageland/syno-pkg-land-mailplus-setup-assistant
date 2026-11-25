package app

import (
	"github.com/synopackageland/syno-pkg-land-sdk/api"
	"github.com/synopackageland/syno-pkg-land-sdk/delegate"
)

// The SDK approval flow needs only executor status/control. MailPlus Setup Assistant
// declares no rootOps and provides no app-defined root helper or root.run.
func (cfg Config) rootRoutes() []api.Route {
	return delegate.ExecutorRoutes(cfg.webAPIClient(), cfg.DataDir)
}
