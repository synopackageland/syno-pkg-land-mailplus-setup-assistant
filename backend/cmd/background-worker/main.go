// Command background-worker is the package's fixed background worker. DSM runs
// it as the package's systemd user unit under the package account; it never
// runs as root. It serves the private IPC the CGI forwards to, hosts the mail
// relay and keeps the setup transactions. Its only scheduled work is the
// automatic mailbox sync of per-address Cloudflare setups: one
// MailPlus account read per setup every ten minutes, and Cloudflare only
// when the mailbox set changed (mail/autosync.go).
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/synopackageland/syno-pkg-land-sdk/background"
	"github.com/synopackageland/syno-pkg-land-sdk/delegate"
	"github.com/synopackageland/syno-pkg-land-sdk/ipc"

	"SynoMailPlusSetupAssistant/internal/app"
	"SynoMailPlusSetupAssistant/internal/core"
	"SynoMailPlusSetupAssistant/internal/mail"
	"SynoMailPlusSetupAssistant/internal/worker"
)

// Set by `synopkgland build-spk` through -ldflags -X.
var packageID = "dev"

func main() {
	log.SetFlags(0)
	log.SetPrefix(packageID + " background: ")
	if err := background.RefuseRoot(os.Geteuid()); err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	dataDir := "/var/packages/" + packageID + "/var"
	socket := filepath.Join(dataDir, "run", "assistant.sock")
	if err := app.RemoveStaleCoreSocket(ctx, socket); err != nil {
		log.Fatal("worker socket unavailable")
	}
	// Claim the private socket before opening the store or starting any work.
	var ready atomic.Pointer[worker.Worker]
	server, err := ipc.StartUnix(ctx, socket, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if wk := ready.Load(); wk != nil {
			wk.ServeHTTP(w, req)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	if err != nil {
		log.Fatal("worker IPC unavailable")
	}
	defer server.Close()
	store, err := core.OpenStore(dataDir)
	if err != nil {
		log.Fatal("private store unavailable")
	}
	defer store.Close()
	// Once per installation each, before any flow can move: drop the sealed
	// operations builds ≤45 left behind, then the stale flow sign-in tokens.
	// Counts only; a failure deletes nothing more and is retried at the next
	// start.
	for _, sweep := range []struct {
		name string
		run  func(context.Context, *core.Store) (mail.SweepCount, error)
	}{
		{"sealed operation sweep", mail.SweepOperationSecretsOnce},
		{"flow token sweep", mail.SweepFlowTokensOnce},
	} {
		if n, err := sweep.run(ctx, store); err != nil {
			log.Printf("%s stopped: removed=%d", sweep.name, n.Removed)
		} else if n.Ran {
			log.Printf("%s: sealed=%d removed=%d kept=%d", sweep.name, n.Sealed, n.Removed, n.Kept)
		}
	}
	authority := &core.Authority{Store: store, Client: delegate.Local(packageID)}
	assistant := mail.Production(dataDir, mail.SystemDependencies())
	// Read-only background jobs end with the worker: stopping the package
	// cancels them, and the stop waits for them before the store closes.
	assistant.Background.Base = ctx
	host, err := core.NewHost(store, core.Env{DSM: authority.DSM(""), DataDir: dataDir}, assistant.Services()...)
	if err != nil {
		log.Fatal("service registry invalid")
	}
	host.Authority = authority
	ready.Store(&worker.Worker{Host: host, Mail: assistant})
	// The jobs capability is what runs and supervises this process (the
	// package-account systemd unit). The App has no SDK file jobs: the
	// template's bg job runner and its routes were removed in build 37.
	var tasks sync.WaitGroup
	var failed atomic.Bool
	run := func(f func(context.Context)) {
		tasks.Add(1)
		go func() {
			defer tasks.Done()
			f(ctx)
		}()
	}
	run(host.HostServices)
	// The automatic mailbox sync uses the worker's own environment (shared
	// background reads: mail-read only).
	run(func(c context.Context) { assistant.Kept.AutoSync(c, host.Env) })
	_ = server.Wait()
	if ctx.Err() == nil {
		log.Print("worker IPC stopped")
		failed.Store(true)
		stop()
	}
	done := make(chan struct{})
	go func() { tasks.Wait(); assistant.Setup.Wait(); assistant.Background.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(app.WorkerStopBudget):
		log.Print("graceful stop budget reached")
	}
	if failed.Load() {
		_ = store.Close()
		os.Exit(1) // let the SDK supervisor restart a failed worker
	}
}
