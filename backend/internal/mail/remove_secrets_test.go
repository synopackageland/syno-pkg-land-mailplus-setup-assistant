package mail

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	"SynoMailPlusSetupAssistant/internal/mail/setup"
)

// sealedKeys lists the keys (never the values) of every sealed secret.
func sealedKeys(t *testing.T, dir string) []string {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(dir, "assistant.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query("SELECT key FROM secrets ORDER BY key")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			t.Fatal(err)
		}
		out = append(out, k)
	}
	return out
}

// While a setup is kept its operations and token stay sealed;
// once it is removed, no sealed value of the setup outlives it.
func TestNoSealedSecretOutlivesARemovedSetup(t *testing.T) {
	ctx := context.Background()
	r := removable(t, newInboundCloud(), setup.ReceiveAddresses, "alice@example.test")
	before := sealedKeys(t, r.env.DataDir)
	ops := 0
	for _, k := range before {
		if strings.HasPrefix(k, "secret:mail.wiring.cloudflare.") {
			ops++
		}
	}
	if ops == 0 {
		t.Fatalf("the fixture sealed no operation: %v", before)
	}
	view, err := r.s.Remove(ctx, r.env, r.id, false, false)
	if err != nil || view.Removal == nil || view.Removal.State != "done" {
		t.Fatalf("removal: %+v %v", view.Removal, err)
	}
	if left := sealedKeys(t, r.env.DataDir); len(left) != 0 {
		t.Fatalf("sealed values outlived the removed setup: %v", left)
	}
}

// A kept setup keeps exactly what its removal needs: its operations and token.
func TestAKeptSetupKeepsItsSealedOperations(t *testing.T) {
	r := removable(t, newInboundCloud(), setup.ReceiveAddresses, "alice@example.test")
	rec := r.record(t)
	have := map[string]bool{}
	for _, k := range sealedKeys(t, r.env.DataDir) {
		have[k] = true
	}
	if !have[rec.TokenRef] {
		t.Fatal("the kept token is not sealed")
	}
	for _, a := range rec.Applied {
		if ref := a.Change.Params["operationRef"]; ref != "" && !have[ref] {
			t.Fatalf("%s lost its operation before removal", a.Change.ID)
		}
	}
}
