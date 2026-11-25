package setup

import (
	"context"
	"sort"
	"strings"

	"SynoMailPlusSetupAssistant/internal/core"
)

// operationSuffixes are the sealed values a change's references grow while it
// runs: the relay credential split for MailPlus (.user/.pass) and the Email
// Sending write's attempt marker and receipt (.attempt/.receipt).
var operationSuffixes = []string{"", ".user", ".pass", ".attempt", ".receipt"}

// OperationSecrets lists the sealed values a plan's changes own: every
// "...Ref" parameter that names a secret, with the values derived from it.
// The kept Cloudflare token and the relay's live token are never a change
// parameter, so they are never listed.
func OperationSecrets(changes []core.Change) []string {
	seen := map[string]bool{}
	for _, c := range changes {
		for name, ref := range c.Params {
			if !strings.HasSuffix(name, "Ref") || !strings.HasPrefix(ref, "secret:") {
				continue
			}
			for _, suffix := range operationSuffixes {
				seen[ref+suffix] = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for ref := range seen {
		out = append(out, ref)
	}
	sort.Strings(out)
	return out
}

// DropOperationSecrets deletes the sealed values a finished plan owns: once
// its changes were all put back, or the kept setup was removed, nothing can
// read them again. The first failed delete is returned; the rest still run.
func DropOperationSecrets(ctx context.Context, env core.Env, changes []core.Change) error {
	if env.Secrets == nil {
		return nil
	}
	var first error
	for _, ref := range OperationSecrets(changes) {
		if err := env.Secrets.Delete(ctx, ref); err != nil && first == nil {
			first = err
		}
	}
	return first
}
