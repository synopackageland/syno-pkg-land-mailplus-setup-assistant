package setup

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Every refusal for safety names its specific reason in plain
// words; none falls back to "integration unavailable".

var locales = []string{"en", "zh-TW", "zh-CN", "ja", "ko", "de", "fr", "es", "it"}

func catalog(t *testing.T, locale string) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "i18n", "messages", locale+".json"))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestEveryUnsafeReasonHasItsOwnPlainMessage(t *testing.T) {
	for _, loc := range locales {
		c := catalog(t, loc)
		generic := c["mail.setup.integrationUnavailable"]
		seen := map[string]string{}
		for _, code := range UnsafeCodes {
			key := UnsafeReason{code}.Error()
			text := c[key]
			if text == "" || text == generic || text == c["mail.setup.unsafePlan"] {
				t.Errorf("%s: %s has no specific message", loc, key)
			}
			if other, dup := seen[text]; dup {
				t.Errorf("%s: %s says the same as %s", loc, key, other)
			}
			seen[text] = key
			if regexp.MustCompile(`\b\d{3,4}\b|journal|ErrUnsafe|unsafe`).MatchString(text) {
				t.Errorf("%s: %s uses a code or jargon: %q", loc, key, text)
			}
		}
	}
}

func TestUnsafeReasonsSurviveThePublicPaths(t *testing.T) {
	for _, code := range UnsafeCodes {
		reason := UnsafeReason{code}
		wrapped := fmt.Errorf("provider said SECRET: %w", reason)
		if !errors.Is(wrapped, ErrUnsafe) {
			t.Fatalf("%s is not ErrUnsafe", code)
		}
		if got := publicError(wrapped); got == nil || got.Error() != reason.Error() || strings.Contains(got.Error(), "SECRET") {
			t.Fatalf("publicError(%s) = %v", code, got)
		}
		if got := publicCode(wrapped); got != reason.Error() {
			t.Fatalf("publicCode(%s) = %s", code, got)
		}
	}
}

// No source returns the bare ErrUnsafe any more: each site names its reason.
func TestNoBareUnsafeRefusalRemains(t *testing.T) {
	bare := regexp.MustCompile(`(return|=)[^=\n]*\bErrUnsafe\b[^.A-Za-z]`)
	root := filepath.Join("..", "..")
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for i, line := range strings.Split(string(raw), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") || strings.Contains(line, "errors.Is") || strings.Contains(line, "ErrUnsafe = errors.New") || strings.Contains(line, "target == ErrUnsafe") {
				continue
			}
			if bare.MatchString(line + " ") {
				t.Errorf("%s:%d returns the bare ErrUnsafe: %s", path, i+1, trimmed)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
