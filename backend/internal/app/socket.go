package app

import (
	"context"
	"errors"
	"os"
	"syscall"

	"github.com/synopackageland/syno-pkg-land-sdk/ipc"
)

// RemoveStaleCoreSocket removes only our owned socket after the SDK verifies
// its protected run directory and a connection proves ECONNREFUSED. The SDK
// refuses stale socket paths itself; package restarts need this narrow repair.
func RemoveStaleCoreSocket(ctx context.Context, path string) error {
	before, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if before.Mode()&os.ModeSocket == 0 || before.Mode().Perm() != 0600 {
		return errors.New("unsafe core socket")
	}
	conn, err := ipc.DialUnix(ctx, path)
	if err == nil {
		conn.Close()
		return errors.New("core is already running")
	}
	if !errors.Is(err, syscall.ECONNREFUSED) {
		return errors.New("core socket cannot be verified stale")
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, after) {
		return errors.New("core socket changed")
	}
	return os.Remove(path)
}
