package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

var (
	ErrNotFound    = errors.New("not_found")
	ErrConflict    = errors.New("conflict")
	ErrInvalid     = errors.New("bad_request")
	ErrUnavailable = errors.New("unavailable")
)

// Store has one SQLite connection; the worker owns it. It keeps small JSON
// values (KV) and sealed secrets only. Diagnostic findings are not stored:
// they are computed on demand and returned to the caller (hibernation-safe:
// nothing is written while nobody uses the App).
type Store struct {
	DataDir string
	db      *sql.DB
	vault   *Vault
	// services is signalled after any write to core.services, whoever makes
	// it, so the event-driven service host sees every enable and disable.
	services chan struct{}
}

func OpenStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	vault, err := OpenVault(dir)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "assistant.sqlite")
	// Refuse symlinks and make the file private before SQLite opens it.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if errors.Is(err, os.ErrExist) {
		info, e := os.Lstat(path)
		if e != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			return nil, errors.New("unsafe database file")
		}
	} else if err != nil {
		return nil, err
	} else {
		f.Close()
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	s := &Store{DataDir: dir, db: db, vault: vault, services: make(chan struct{}, 1)}
	_, err = db.Exec(`
PRAGMA busy_timeout=5000;
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
CREATE TABLE IF NOT EXISTS kv (module TEXT, key TEXT, value BLOB NOT NULL, PRIMARY KEY(module,key));
CREATE TABLE IF NOT EXISTS secrets (key TEXT PRIMARY KEY, value BLOB NOT NULL);
`)
	if err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) Get(ctx context.Context, module, key string, out any) (bool, error) {
	var data []byte
	err := s.db.QueryRowContext(ctx, "SELECT value FROM kv WHERE module=? AND key=?", module, key).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, json.Unmarshal(data, out)
}

// Put writes only when the value changed, so repeated reads that store the
// same state never touch the disk.
func (s *Store) Put(ctx context.Context, module, key string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(data) > 1<<20 {
		return ErrInvalid
	}
	var old []byte
	if err := s.db.QueryRowContext(ctx, "SELECT value FROM kv WHERE module=? AND key=?", module, key).Scan(&old); err == nil && string(old) == string(data) {
		return nil
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO kv VALUES(?,?,?)
ON CONFLICT(module,key) DO UPDATE SET value=excluded.value`, module, key, data)
	if err == nil && module == "core.services" {
		select {
		case s.services <- struct{}{}:
		default:
		}
	}
	return err
}

// Delete removes one KV value; a missing value is not an error.
func (s *Store) Delete(ctx context.Context, module, key string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM kv WHERE module=? AND key=?", module, key)
	return err
}

// ServiceSignal is signalled after every write to core.services.
func (s *Store) ServiceSignal() <-chan struct{} { return s.services }

// Keys lists the KV keys of module that start with prefix (sorted, at most
// 100). Callers reach it through the KeyLister interface.
func (s *Store) Keys(ctx context.Context, module, prefix string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT key FROM kv WHERE module=? AND substr(key,1,length(?))=? ORDER BY key LIMIT 100", module, prefix, prefix)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// KeyLister is a KV that can list its keys (the Store).
type KeyLister interface {
	Keys(ctx context.Context, module, prefix string) ([]string, error)
}

// AllKeys lists every KV key of module that starts with prefix, sorted and
// without Keys' page limit: for a sweep that must see every record before
// it may conclude that nothing refers to a value.
func (s *Store) AllKeys(ctx context.Context, module, prefix string) ([]string, error) {
	return s.column(ctx, "SELECT key FROM kv WHERE module=? AND substr(key,1,length(?))=? ORDER BY key", module, prefix, prefix)
}

func (s *Store) column(ctx context.Context, query string, args ...any) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}
