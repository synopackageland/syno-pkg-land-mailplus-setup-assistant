package core

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"errors"
	"io"
	"os"
	"path/filepath"
)

// Vault protects secrets and the entire wizard journal, including answers and
// snapshots. Its key is package-owned 0600 and is never regenerated over data.
type Vault struct{ aead cipher.AEAD }

func OpenVault(dir string) (*Vault, error) {
	path := filepath.Join(dir, "assistant.key")
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		if _, err := os.Lstat(filepath.Join(dir, "assistant.sqlite")); !errors.Is(err, os.ErrNotExist) {
			return nil, errors.New("encryption key missing for existing database")
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err == nil {
		key := make([]byte, 32)
		_, err = io.ReadFull(rand.Reader, key)
		if err == nil {
			_, err = f.Write(key)
		}
		if err == nil {
			err = f.Sync()
		}
		closeErr := f.Close()
		if err != nil {
			os.Remove(path)
			return nil, err
		}
		if closeErr != nil {
			return nil, closeErr
		}
	} else if !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return nil, errors.New("unsafe encryption key")
	}
	key, err := os.ReadFile(path)
	if err != nil || len(key) != 32 {
		return nil, errors.New("encryption key unavailable")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	return &Vault{aead: aead}, err
}

func (v *Vault) seal(data []byte, purpose string) ([]byte, error) {
	nonce := make([]byte, v.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return v.aead.Seal(nonce, nonce, data, []byte(purpose)), nil
}

func (v *Vault) open(data []byte, purpose string) ([]byte, error) {
	n := v.aead.NonceSize()
	if len(data) < n {
		return nil, errors.New("invalid encrypted record")
	}
	return v.aead.Open(nil, data[:n], data[n:], []byte(purpose))
}

type SecretStore struct{ Store *Store }

func (s SecretStore) Get(ctx context.Context, key string) (string, error) {
	var data []byte
	err := s.Store.db.QueryRowContext(ctx, "SELECT value FROM secrets WHERE key=?", key).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	value, err := s.Store.vault.open(data, "secret:"+key)
	return string(value), err
}

func (s SecretStore) Put(ctx context.Context, key, value string) error {
	if key == "" || len(key) > 256 || len(value) > 1<<20 {
		return ErrInvalid
	}
	data, err := s.Store.vault.seal([]byte(value), "secret:"+key)
	if err != nil {
		return err
	}
	_, err = s.Store.db.ExecContext(ctx, `INSERT INTO secrets VALUES(?,?)
ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, data)
	return err
}

func (s SecretStore) Delete(ctx context.Context, key string) error {
	_, err := s.Store.db.ExecContext(ctx, "DELETE FROM secrets WHERE key=?", key)
	return err
}

// Keys lists the key of every sealed value, sorted; never a value. Only the
// one-time sweep of leftover operation secrets reads the whole list.
func (s SecretStore) Keys(ctx context.Context) ([]string, error) {
	return s.Store.column(ctx, "SELECT key FROM secrets ORDER BY key")
}
