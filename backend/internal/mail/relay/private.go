package relay

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"SynoMailPlusSetupAssistant/internal/core"
)

// AuthCredentials must be handed directly to MailPlus, never to UI facts/logs.
type AuthCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Redact accidental fmt/log use, while preserving fields for the wizard.
func (AuthCredentials) String() string     { return "[relay credentials redacted]" }
func (a AuthCredentials) GoString() string { return a.String() }

var credentialsMu sync.Mutex

// Credentials creates one atomic secret record when absent (Get returns "", nil).
// Store errors fail closed; they never trigger credential replacement.
func Credentials(ctx context.Context, env core.Env) (AuthCredentials, error) {
	credentialsMu.Lock()
	defer credentialsMu.Unlock()
	var auth AuthCredentials
	if env.Secrets == nil {
		return auth, errors.New("mail.relay.secrets_required")
	}
	value, err := env.Secrets.Get(ctx, CredentialsSecretKey)
	if err != nil {
		return auth, errors.New("mail.relay.credentials_read")
	}
	if value != "" {
		if json.Unmarshal([]byte(value), &auth) != nil || auth.Username == "" || auth.Password == "" {
			return AuthCredentials{}, errors.New("mail.relay.credentials_invalid")
		}
		return auth, nil
	}
	var b [32]byte
	if _, err = rand.Read(b[:]); err != nil {
		return auth, errors.New("mail.relay.random_failed")
	}
	auth = AuthCredentials{Username: "homekeeper-" + base64.RawURLEncoding.EncodeToString(b[:12]), Password: base64.RawURLEncoding.EncodeToString(b[12:])}
	data, _ := json.Marshal(auth)
	if env.Secrets.Put(ctx, CredentialsSecretKey, string(data)) != nil {
		return AuthCredentials{}, errors.New("mail.relay.credentials_write")
	}
	return auth, nil
}

func equal(a, b string) bool {
	x, y := sha256.Sum256([]byte(a)), sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(x[:], y[:]) == 1
}

// Keep the certificate and key in one atomic, private record. Refuse symlinks,
// permissive modes, corruption and an unsafe relay directory instead of
// following paths or silently replacing unknown state.
func prepareCertificate(dataDir string) (tls.Certificate, error) {
	fail := func() (tls.Certificate, error) {
		return tls.Certificate{}, errors.New("mail.relay.certificate_unavailable")
	}
	if dataDir == "" {
		return fail()
	}
	dir := filepath.Join(dataDir, "mail-relay")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fail()
	}
	fi, err := os.Lstat(dir)
	if err != nil || !fi.IsDir() || fi.Mode().Perm() != 0700 {
		return fail()
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return fail()
	}
	defer root.Close()
	const name = "starttls.pem"
	fi, err = root.Lstat(name)
	if err == nil {
		if !fi.Mode().IsRegular() || fi.Mode().Perm() != 0600 || fi.Size() > 16<<10 {
			return fail()
		}
		data, e := root.ReadFile(name)
		if e != nil {
			return fail()
		}
		cert, e := tls.X509KeyPair(data, data)
		if e != nil {
			return fail()
		}
		leaf, e := x509.ParseCertificate(cert.Certificate[0])
		if e != nil || leaf.VerifyHostname("127.0.0.1") != nil {
			return fail()
		}
		if time.Now().After(leaf.NotBefore) && time.Until(leaf.NotAfter) > 24*time.Hour {
			return cert, nil
		}
	} else if !os.IsNotExist(err) {
		return fail()
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fail()
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fail()
	}
	template := x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour),
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return fail()
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fail()
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	data = append(data, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})...)
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return fail()
	}
	temp := ".certificate-" + base64.RawURLEncoding.EncodeToString(nonce[:])
	f, err := root.OpenFile(temp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return fail()
	}
	defer root.Remove(temp)
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return fail()
	}
	if root.Rename(temp, name) != nil {
		return fail()
	}
	cert, err := tls.X509KeyPair(data, data)
	if err != nil {
		return fail()
	}
	return cert, nil
}
