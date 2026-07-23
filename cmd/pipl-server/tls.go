package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// TLS for the coordination server.
//
// What TLS protects here is METADATA and integrity in transit — who is
// talking to whom, blob sizes and timing, and a network attacker tampering
// with directory answers or notifications. It is NOT protecting message
// content: that is already end-to-end encrypted before it reaches the
// server, which is keyless by design. So a self-signed certificate pinned
// on first use (like the peer identities themselves) fits the model; a
// public CA is optional, for when the server has a real hostname.
//
// Three modes, chosen by flags:
//   -tls-cert FILE -tls-key FILE   use an existing certificate (e.g. a
//                                   Let's Encrypt cert for a real host)
//   -tls-self-signed               generate an in-memory cert for the
//                                   addresses in -addr, print its
//                                   fingerprint for clients to pin
//   (neither)                      plain HTTP (fine only on loopback/dev)

// tlsConfig builds the server's TLS configuration from the flags, or
// returns nil for plain HTTP. It also returns a human note to log.
//
// selfSignedDir, when set, is where a self-signed cert is cached: it is
// reused across restarts so its pinned fingerprint stays stable, and
// regenerated only when missing or expired. Empty means an ephemeral
// in-memory cert (fine for a throwaway run, but its fingerprint changes
// each start, so pinned clients would reject it after a restart).
func tlsConfig(certFile, keyFile string, selfSigned bool, selfSignedDir, addr string) (*tls.Config, string, error) {
	switch {
	case certFile != "" || keyFile != "":
		if certFile == "" || keyFile == "" {
			return nil, "", fmt.Errorf("-tls-cert and -tls-key must be given together")
		}
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, "", fmt.Errorf("loading TLS cert: %w", err)
		}
		fp := certFingerprint(cert.Certificate[0])
		return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
			"TLS: certificate " + certFile + " (pin " + fp + ")", nil

	case selfSigned:
		cert, fp, reused, err := selfSignedCert(selfSignedDir, addr)
		if err != nil {
			return nil, "", err
		}
		origin := "generated"
		if reused {
			origin = "reused from " + selfSignedDir
		} else if selfSignedDir != "" {
			origin = "generated, cached in " + selfSignedDir
		} else {
			origin = "generated, in-memory (fingerprint changes on restart — use -tls-dir to keep it stable)"
		}
		return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
			"TLS: self-signed, " + origin + "\n  clients must pin: " + fp, nil

	default:
		return nil, "plain HTTP — no transport encryption (use -tls-self-signed or -tls-cert for TLS)", nil
	}
}

// selfSignedCert returns a self-signed cert for addr. With dir set it
// reuses cert.pem/key.pem there when they exist and are still valid,
// otherwise generates a fresh pair and writes them. With dir empty it is
// purely in-memory. reused reports whether an on-disk pair was loaded.
func selfSignedCert(dir, addr string) (cert tls.Certificate, fp string, reused bool, err error) {
	if dir != "" {
		certPath := filepath.Join(dir, "cert.pem")
		keyPath := filepath.Join(dir, "key.pem")
		if c, ok, verr := loadCachedCert(certPath, keyPath); verr != nil {
			return tls.Certificate{}, "", false, verr
		} else if ok {
			return c, certFingerprint(c.Certificate[0]), true, nil
		}
	}
	c, certPEM, keyPEM, fp, err := generateSelfSigned(addr)
	if err != nil {
		return tls.Certificate{}, "", false, err
	}
	if dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return tls.Certificate{}, "", false, err
		}
		if err := os.WriteFile(filepath.Join(dir, "cert.pem"), certPEM, 0o644); err != nil {
			return tls.Certificate{}, "", false, err
		}
		if err := os.WriteFile(filepath.Join(dir, "key.pem"), keyPEM, 0o600); err != nil {
			return tls.Certificate{}, "", false, err
		}
	}
	return c, fp, false, nil
}

// loadCachedCert loads a cached cert/key pair, returning ok=false (not an
// error) when the files are simply absent, so the caller regenerates. An
// expired or unparseable cert is treated as absent for the same reason.
func loadCachedCert(certPath, keyPath string) (tls.Certificate, bool, error) {
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		return tls.Certificate{}, false, nil
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return tls.Certificate{}, false, nil // corrupt/partial: regenerate
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return tls.Certificate{}, false, nil
	}
	if time.Now().After(leaf.NotAfter) {
		return tls.Certificate{}, false, nil // expired: regenerate
	}
	return cert, true, nil
}

// generateSelfSigned mints an ECDSA P-256 certificate valid for the host
// portion of addr (and the loopback names), returning the usable cert, its
// PEM encodings (so it can be cached to disk), and the SHA-256 fingerprint
// clients pin.
func generateSelfSigned(addr string) (cert tls.Certificate, certPEM, keyPEM []byte, fp string, err error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, nil, "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, nil, nil, "", err
	}
	now := time.Now()
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{Organization: []string{"PIPL self-signed"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	addSAN(&tmpl, addr)

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, nil, nil, "", err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, nil, nil, "", err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	cert, err = tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, nil, nil, "", err
	}
	return cert, certPEM, keyPEM, certFingerprint(der), nil
}

// addSAN fills the certificate's Subject Alternative Names from the host
// in addr, so the cert is valid for however clients name the server.
// Loopback always gets 127.0.0.1 and localhost.
func addSAN(tmpl *x509.Certificate, addr string) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	seen := map[string]bool{}
	add := func(h string) {
		if h == "" || seen[h] {
			return
		}
		seen[h] = true
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	// A bare or wildcard host means "listen on all interfaces"; still make
	// the cert usable for the common local names.
	if host == "" || host == "0.0.0.0" || host == "::" {
		add("127.0.0.1")
		add("localhost")
	} else {
		add(host)
		if host == "127.0.0.1" || host == "localhost" {
			add("127.0.0.1")
			add("localhost")
		}
	}
}

// certFingerprint is the SHA-256 of the DER certificate, hex-encoded — the
// value a client pins and a human compares out of band. Same shape as the
// identity fingerprints used elsewhere.
func certFingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// writeFingerprintFile drops the pin somewhere clients can read it, so a
// local peer can be pointed at it without copy-pasting from logs.
func writeFingerprintFile(path, fp string) error {
	return os.WriteFile(path, []byte(fp+"\n"), 0o644)
}
