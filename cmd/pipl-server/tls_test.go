package main

import (
	"os"
	"path/filepath"
	"testing"
)

// A cached self-signed cert must keep the same fingerprint across
// "restarts" (fresh selfSignedCert calls over the same dir), or pinned
// clients would reject the server after every restart.
func TestSelfSignedCertIsStableWithDir(t *testing.T) {
	dir := t.TempDir()

	c1, fp1, reused1, err := selfSignedCert(dir, "127.0.0.1:8737")
	if err != nil {
		t.Fatal(err)
	}
	if reused1 {
		t.Fatal("first call reused a cert that should not exist yet")
	}
	if len(c1.Certificate) == 0 {
		t.Fatal("no certificate produced")
	}

	_, fp2, reused2, err := selfSignedCert(dir, "127.0.0.1:8737")
	if err != nil {
		t.Fatal(err)
	}
	if !reused2 {
		t.Fatal("second call did not reuse the cached cert")
	}
	if fp1 != fp2 {
		t.Fatalf("fingerprint changed across restart: %s -> %s", fp1, fp2)
	}
	// The cache files must actually be on disk.
	for _, name := range []string{"cert.pem", "key.pem"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("expected %s in the cache dir: %v", name, err)
		}
	}
}

// Without a dir the cert is ephemeral, so its fingerprint changes each
// time — that is exactly why -tls-dir exists, and the note must warn.
func TestSelfSignedCertIsEphemeralWithoutDir(t *testing.T) {
	_, fp1, reused1, err := selfSignedCert("", "127.0.0.1:8737")
	if err != nil {
		t.Fatal(err)
	}
	_, fp2, _, err := selfSignedCert("", "127.0.0.1:8737")
	if err != nil {
		t.Fatal(err)
	}
	if reused1 {
		t.Fatal("an in-memory cert cannot have been reused")
	}
	if fp1 == fp2 {
		t.Fatal("two in-memory certs shared a fingerprint (should be independent)")
	}
}

// A corrupt or expired cache must regenerate rather than fail startup.
func TestCorruptCacheRegenerates(t *testing.T) {
	dir := t.TempDir()
	if _, _, _, err := selfSignedCert(dir, "127.0.0.1:8737"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cert.pem"), []byte("not a cert"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, reused, err := selfSignedCert(dir, "127.0.0.1:8737")
	if err != nil {
		t.Fatalf("corrupt cache should regenerate, not error: %v", err)
	}
	if reused {
		t.Fatal("a corrupt cache was treated as reusable")
	}
}

// tlsConfig's mode selection: cert+key together, self-signed, or plain.
func TestTLSConfigModes(t *testing.T) {
	t.Run("plain http when nothing set", func(t *testing.T) {
		cfg, note, err := tlsConfig("", "", false, "", "127.0.0.1:8737")
		if err != nil {
			t.Fatal(err)
		}
		if cfg != nil {
			t.Fatal("expected nil TLS config for plain HTTP")
		}
		if note == "" {
			t.Fatal("expected a note explaining plain HTTP")
		}
	})
	t.Run("cert without key is an error", func(t *testing.T) {
		if _, _, err := tlsConfig("cert.pem", "", false, "", "127.0.0.1:8737"); err == nil {
			t.Fatal("expected an error when only one of cert/key is given")
		}
	})
	t.Run("self-signed yields a config", func(t *testing.T) {
		cfg, _, err := tlsConfig("", "", true, t.TempDir(), "127.0.0.1:8737")
		if err != nil {
			t.Fatal(err)
		}
		if cfg == nil || len(cfg.Certificates) == 0 {
			t.Fatal("self-signed produced no usable TLS config")
		}
	})
}
