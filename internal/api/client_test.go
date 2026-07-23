package api

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/antonio/pipl/internal/identity"
)

// pinOf returns the hex SHA-256 of a test server's leaf certificate.
func pinOf(t *testing.T, s *httptest.Server) string {
	t.Helper()
	cert := s.Certificate()
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
}

func testIdentity(t *testing.T) identity.PublicIdentity {
	t.Helper()
	id, err := identity.New("alice")
	if err != nil {
		t.Fatal(err)
	}
	return id.Public()
}

// The whole point: a correct pin lets the client talk to a self-signed
// server with no CA involved.
func TestPinnedClientTrustsMatchingCert(t *testing.T) {
	srv := httptest.NewTLSServer(okHandler())
	defer srv.Close()

	c := New(srv.URL, pinOf(t, srv))
	if err := c.Register(testIdentity(t)); err != nil {
		t.Fatalf("pinned client rejected the very cert it pinned: %v", err)
	}
}

// A wrong pin must fail closed — this is what stops a swapped or
// man-in-the-middle certificate.
func TestPinnedClientRejectsWrongCert(t *testing.T) {
	srv := httptest.NewTLSServer(okHandler())
	defer srv.Close()

	wrong := strings.Repeat("00", 32)
	c := New(srv.URL, wrong)
	err := c.Register(testIdentity(t))
	if err == nil {
		t.Fatal("pinned client accepted a certificate that did not match the pin")
	}
	if !strings.Contains(err.Error(), "fingerprint mismatch") {
		t.Fatalf("error did not explain the mismatch: %v", err)
	}
}

// Without a pin, an https server with an untrusted (self-signed) cert must
// be rejected by the default chain check — no silent InsecureSkipVerify.
func TestUnpinnedClientRejectsUntrustedCert(t *testing.T) {
	srv := httptest.NewTLSServer(okHandler())
	defer srv.Close()

	c := New(srv.URL, "") // no pin
	if err := c.Register(testIdentity(t)); err == nil {
		t.Fatal("unpinned client accepted a self-signed cert (should require the system roots)")
	}
}

// Pin formatting must be forgiving: colons and case should not matter,
// since a human may copy it from a log with either.
func TestPinAcceptsColonsAndCase(t *testing.T) {
	srv := httptest.NewTLSServer(okHandler())
	defer srv.Close()
	raw := pinOf(t, srv)

	// Upper-case with colons every two chars.
	var withColons strings.Builder
	up := strings.ToUpper(raw)
	for i := 0; i < len(up); i += 2 {
		if i > 0 {
			withColons.WriteByte(':')
		}
		withColons.WriteString(up[i : i+2])
	}

	c := New(srv.URL, withColons.String())
	if err := c.Register(testIdentity(t)); err != nil {
		t.Fatalf("pin with colons/upper-case was not accepted: %v", err)
	}
}

// The SSE stream shares the pinned transport, so a pinned client must be
// able to open the event stream against the same cert. (We only check the
// TLS handshake succeeds, not the streaming itself.)
func TestPinnedTransportSharedWithStream(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/events" {
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := New(srv.URL, pinOf(t, srv))
	if c.tr == nil || c.tr.TLSClientConfig == nil {
		t.Fatal("pinned client has no TLS config on its shared transport")
	}
	// A quick sanity connection over the pooled client proves the pin works;
	// the stream uses the same c.tr, so it inherits the trust decision.
	if _, err := c.http.Get(srv.URL + "/v1/identities/x"); err != nil {
		t.Fatalf("pinned transport could not connect: %v", err)
	}
	_ = tls.VersionTLS12 // keep tls import meaningful if the above changes
}
